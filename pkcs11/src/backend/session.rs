use std::{collections::HashMap, sync::Arc};

use cryptoki_sys::{
    CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_OK, CKR_USER_NOT_LOGGED_IN, CKS_RO_PUBLIC_SESSION,
    CKS_RW_SO_FUNCTIONS, CKS_RW_USER_FUNCTIONS, CK_FLAGS, CK_OBJECT_HANDLE, CK_RV,
    CK_SESSION_HANDLE, CK_SLOT_ID, CK_USER_TYPE,
};
use log::{debug, error};
use openapi::apis::default_api::{self};

use crate::{backend::key::CreateKeyError, config::device::Slot};

use super::{
    db::{self, attr::CkRawAttrTemplate, object::ObjectKind, Db, Object, ObjectHandle},
    decrypt::DecryptCtx,
    encrypt::EncryptCtx,
    key::{create_key_from_template, generate_key_from_template},
    login::{LoginCtx, UserStatus},
    mechanism::Mechanism,
    object::{EnumCtx, KeyRequirements},
    sign::SignCtx,
};

#[derive(Clone, Debug)]
pub struct SessionManager {
    pub sessions: HashMap<CK_SESSION_HANDLE, Session>,
    pub next_session_handle: CK_SESSION_HANDLE,
}

impl SessionManager {
    pub fn new() -> Self {
        Self {
            sessions: HashMap::new(),
            next_session_handle: 1,
        }
    }

    pub fn create_session(
        &mut self,
        slot_id: CK_SLOT_ID,
        slot: Arc<Slot>,
        flags: CK_FLAGS,
    ) -> CK_SESSION_HANDLE {
        let session = Session::new(slot_id, slot, flags);
        let handle = self.next_session_handle;
        self.sessions.insert(handle, session);

        self.next_session_handle += 1;
        handle
    }

    pub fn get_session(&self, handle: CK_SESSION_HANDLE) -> Option<&Session> {
        self.sessions.get(&handle)
    }

    pub fn get_session_mut(&mut self, handle: CK_SESSION_HANDLE) -> Option<&mut Session> {
        self.sessions.get_mut(&handle)
    }

    pub fn delete_session(
        &mut self,
        handle: CK_SESSION_HANDLE,
    ) -> Option<(CK_SESSION_HANDLE, Session)> {
        self.sessions.remove_entry(&handle)
    }

    pub fn delete_all_slot_sessions(&mut self, slot_id: CK_SLOT_ID) {
        let mut deleted_sessions = Vec::new();
        self.sessions.iter().for_each(|(handle, session)| {
            if session.slot_id == slot_id {
                deleted_sessions.push(*handle);
            }
        });
        for handle in deleted_sessions.iter() {
            self.sessions.remove(handle);
        }
    }
}

#[derive(Clone, Debug)]
pub struct Session {
    pub slot_id: CK_SLOT_ID,
    pub login_ctx: LoginCtx,
    pub flags: CK_FLAGS,
    pub device_error: CK_RV,
    pub fetched_all_keys: bool,
    pub db: Db,
    pub sign_ctx: Option<SignCtx>,
    pub encrypt_ctx: Option<EncryptCtx>,
    pub decrypt_ctx: Option<DecryptCtx>,
    pub enum_ctx: Option<EnumCtx>,
}

impl Session {
    pub fn new(slot_id: CK_SLOT_ID, slot: Arc<Slot>, flags: CK_FLAGS) -> Self {
        // cloning the api config should keep the connection pool as it's behind an Arc

        let api_config = slot.api_config.clone();

        Self {
            login_ctx: LoginCtx::new(slot.operator.clone(), slot.administator.clone(), api_config),
            slot_id,
            flags,
            fetched_all_keys: false,
            db: Db::new(),
            device_error: CKR_OK,
            sign_ctx: None,
            encrypt_ctx: None,
            decrypt_ctx: None,
            enum_ctx: None,
        }
    }
    pub fn get_ck_info(&self) -> cryptoki_sys::CK_SESSION_INFO {
        let state = match self.login_ctx.user_status() {
            UserStatus::LoggedOut => CKS_RO_PUBLIC_SESSION,
            UserStatus::Operator => CKS_RW_USER_FUNCTIONS,
            UserStatus::Administrator => CKS_RW_SO_FUNCTIONS,
        };

        cryptoki_sys::CK_SESSION_INFO {
            slotID: self.slot_id,
            state,
            flags: self.flags,
            ulDeviceError: self.device_error,
        }
    }

    pub fn login(&mut self, user_type: CK_USER_TYPE, pin: String) -> CK_RV {
        match self.login_ctx.login(user_type, pin) {
            Ok(_) => CKR_OK,
            Err(err) => {
                error!("Failed to login: {:?}", err);
                err.into()
            }
        }
    }

    // ignore logout for now
    pub fn logout(&mut self) -> CK_RV {
        CKR_OK
    }

    pub fn enum_init(&mut self, template: Option<CkRawAttrTemplate>) -> CK_RV {
        if self.enum_ctx.is_some() {
            return cryptoki_sys::CKR_OPERATION_ACTIVE;
        }

        self.enum_ctx = Some(match EnumCtx::enum_init(self, template) {
            Ok(ctx) => ctx,
            Err(err) => {
                error!("Failed to initialize enum context: {:?}", err);
                return err;
            }
        });

        cryptoki_sys::CKR_OK
    }

    pub fn enum_next_chunk(&mut self, count: usize) -> Result<Vec<CK_SESSION_HANDLE>, CK_RV> {
        match self.enum_ctx {
            Some(ref mut enum_ctx) => Ok(enum_ctx.next_chunck(count)),
            None => Err(cryptoki_sys::CKR_OPERATION_NOT_INITIALIZED),
        }
    }
    pub fn enum_final(&mut self) {
        self.enum_ctx = None;
    }

    pub fn sign_init(&mut self, mechanism: &Mechanism, key_handle: CK_OBJECT_HANDLE) -> CK_RV {
        if self.sign_ctx.is_some() {
            return cryptoki_sys::CKR_OPERATION_ACTIVE;
        }

        // get key id from the handle

        let key = match self
            .db
            .object(ObjectHandle::from(key_handle))
            .ok_or(cryptoki_sys::CKR_KEY_HANDLE_INVALID)
        {
            Ok(object) => object,
            Err(err) => {
                error!("Failed to get key: {:?}", err);
                return err;
            }
        };
        let api_config = match self.login_ctx.operator() {
            Some(conf) => conf,
            None => return CKR_USER_NOT_LOGGED_IN,
        };

        self.sign_ctx = match SignCtx::init(mechanism.clone(), key.clone(), api_config) {
            Ok(ctx) => Some(ctx),
            Err(err) => return err,
        };

        cryptoki_sys::CKR_OK
    }

    pub fn sign_theoretical_size(&self) -> usize {
        let sign_ctx = self
            .sign_ctx
            .as_ref()
            .expect("sign context should be initialized");

        sign_ctx.get_theoretical_size()
    }

    pub fn sign_update(&mut self, data: &[u8]) -> Result<(), CK_RV> {
        let sign_ctx = self
            .sign_ctx
            .as_mut()
            .ok_or(cryptoki_sys::CKR_OPERATION_NOT_INITIALIZED)?;

        sign_ctx.update(data);
        Ok(())
    }

    pub fn sign_final(&mut self) -> Result<Vec<u8>, CK_RV> {
        let sign_ctx = self
            .sign_ctx
            .as_ref()
            .ok_or(cryptoki_sys::CKR_OPERATION_NOT_INITIALIZED)?;

        sign_ctx.sign_final()
    }

    pub fn sign(&mut self, data: &[u8]) -> Result<Vec<u8>, CK_RV> {
        self.sign_update(data)?;
        self.sign_final()
    }

    pub fn sign_clear(&mut self) {
        self.sign_ctx = None;
    }

    pub fn encrypt_init(&mut self, mechanism: &Mechanism, key_handle: CK_OBJECT_HANDLE) -> CK_RV {
        if self.encrypt_ctx.is_some() {
            return cryptoki_sys::CKR_OPERATION_ACTIVE;
        }

        // get key id from the handle

        let key = match self
            .db
            .object(ObjectHandle::from(key_handle))
            .ok_or(cryptoki_sys::CKR_KEY_HANDLE_INVALID)
        {
            Ok(object) => object,
            Err(err) => {
                error!("Failed to get key: {:?}", err);
                return err;
            }
        };

        let api_config = match self.login_ctx.operator() {
            Some(conf) => conf,
            None => return CKR_USER_NOT_LOGGED_IN,
        };

        self.encrypt_ctx = match EncryptCtx::init(mechanism.clone(), key, api_config) {
            Ok(ctx) => Some(ctx),
            Err(err) => return err,
        };

        cryptoki_sys::CKR_OK
    }

    pub fn encrypt_add_data(&mut self, data: &[u8]) -> Result<(), CK_RV> {
        let encrypt_ctx = self
            .encrypt_ctx
            .as_mut()
            .ok_or(cryptoki_sys::CKR_OPERATION_NOT_INITIALIZED)?;

        encrypt_ctx.add_data(data);
        Ok(())
    }

    pub fn encrypt_available_data(&mut self) -> Result<Vec<u8>, CK_RV> {
        let encrypt_ctx = self
            .encrypt_ctx
            .as_mut()
            .ok_or(cryptoki_sys::CKR_OPERATION_NOT_INITIALIZED)?;

        encrypt_ctx.encrypt_available_data()
    }

    pub fn encrypt_update(&mut self, data: &[u8]) -> Result<Vec<u8>, CK_RV> {
        self.encrypt_add_data(data)?;
        self.encrypt_available_data()
    }

    pub fn encrypt_final(&mut self) -> Result<Vec<u8>, CK_RV> {
        let encrypt_ctx = self
            .encrypt_ctx
            .as_ref()
            .ok_or(cryptoki_sys::CKR_OPERATION_NOT_INITIALIZED)?;

        encrypt_ctx.encrypt_final()
    }

    pub fn encrypt(&mut self, data: &[u8]) -> Result<Vec<u8>, CK_RV> {
        self.encrypt_add_data(data)?;
        self.encrypt_final()
    }

    pub fn encrypt_clear(&mut self) {
        self.encrypt_ctx = None;
    }

    pub fn decrypt_init(&mut self, mechanism: &Mechanism, key_handle: CK_OBJECT_HANDLE) -> CK_RV {
        if self.decrypt_ctx.is_some() {
            return cryptoki_sys::CKR_OPERATION_ACTIVE;
        }

        // get key id from the handle

        let key = match self
            .db
            .object(ObjectHandle::from(key_handle))
            .ok_or(cryptoki_sys::CKR_KEY_HANDLE_INVALID)
        {
            Ok(object) => object,
            Err(err) => {
                error!("Failed to get key: {:?}", err);
                return err;
            }
        };

        let api_config = match self.login_ctx.operator() {
            Some(conf) => conf,
            None => return CKR_USER_NOT_LOGGED_IN,
        };

        self.decrypt_ctx = match DecryptCtx::init(mechanism.clone(), key, api_config) {
            Ok(ctx) => Some(ctx),
            Err(err) => return err,
        };

        cryptoki_sys::CKR_OK
    }

    // only adds data to the decrypt context, does not decrypt anything
    pub fn decrypt_update(&mut self, data: &[u8]) -> Result<(), CK_RV> {
        let decrypt_ctx = self
            .decrypt_ctx
            .as_mut()
            .ok_or(cryptoki_sys::CKR_OPERATION_NOT_INITIALIZED)?;

        decrypt_ctx.update(data);
        Ok(())
    }

    // For now we go safe and lazy and just return the same size as the input
    pub fn decrypt_theoretical_size(&self, input_size: usize) -> usize {
        input_size
    }

    pub fn decrypt_theoretical_final_size(&self) -> Result<usize, CK_RV> {
        let decrypt_ctx = self
            .decrypt_ctx
            .as_ref()
            .ok_or(cryptoki_sys::CKR_OPERATION_NOT_INITIALIZED)?;

        Ok(decrypt_ctx.data.len())
    }

    pub fn decrypt_final(&mut self) -> Result<Vec<u8>, CK_RV> {
        let decrypt_ctx = self
            .decrypt_ctx
            .as_ref()
            .ok_or(cryptoki_sys::CKR_OPERATION_NOT_INITIALIZED)?;

        decrypt_ctx.decrypt_final()
    }

    pub fn decrypt(&mut self, data: &[u8]) -> Result<Vec<u8>, CK_RV> {
        self.decrypt_update(data)?;
        self.decrypt_final()
    }

    pub fn decrypt_clear(&mut self) {
        self.decrypt_ctx = None;
    }

    pub fn get_object(&self, handle: CK_OBJECT_HANDLE) -> Option<&Object> {
        self.db.object(ObjectHandle::from(handle))
    }

    pub(super) fn find_key(
        &mut self,
        requirements: KeyRequirements,
    ) -> Result<Vec<CK_OBJECT_HANDLE>, CK_RV> {
        let mut result = match requirements.id {
            Some(key_id) => {
                let mut results: Vec<(CK_OBJECT_HANDLE, Object)> = self
                    .fetch_key(&key_id)?
                    .iter()
                    .map(|(handle, obj)| (*handle, obj.clone()))
                    .collect();

                match self.fetch_certificate(&key_id) {
                    Ok((handle, obj)) => results.push((handle, obj)),
                    Err(err) => {
                        debug!("Failed to fetch certificate: {:?}", err);
                    }
                }

                Ok(results)
            }

            None => self.fetch_all_keys(),
        }?;

        if let Some(kind) = requirements.kind {
            result.retain(|(_, obj)| obj.kind == kind);
        }

        Ok(result.iter().map(|(handle, _)| *handle).collect())
    }

    fn fetch_all_keys(&mut self) -> Result<Vec<(CK_OBJECT_HANDLE, Object)>, CK_RV> {
        if self.fetched_all_keys {
            return Ok(self
                .db
                .enumerate()
                .map(|(handle, obj)| (handle.into(), obj.clone()))
                .collect());
        }

        // clear the db to not have any double entries
        self.db.clear();

        let api_config = match self.login_ctx.operator_or_administrator() {
            Some(conf) => conf,
            None => return Err(CKR_USER_NOT_LOGGED_IN),
        };

        let keys = default_api::keys_get(&api_config, None).map_err(|err| {
            error!("Failed to fetch keys: {:?}", err);
            CKR_DEVICE_ERROR
        })?;

        let mut handles = Vec::new();

        for key in keys {
            let mut objects = self.fetch_key(&key.key)?;

            // try to fetch the certificate
            match self.fetch_certificate(&key.key) {
                Ok((handle, object)) => objects.push((handle, object)),
                Err(err) => {
                    debug!("Failed to fetch certificate: {:?}", err);
                }
            }

            for (handle, object) in objects {
                handles.push((handle, object));
            }
        }
        Ok(handles)
    }

    fn fetch_certificate(&mut self, key_id: &str) -> Result<(CK_OBJECT_HANDLE, Object), CK_RV> {
        let api_config = self
            .login_ctx
            .operator_or_administrator()
            .ok_or(CKR_USER_NOT_LOGGED_IN)?;

        let cert_data = default_api::keys_key_id_cert_get(&api_config, key_id).map_err(|err| {
            debug!("Failed to fetch certificate {}: {:?}", key_id, err);
            CKR_DEVICE_ERROR
        })?;

        let object = db::object::from_cert_data(cert_data, key_id).map_err(|err| {
            debug!("Failed to convert certificate {}: {:?}", key_id, err);
            CKR_DEVICE_ERROR
        })?;

        let r = self.db.add_object(object);

        Ok((r.0, r.1.clone()))
    }

    fn fetch_key(&mut self, key_id: &str) -> Result<Vec<(CK_OBJECT_HANDLE, Object)>, CK_RV> {
        let api_config = self
            .login_ctx
            .operator_or_administrator()
            .ok_or(CKR_USER_NOT_LOGGED_IN)?;

        let key_data = default_api::keys_key_id_get(&api_config, key_id).map_err(|err| {
            error!("Failed to fetch key {}: {:?}", key_id, err);
            CKR_DEVICE_ERROR
        })?;

        let objects = db::object::from_key_data(key_data, key_id).map_err(|err| {
            error!("Failed to convert key {}: {:?}", key_id, err);
            CKR_DEVICE_ERROR
        })?;

        let mut result = Vec::new();

        for object in objects {
            let r = self.db.add_object(object.clone());
            result.push((r.0, r.1.clone()));
        }

        Ok(result)
    }

    pub fn create_object(
        &mut self,
        template: CkRawAttrTemplate,
    ) -> Result<Vec<(CK_OBJECT_HANDLE, Object)>, CK_RV> {
        let api_config = self
            .login_ctx
            .administrator()
            .ok_or(CKR_USER_NOT_LOGGED_IN)?;

        let key_info = create_key_from_template(template, &api_config).map_err(|err| {
            error!("Failed to create key: {:?}", err);
            if err == CreateKeyError::ClassNotSupported {
                return CKR_DEVICE_MEMORY;
            }
            CKR_DEVICE_ERROR
        })?;

        match key_info.1 {
            ObjectKind::Certificate => self
                .fetch_certificate(&key_info.0)
                .map(|(handle, obj)| vec![(handle, obj)]),
            _ => self.fetch_key(&key_info.0),
        }
    }

    pub fn delete_object(&mut self, handle: CK_OBJECT_HANDLE) -> Result<(), CK_RV> {
        let api_config = self
            .login_ctx
            .administrator()
            .ok_or(CKR_USER_NOT_LOGGED_IN)?;

        let key = self.db.object(ObjectHandle::from(handle)).ok_or_else(|| {
            error!("Failed to delete object: invalid handle");
            CKR_DEVICE_ERROR
        })?;

        default_api::keys_key_id_delete(&api_config, &key.id).map_err(|err| {
            error!("Failed to delete key {}: {:?}", key.id, err);
            CKR_DEVICE_ERROR
        })?;

        self.db.remove(ObjectHandle::from(handle)).ok_or_else(|| {
            error!("Failed to delete object: invalid handle");
            CKR_DEVICE_ERROR
        })?;

        Ok(())
    }

    pub fn generate_key(
        &mut self,
        template: &CkRawAttrTemplate,
        public_template: Option<&CkRawAttrTemplate>,
        mechanism: &Mechanism,
    ) -> Result<Vec<(CK_OBJECT_HANDLE, Object)>, CK_RV> {
        let api_config = self
            .login_ctx
            .administrator()
            .ok_or(CKR_USER_NOT_LOGGED_IN)?;

        let id = generate_key_from_template(template, public_template, mechanism, &api_config)
            .map_err(|err| {
                error!("Failed to create key: {:?}", err);
                if err == CreateKeyError::ClassNotSupported {
                    return CKR_DEVICE_MEMORY;
                }

                CKR_DEVICE_ERROR
            })?;

        self.fetch_key(&id)
    }
}
