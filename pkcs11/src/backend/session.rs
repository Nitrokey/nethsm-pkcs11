use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use cryptoki_sys::{
    CKR_OK, CK_FLAGS, CK_OBJECT_HANDLE, CK_RV, CK_SESSION_HANDLE, CK_SESSION_INFO, CK_SLOT_ID,
    CK_USER_TYPE,
};
use log::{debug, error, trace};
use openapi::apis::default_api::{self};

use crate::{
    backend::{self, login::UserMode, ApiError, Error},
    config::device::Slot,
};

use super::{
    db::{self, attr::CkRawAttrTemplate, object::ObjectKind, Db, Object},
    decrypt::DecryptCtx,
    encrypt::EncryptCtx,
    key::{create_key_from_template, generate_key_from_template},
    login::LoginCtx,
    mechanism::Mechanism,
    object::{EnumCtx, KeyRequirements},
    sign::SignCtx,
};

#[derive(Debug)]
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

#[derive(Debug)]
pub struct Session {
    pub slot_id: CK_SLOT_ID,
    pub login_ctx: LoginCtx,
    pub flags: CK_FLAGS,
    pub device_error: CK_RV,
    pub db: Arc<Mutex<Db>>,
    pub sign_ctx: Option<SignCtx>,
    pub encrypt_ctx: Option<EncryptCtx>,
    pub decrypt_ctx: Option<DecryptCtx>,
    pub enum_ctx: Option<EnumCtx>,
}

impl Session {
    pub fn new(slot_id: CK_SLOT_ID, slot: Arc<Slot>, flags: CK_FLAGS) -> Self {
        let login_ctx = LoginCtx::new(
            slot.operator.clone(),
            slot.administrator.clone(),
            slot.instances.clone(),
        );

        Self {
            login_ctx,
            slot_id,
            flags,
            db: slot.db.clone(),
            device_error: CKR_OK,
            sign_ctx: None,
            encrypt_ctx: None,
            decrypt_ctx: None,
            enum_ctx: None,
        }
    }
    pub fn get_ck_info(&self) -> CK_SESSION_INFO {
        let state = self.login_ctx.ck_state();

        CK_SESSION_INFO {
            slotID: self.slot_id,
            state,
            flags: self.flags,
            ulDeviceError: self.device_error,
        }
    }

    pub fn login(&mut self, user_type: CK_USER_TYPE, pin: String) -> Result<(), Error> {
        Ok(self.login_ctx.login(user_type, pin)?)
    }

    // ignore logout for now
    pub fn logout(&mut self) -> Result<(), Error> {
        self.login_ctx.logout();
        Ok(())
    }

    pub fn enum_init(&mut self, template: Option<CkRawAttrTemplate>) -> Result<(), Error> {
        if self.enum_ctx.is_some() {
            return Err(Error::OperationActive);
        }

        self.enum_ctx = Some(EnumCtx::enum_init(self, template)?);

        Ok(())
    }

    pub fn enum_next_chunk(&mut self, count: usize) -> Result<Vec<CK_SESSION_HANDLE>, Error> {
        match self.enum_ctx {
            Some(ref mut enum_ctx) => Ok(enum_ctx.next_chunck(count)),
            None => Err(Error::OperationNotInitialized),
        }
    }
    pub fn enum_final(&mut self) {
        self.enum_ctx = None;
    }

    pub fn sign_init(
        &mut self,
        mechanism: &Mechanism,
        key_handle: CK_OBJECT_HANDLE,
    ) -> Result<(), Error> {
        if self.sign_ctx.is_some() {
            return Err(Error::OperationActive);
        }

        trace!("sign_init() called with key handle {}", key_handle);
        trace!("sign_init() called with mechanism {:?}", mechanism);

        let db = self.db.lock()?;

        // get key id from the handle

        let key = match db.object(key_handle) {
            Some(object) => object,
            None => {
                return Err(Error::InvalidObjectHandle(key_handle));
            }
        };

        self.sign_ctx = Some(SignCtx::init(
            mechanism.clone(),
            key.clone(),
            &self.login_ctx,
        )?);

        Ok(())
    }

    pub fn sign_theoretical_size(&self) -> usize {
        let sign_ctx = self
            .sign_ctx
            .as_ref()
            .expect("sign context should be initialized");

        sign_ctx.get_theoretical_size()
    }

    pub fn sign_update(&mut self, data: &[u8]) -> Result<(), Error> {
        let sign_ctx = self
            .sign_ctx
            .as_mut()
            .ok_or(Error::OperationNotInitialized)?;

        sign_ctx.update(data);
        Ok(())
    }

    pub fn sign_final(&mut self) -> Result<Vec<u8>, Error> {
        let sign_ctx = self
            .sign_ctx
            .as_mut()
            .ok_or(Error::OperationNotInitialized)?;

        sign_ctx.sign_final()
    }

    pub fn sign(&mut self, data: &[u8]) -> Result<Vec<u8>, Error> {
        self.sign_update(data)?;
        self.sign_final()
    }

    pub fn sign_clear(&mut self) {
        self.sign_ctx = None;
    }

    pub fn encrypt_init(
        &mut self,
        mechanism: &Mechanism,
        key_handle: CK_OBJECT_HANDLE,
    ) -> Result<(), Error> {
        if self.encrypt_ctx.is_some() {
            return Err(Error::OperationActive);
        }

        let db = self.db.lock()?;

        // get key id from the handle

        let key = match db.object(key_handle) {
            Some(object) => object,

            None => {
                error!("Failed to get key: invalid handle");
                return Err(Error::InvalidObjectHandle(key_handle));
            }
        };

        self.encrypt_ctx = Some(EncryptCtx::init(mechanism.clone(), key, &self.login_ctx)?);

        Ok(())
    }

    pub fn encrypt_add_data(&mut self, data: &[u8]) -> Result<(), Error> {
        let encrypt_ctx = self
            .encrypt_ctx
            .as_mut()
            .ok_or(Error::OperationNotInitialized)?;

        encrypt_ctx.add_data(data);
        Ok(())
    }

    pub fn encrypt_available_data(&mut self) -> Result<Vec<u8>, Error> {
        let encrypt_ctx = self
            .encrypt_ctx
            .as_mut()
            .ok_or(Error::OperationNotInitialized)?;

        encrypt_ctx.encrypt_available_data()
    }

    pub fn encrypt_update(&mut self, data: &[u8]) -> Result<Vec<u8>, Error> {
        self.encrypt_add_data(data)?;
        self.encrypt_available_data()
    }

    pub fn encrypt_final(&mut self) -> Result<Vec<u8>, Error> {
        let encrypt_ctx = self
            .encrypt_ctx
            .as_mut()
            .ok_or(Error::OperationNotInitialized)?;

        encrypt_ctx.encrypt_final()
    }

    pub fn encrypt(&mut self, data: &[u8]) -> Result<Vec<u8>, Error> {
        self.encrypt_add_data(data)?;
        self.encrypt_final()
    }

    pub fn encrypt_clear(&mut self) {
        self.encrypt_ctx = None;
    }

    pub fn decrypt_init(
        &mut self,
        mechanism: &Mechanism,
        key_handle: CK_OBJECT_HANDLE,
    ) -> Result<(), Error> {
        if self.decrypt_ctx.is_some() {
            return Err(Error::OperationActive);
        }

        let db = self.db.lock()?;

        // get key id from the handle

        let key = match db.object(key_handle) {
            Some(object) => object,

            None => {
                error!("Failed to get key: invalid handle");
                return Err(Error::InvalidObjectHandle(key_handle));
            }
        };

        self.decrypt_ctx = Some(DecryptCtx::init(mechanism.clone(), key, &self.login_ctx)?);

        Ok(())
    }

    // only adds data to the decrypt context, does not decrypt anything
    pub fn decrypt_update(&mut self, data: &[u8]) -> Result<(), Error> {
        let decrypt_ctx = self
            .decrypt_ctx
            .as_mut()
            .ok_or(Error::OperationNotInitialized)?;

        decrypt_ctx.update(data);
        Ok(())
    }

    // For now we go safe and lazy and just return the same size as the input
    pub fn decrypt_theoretical_size(&self, input_size: usize) -> usize {
        input_size
    }

    pub fn decrypt_theoretical_final_size(&self) -> Result<usize, Error> {
        let decrypt_ctx = self
            .decrypt_ctx
            .as_ref()
            .ok_or(Error::OperationNotInitialized)?;

        Ok(decrypt_ctx.data.len())
    }

    pub fn decrypt_final(&mut self) -> Result<Vec<u8>, Error> {
        let decrypt_ctx = self
            .decrypt_ctx
            .as_mut()
            .ok_or(Error::OperationNotInitialized)?;

        decrypt_ctx.decrypt_final()
    }

    pub fn decrypt(&mut self, data: &[u8]) -> Result<Vec<u8>, Error> {
        self.decrypt_update(data)?;
        self.decrypt_final()
    }

    pub fn decrypt_clear(&mut self) {
        self.decrypt_ctx = None;
    }

    pub fn get_object(&self, handle: CK_OBJECT_HANDLE) -> Option<Object> {
        let db = match self.db.lock() {
            Ok(db) => db,
            Err(err) => {
                error!("Failed to lock db: {:?}", err);
                return None;
            }
        };

        db.object(handle).cloned()
    }

    pub(super) fn find_key(
        &mut self,
        requirements: KeyRequirements,
    ) -> Result<Vec<CK_OBJECT_HANDLE>, Error> {
        let mut result = match requirements.id {
            Some(key_id) => {
                let mut results: Vec<(CK_OBJECT_HANDLE, Object)> = self
                    .fetch_key(&key_id, requirements.raw_id)?
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

    fn fetch_all_keys(&mut self) -> Result<Vec<(CK_OBJECT_HANDLE, Object)>, Error> {
        {
            let mut db = self.db.lock()?;

            if db.fetched_all_keys() {
                return Ok(db
                    .enumerate()
                    .map(|(handle, obj)| (handle, obj.clone()))
                    .collect());
            }

            // clear the db to not have any double entries
            db.clear();
        }

        if !self
            .login_ctx
            .can_run_mode(super::login::UserMode::OperatorOrAdministrator)
        {
            return Err(Error::NotLoggedIn(
                super::login::UserMode::OperatorOrAdministrator,
            ));
        }

        let keys = self.login_ctx.try_(
            |api_config| default_api::keys_get(api_config, None),
            super::login::UserMode::OperatorOrAdministrator,
        )?;

        let mut handles = Vec::new();

        for key in keys {
            let mut objects = self.fetch_key(&key.key, None)?;

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
        let mut db = self.db.lock()?;
        db.set_fetched_all_keys(true);

        Ok(handles)
    }

    fn fetch_certificate(&mut self, key_id: &str) -> Result<(CK_OBJECT_HANDLE, Object), Error> {
        if !self
            .login_ctx
            .can_run_mode(super::login::UserMode::OperatorOrAdministrator)
        {
            return Err(Error::NotLoggedIn(
                super::login::UserMode::OperatorOrAdministrator,
            ));
        }

        let cert_data = self.login_ctx.try_(
            |api_config| default_api::keys_key_id_cert_get(api_config, key_id),
            super::login::UserMode::OperatorOrAdministrator,
        )?;

        let object = db::object::from_cert_data(cert_data, key_id)?;

        let r = self.db.lock()?.add_object(object);

        Ok(r)
    }

    // we need the raw id when the CKA_KEY_ID doesn't parse to an alphanumeric string
    fn fetch_key(
        &mut self,
        key_id: &str,
        raw_id: Option<Vec<u8>>,
    ) -> Result<Vec<(CK_OBJECT_HANDLE, Object)>, Error> {
        if !self
            .login_ctx
            .can_run_mode(super::login::UserMode::OperatorOrAdministrator)
        {
            return Err(Error::NotLoggedIn(
                super::login::UserMode::OperatorOrAdministrator,
            ));
        }

        let key_data = match self.login_ctx.try_(
            |api_config| default_api::keys_key_id_get(api_config, key_id),
            super::login::UserMode::OperatorOrAdministrator,
        ) {
            Ok(key_data) => key_data,
            Err(err) => {
                debug!("Failed to fetch key {}: {:?}", key_id, err);
                if matches!(
                    err,
                    Error::Api(ApiError::ResponseError(backend::ResponseContent {
                        status: reqwest::StatusCode::NOT_FOUND,
                        ..
                    }))
                ) {
                    return Ok(vec![]);
                }
                return Err(err);
            }
        };

        let objects = db::object::from_key_data(key_data, key_id, raw_id)?;

        let mut result = Vec::new();

        let mut db = self.db.lock()?;

        for object in objects {
            let r = db.add_object(object.clone());
            result.push((r.0, r.1.clone()));
        }

        Ok(result)
    }

    pub fn create_object(
        &mut self,
        template: CkRawAttrTemplate,
    ) -> Result<Vec<(CK_OBJECT_HANDLE, Object)>, Error> {
        if !self
            .login_ctx
            .can_run_mode(super::login::UserMode::Administrator)
        {
            return Err(Error::NotLoggedIn(super::login::UserMode::Administrator));
        }

        let key_info = create_key_from_template(template, &mut self.login_ctx)?;

        match key_info.1 {
            ObjectKind::Certificate => self
                .fetch_certificate(&key_info.0)
                .map(|(handle, obj)| vec![(handle, obj)]),
            _ => self.fetch_key(&key_info.0, None),
        }
    }

    pub fn delete_object(&mut self, handle: CK_OBJECT_HANDLE) -> Result<(), Error> {
        if !self.login_ctx.can_run_mode(UserMode::Administrator) {
            return Err(Error::NotLoggedIn(UserMode::Administrator));
        }

        let mut db = self.db.lock()?;

        let key = db
            .object(handle)
            .ok_or(Error::InvalidObjectHandle(handle))?;

        debug!("Deleting key {} {:?}", key.id, key.kind);

        match key.kind {
            ObjectKind::Certificate => self.login_ctx.try_(
                |api_config| default_api::keys_key_id_cert_delete(api_config, &key.id),
                crate::backend::login::UserMode::Administrator,
            )?,
            ObjectKind::SecretKey | ObjectKind::PrivateKey => self.login_ctx.try_(
                |api_config| default_api::keys_key_id_delete(api_config, &key.id),
                crate::backend::login::UserMode::Administrator,
            )?,
            _ => {
                // we don't support deleting other objects
            }
        }

        db.remove(handle)
            .ok_or(Error::InvalidObjectHandle(handle))?;

        Ok(())
    }

    pub fn generate_key(
        &mut self,
        template: &CkRawAttrTemplate,
        public_template: Option<&CkRawAttrTemplate>,
        mechanism: &Mechanism,
    ) -> Result<Vec<(CK_OBJECT_HANDLE, Object)>, Error> {
        if !self
            .login_ctx
            .can_run_mode(super::login::UserMode::Administrator)
        {
            return Err(Error::NotLoggedIn(super::login::UserMode::Administrator));
        }

        let res =
            generate_key_from_template(template, public_template, mechanism, &mut self.login_ctx)
                .map_err(|err| {
                error!("Failed to create key: {:?}", err);
                err
            })?;

        self.fetch_key(&res.0, res.1)
    }
}
