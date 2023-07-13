use std::{collections::HashMap, sync::Arc};

use cryptoki_sys::{
    CKR_DEVICE_ERROR, CKR_OK, CKR_PIN_INCORRECT, CKR_USER_TYPE_INVALID, CKS_RO_PUBLIC_SESSION,
    CKS_RW_SO_FUNCTIONS, CKS_RW_USER_FUNCTIONS, CKU_SO, CKU_USER, CK_FLAGS, CK_OBJECT_HANDLE,
    CK_RV, CK_SESSION_HANDLE, CK_SLOT_ID, CK_USER_TYPE,
};
use log::{error, info};
use openapi::{
    apis::default_api::{self},
    models::UserRole,
};

use crate::config::device::Slot;

use super::{
    db::{self, attr::CkRawAttrTemplate, Db, Object, ObjectHandle},
    decrypt::DecryptCtx,
    encrypt::EncryptCtx,
    mechanism::Mechanism,
    object::EnumCtx,
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

#[derive(Clone, Debug, PartialEq)]
pub enum UserStatus {
    Operator,
    Administrator,
    LoggedOut,
}

impl UserStatus {
    pub fn from_ck_user_type(user_type: CK_USER_TYPE) -> Self {
        match user_type {
            CKU_USER => Self::Operator,
            CKU_SO => Self::Administrator,
            _ => Self::LoggedOut,
        }
    }
}

#[derive(Clone, Debug)]
pub struct Session {
    pub slot_id: CK_SLOT_ID,
    pub api_config: openapi::apis::configuration::Configuration,
    pub flags: CK_FLAGS,
    pub user: UserStatus,
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

        let api_configuration = slot.api_config.clone();

        let user = get_current_user(&api_configuration);

        Self {
            api_config: api_configuration,
            slot_id,
            flags,
            user,
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
        let state = match self.user {
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
        let mut username = self
            .api_config
            .basic_auth
            .clone()
            .map(|(username, _)| username);

        // if we want to be admin but the previous username does not login as admin, we set the username to admin
        if user_type == CKU_SO && (self.user != UserStatus::Administrator || username.is_none()) {
            info!("Setting username to admin");

            username = Some("admin".to_string());
        }

        let username = match username {
            Some(username) => username,
            None => {
                error!("Failed to login: no username set");
                return CKR_USER_TYPE_INVALID;
            }
        };

        // we can unwrap here, because the auth should always be set
        self.api_config.basic_auth = Some((username, Some(pin)));

        // try an authenticated request to see if the pin is correct
        let user = get_current_user(&self.api_config);

        if user == UserStatus::LoggedOut {
            error!("Failed to login: invalid username or pin");
            self.api_config.basic_auth = None;
            return CKR_PIN_INCORRECT;
        }

        let wanted_user = UserStatus::from_ck_user_type(user_type);

        if wanted_user != user {
            error!("Failed to login: invalid user type");
            self.api_config.basic_auth = None;
            return CKR_USER_TYPE_INVALID;
        }

        CKR_OK
    }

    pub fn logout(&mut self) -> CK_RV {
        self.api_config.basic_auth = None;
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

        self.sign_ctx = match SignCtx::init(mechanism.clone(), key.clone(), self.api_config.clone())
        {
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

        self.encrypt_ctx = match EncryptCtx::init(mechanism.clone(), key, self.api_config.clone()) {
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

        self.decrypt_ctx = match DecryptCtx::init(mechanism.clone(), key, self.api_config.clone()) {
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
        key_id: Option<String>,
    ) -> Result<Vec<CK_OBJECT_HANDLE>, CK_RV> {
        match key_id {
            Some(key_id) => Ok(self
                .fetch_key(key_id)?
                .iter()
                .map(|(handle, _)| *handle)
                .collect()),
            None => self.fetch_all_keys(),
        }
    }

    fn fetch_all_keys(&mut self) -> Result<Vec<CK_OBJECT_HANDLE>, CK_RV> {
        if self.fetched_all_keys {
            return Ok(self
                .db
                .enumerate()
                .map(|(handle, _)| handle.into())
                .collect());
        }

        // clear the db to not have any double entries
        self.db.clear();

        let keys = default_api::keys_get(&self.api_config, None).map_err(|err| {
            error!("Failed to fetch keys: {:?}", err);
            CKR_DEVICE_ERROR
        })?;

        let mut handles = Vec::new();

        for key in keys {
            let objects = self.fetch_key(key.key)?;
            for (handle, _) in objects {
                handles.push(handle);
            }
        }
        Ok(handles)
    }

    fn fetch_key(&mut self, key_id: String) -> Result<Vec<(CK_OBJECT_HANDLE, Object)>, CK_RV> {
        let key_data = default_api::keys_key_id_get(&self.api_config, &key_id).map_err(|err| {
            error!("Failed to fetch key {}: {:?}", key_id, err);
            CKR_DEVICE_ERROR
        })?;

        let objects = db::object::from_key_data(key_data, key_id.clone()).map_err(|err| {
            error!("Failed to convert key {}: {:?}", key_id, err);
            CKR_DEVICE_ERROR
        })?;

        let mut result = Vec::new();

        for object in objects {
            let handle = self.db.add_object(object.clone());
            result.push((handle, object));
        }

        Ok(result)
    }
}

pub fn get_current_user(api_config: &openapi::apis::configuration::Configuration) -> UserStatus {
    let auth = match api_config.basic_auth.as_ref() {
        Some(auth) => auth,
        None => return UserStatus::LoggedOut,
    };

    if auth.1.is_none() {
        return UserStatus::LoggedOut;
    }

    let user = match default_api::users_user_id_get(api_config, auth.0.as_str()) {
        Ok(user) => user,
        Err(err) => {
            error!("Failed to get user: {:?}", err);
            return UserStatus::LoggedOut;
        }
    };

    match user.role {
        UserRole::Operator => UserStatus::Operator,
        UserRole::Administrator => UserStatus::Administrator,
        _ => UserStatus::LoggedOut,
    }
}
