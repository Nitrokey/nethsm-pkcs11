use std::{collections::HashMap, sync::Arc};

use cryptoki_sys::{
    CKR_OK, CK_FLAGS, CK_OBJECT_HANDLE, CK_RV, CK_SESSION_HANDLE, CK_SESSION_INFO, CK_SLOT_ID,
    CK_USER_TYPE,
};
use log::{debug, error, trace};
use nethsm_sdk_rs::apis::default_api;
use tokio::{sync::Mutex, task::JoinSet};

use crate::{
    backend::{login::UserMode, Error},
    config::device::Slot,
    utils::get_tokio_rt,
};

use super::{
    db::{attr::CkRawAttrTemplate, object::ObjectKind, Db, Object},
    decrypt::DecryptCtx,
    encrypt::EncryptCtx,
    key::{create_key_from_template, fetch_certificate, fetch_key, generate_key_from_template},
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
        Ok(get_tokio_rt().block_on(self.login_ctx.login(user_type, pin))?)
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

        // get key id from the handle

        let key = get_tokio_rt().block_on(async {
            let db = self.db.lock().await;
            match db.object(key_handle) {
                Some(object) => Ok(object.clone()),

                None => {
                    error!("Failed to get key: invalid handle");
                    Err(Error::InvalidObjectHandle(key_handle))
                }
            }
        })?;

        self.sign_ctx = Some(SignCtx::init(
            mechanism.clone(),
            key,
            self.login_ctx.clone(),
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

        // get key id from the handle

        let key = get_tokio_rt().block_on(async {
            let db = self.db.lock().await;
            match db.object(key_handle) {
                Some(object) => Ok(object.clone()),

                None => {
                    error!("Failed to get key: invalid handle");
                    Err(Error::InvalidObjectHandle(key_handle))
                }
            }
        })?;

        self.encrypt_ctx = Some(EncryptCtx::init(
            mechanism.clone(),
            &key,
            self.login_ctx.clone(),
        )?);

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

        // get key id from the handle

        let key = get_tokio_rt().block_on(async {
            let db = self.db.lock().await;
            match db.object(key_handle) {
                Some(object) => Ok(object.clone()),

                None => {
                    error!("Failed to get key: invalid handle");
                    Err(Error::InvalidObjectHandle(key_handle))
                }
            }
        })?;

        self.decrypt_ctx = Some(DecryptCtx::init(
            mechanism.clone(),
            &key,
            self.login_ctx.clone(),
        )?);

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
        get_tokio_rt().block_on(async {
            let db = self.db.lock().await;

            db.object(handle).cloned()
        })
    }

    pub(super) async fn find_key(
        &mut self,
        requirements: KeyRequirements,
    ) -> Result<Vec<CK_OBJECT_HANDLE>, Error> {
        let mut result = match requirements.id {
            Some(key_id) => {
                // try to search in the db first
                let mut results: Vec<(CK_OBJECT_HANDLE, Object)> = {
                    let db = self.db.lock().await;
                    db.enumerate()
                        .filter(|(_, obj)| {
                            obj.id == key_id
                                && requirements.kind.map(|k| k == obj.kind).unwrap_or(true)
                        })
                        .map(|(handle, obj)| (handle, obj.clone()))
                        .collect()
                };

                // then try to fetch from the server
                if results.is_empty() {
                    if matches!(
                        requirements.kind,
                        None | Some(ObjectKind::Other)
                            | Some(ObjectKind::PrivateKey)
                            | Some(ObjectKind::PublicKey)
                            | Some(ObjectKind::SecretKey)
                    ) {
                        results = fetch_key(
                            &key_id,
                            requirements.raw_id.clone(),
                            self.login_ctx.clone(),
                            self.db.clone(),
                        )
                        .await?
                        .iter()
                        .map(|(handle, obj)| (*handle, obj.clone()))
                        .collect();
                    }

                    if (requirements.kind.is_none() && !results.is_empty())
                        || matches!(requirements.kind, Some(ObjectKind::Certificate))
                    {
                        match fetch_certificate(
                            &key_id,
                            requirements.raw_id,
                            self.login_ctx.clone(),
                            self.db.clone(),
                        )
                        .await
                        {
                            Ok(ref mut vec) => results.append(vec),
                            Err(err) => {
                                debug!("Failed to fetch certificate: {:?}", err);
                            }
                        }
                    }
                }
                Ok(results)
            }

            None => self.fetch_all_keys(requirements.kind).await,
        }?;

        if let Some(kind) = requirements.kind {
            result.retain(|(_, obj)| obj.kind == kind);
        }

        Ok(result.iter().map(|(handle, _)| *handle).collect())
    }

    async fn fetch_all_keys(
        &mut self,
        kind: Option<ObjectKind>,
    ) -> Result<Vec<(CK_OBJECT_HANDLE, Object)>, Error> {
        {
            let db = self.db.lock().await;

            if db.fetched_all_keys() {
                return Ok(db
                    .enumerate()
                    .map(|(handle, obj)| (handle, obj.clone()))
                    .collect());
            }
        }

        if !self
            .login_ctx
            .can_run_mode(super::login::UserMode::OperatorOrAdministrator)
        {
            return Err(Error::NotLoggedIn(
                super::login::UserMode::OperatorOrAdministrator,
            ));
        }

        let keys = self
            .login_ctx
            .try_(
                |api_config| async move { default_api::keys_get(&api_config, None).await },
                super::login::UserMode::OperatorOrAdministrator,
            )
            .await?
            .entity;

        let mut set: JoinSet<Result<Vec<(u64, Object)>, Error>> = JoinSet::new();

        let mut handles = Vec::new();

        // limit to 15 concurrent requests
        let semaphore: Arc<tokio::sync::Semaphore> = Arc::new(tokio::sync::Semaphore::new(15));

        // If we want everything or only the keys
        if matches!(
            kind,
            None | Some(ObjectKind::Other)
                | Some(ObjectKind::PrivateKey)
                | Some(ObjectKind::PublicKey)
                | Some(ObjectKind::SecretKey)
        ) {
            for key in &keys {
                let key_id = key.key.clone();

                let login_ctx = self.login_ctx.clone();
                let db = self.db.clone();
                let semaphore_permit = semaphore.clone().acquire_owned().await.unwrap();

                set.spawn(async move {
                    let res = fetch_key(&key_id, None, login_ctx, db).await;

                    drop(semaphore_permit);

                    res
                });
            }
        }

        // If we want everything or only the certificates
        if matches!(kind, None | Some(ObjectKind::Certificate)) {
            for key in keys {
                let cert_id = key.key.clone();
                let login_ctx = self.login_ctx.clone();
                let db = self.db.clone();

                let semaphore_permit = semaphore.clone().acquire_owned().await.unwrap();

                set.spawn(async move {
                    let res = match fetch_certificate(&cert_id, None, login_ctx, db).await {
                        Ok(vec) => Ok(vec),
                        Err(err) => {
                            debug!("Failed to fetch certificate: {:?}", err);
                            Ok(Vec::new())
                        }
                    };
                    drop(semaphore_permit);

                    res
                });
            }
        }

        while let Some(res) = set.join_next().await {
            let mut objs = res.map_err(|_| Error::InvalidData)??;
            handles.append(&mut objs);
        }

        let mut db = self.db.lock().await;
        db.set_fetched_all_keys(true);

        Ok(handles)
    }

    pub async fn create_object(
        &mut self,
        template: CkRawAttrTemplate,
    ) -> Result<Vec<(CK_OBJECT_HANDLE, Object)>, Error> {
        if !self
            .login_ctx
            .can_run_mode(super::login::UserMode::Administrator)
        {
            return Err(Error::NotLoggedIn(super::login::UserMode::Administrator));
        }

        let login_ctx = self.login_ctx.clone();

        let key_info = create_key_from_template(template, login_ctx).await?;

        let login_ctx = self.login_ctx.clone();
        let db = self.db.clone();

        match key_info.1 {
            ObjectKind::Certificate => fetch_certificate(&key_info.0, None, login_ctx, db).await,
            _ => fetch_key(&key_info.0, None, login_ctx, db).await,
        }
    }

    pub fn delete_object(&mut self, handle: CK_OBJECT_HANDLE) -> Result<(), Error> {
        if !self.login_ctx.can_run_mode(UserMode::Administrator) {
            return Err(Error::NotLoggedIn(UserMode::Administrator));
        }

        // get key id from the handle

        let key = get_tokio_rt().block_on(async {
            let db = self.db.lock().await;
            match db.object(handle) {
                Some(object) => Ok(object.clone()),

                None => Err(Error::InvalidObjectHandle(handle)),
            }
        })?;

        debug!("Deleting key {} {:?}", key.id, key.kind);

        match key.kind {
            ObjectKind::Certificate => {
                get_tokio_rt().block_on(async {
                    self.login_ctx
                        .try_(
                            |api_config| async move {
                                default_api::keys_key_id_cert_delete(&api_config, &key.id).await
                            },
                            crate::backend::login::UserMode::Administrator,
                        )
                        .await
                })?;
            }
            ObjectKind::SecretKey | ObjectKind::PrivateKey => {
                get_tokio_rt().block_on(async {
                    self.login_ctx
                        .try_(
                            |api_config| async move {
                                default_api::keys_key_id_delete(&api_config, &key.id).await
                            },
                            crate::backend::login::UserMode::Administrator,
                        )
                        .await
                })?;
            }
            _ => {
                // we don't support deleting other objects
            }
        }

        get_tokio_rt().block_on(async {
            let mut db = self.db.lock().await;
            match db.remove(handle) {
                Some(object) => Ok(object),

                None => Err(Error::InvalidObjectHandle(handle)),
            }
        })?;

        Ok(())
    }

    pub fn generate_key(
        &self,
        template: &CkRawAttrTemplate,
        public_template: Option<&CkRawAttrTemplate>,
        mechanism: &Mechanism,
    ) -> Result<Vec<(CK_OBJECT_HANDLE, Object)>, Error> {
        if !self.login_ctx.can_run_mode(UserMode::Administrator) {
            return Err(Error::NotLoggedIn(UserMode::Administrator));
        }

        generate_key_from_template(
            template,
            public_template,
            mechanism,
            self.login_ctx.clone(),
            self.db.clone(),
        )
    }
}
