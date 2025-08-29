use std::{
    collections::HashMap,
    sync::{atomic::Ordering, Arc, Condvar, Mutex, MutexGuard},
};

use cryptoki_sys::{
    CKR_OK, CK_FLAGS, CK_OBJECT_HANDLE, CK_RV, CK_SESSION_HANDLE, CK_SESSION_INFO, CK_SLOT_ID,
    CK_USER_TYPE,
};
use log::{debug, error, trace};
use nethsm_sdk_rs::{apis::default_api, models::MoveKeyRequest};

use crate::{
    backend::{login::UserMode, Error},
    config::device::Slot,
    data::THREADS_ALLOWED,
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
    pub sessions: HashMap<CK_SESSION_HANDLE, Arc<Mutex<Session>>>,
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
        self.sessions.insert(handle, Arc::new(Mutex::new(session)));

        self.next_session_handle += 1;
        handle
    }

    pub fn get_session(&self, handle: CK_SESSION_HANDLE) -> Option<Arc<Mutex<Session>>> {
        self.sessions.get(&handle).cloned()
    }

    pub fn delete_session(
        &mut self,
        handle: CK_SESSION_HANDLE,
    ) -> Option<(CK_SESSION_HANDLE, Arc<Mutex<Session>>)> {
        self.sessions.remove_entry(&handle)
    }

    pub fn delete_all_slot_sessions(&mut self, slot_id: CK_SLOT_ID) {
        let mut deleted_sessions = Vec::new();
        self.sessions.iter().for_each(|(handle, session)| {
            if session.lock().unwrap().slot_id == slot_id {
                deleted_sessions.push(*handle);
            }
        });
        for handle in deleted_sessions.iter() {
            self.sessions.remove(handle);
        }
    }

    // test only function to setup a session how we want it
    #[allow(dead_code)]
    #[cfg(test)]
    pub fn set_session(&mut self, handle: CK_SESSION_HANDLE, session: Session) {
        self.sessions.insert(handle, Arc::new(Mutex::new(session)));
    }

    // test only function to setup a blank session
    #[cfg(test)]
    pub fn setup_dummy_session(&mut self) -> cryptoki_sys::CK_SESSION_HANDLE {
        self.create_session(
            0,
            Arc::new(Slot {
                administrator: None,
                retries: None,
                db: Arc::new((Mutex::new(Db::new()), Condvar::new())),
                _description: None,
                instances: Default::default(),
                label: "test".to_string(),
                operator: None,
                instance_balancer: Default::default(),
                certificate_format: config_file::CertificateFormat::Der,
            }),
            0,
        )
    }
}

#[derive(Debug)]
pub struct Session {
    pub slot_id: CK_SLOT_ID,
    pub login_ctx: LoginCtx,
    pub flags: CK_FLAGS,
    pub device_error: CK_RV,
    pub db: Arc<(Mutex<Db>, Condvar)>,
    pub sign_ctx: Option<SignCtx>,
    pub encrypt_ctx: Option<EncryptCtx>,
    pub decrypt_ctx: Option<DecryptCtx>,
    pub enum_ctx: Option<EnumCtx>,
}

impl Session {
    pub fn new(slot_id: CK_SLOT_ID, slot: Arc<Slot>, flags: CK_FLAGS) -> Self {
        let db = slot.db.clone();
        let login_ctx = LoginCtx::new(slot, true, true);

        Self {
            login_ctx,
            slot_id,
            flags,
            db,
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

        trace!("sign_init() called with key handle {key_handle}");
        trace!("sign_init() called with mechanism {mechanism:?}");

        // get key id from the handle

        let key = {
            let db = self.db.0.lock()?;
            match db.object(key_handle) {
                Some(object) => Ok(object.clone()),

                None => {
                    error!("Failed to get key: invalid handle");
                    Err(Error::InvalidObjectHandle(key_handle))
                }
            }
        }?;

        self.sign_ctx = Some(SignCtx::init(mechanism.clone(), key, &self.login_ctx)?);

        Ok(())
    }

    pub fn sign_theoretical_size(&self) -> Result<usize, Error> {
        let sign_ctx = self
            .sign_ctx
            .as_ref()
            .ok_or(Error::OperationNotInitialized)?;

        Ok(sign_ctx.get_theoretical_size())
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

        sign_ctx.sign_final(&self.login_ctx)
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

        let key = {
            let db = self.db.0.lock()?;
            match db.object(key_handle) {
                Some(object) => Ok(object.clone()),

                None => {
                    error!("Failed to get key: invalid handle");
                    Err(Error::InvalidObjectHandle(key_handle))
                }
            }
        }?;

        self.encrypt_ctx = Some(EncryptCtx::init(mechanism.clone(), &key, &self.login_ctx)?);

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

        encrypt_ctx.encrypt_available_data(&self.login_ctx)
    }

    pub fn encrypt_update(&mut self, data: &[u8]) -> Result<Vec<u8>, Error> {
        self.encrypt_add_data(data)?;
        self.encrypt_available_data()
    }

    pub fn encrypt_get_theoretical_final_size(&self) -> Result<usize, Error> {
        let encrypt_ctx = self
            .encrypt_ctx
            .as_ref()
            .ok_or(Error::OperationNotInitialized)?;

        Ok(encrypt_ctx.get_biggest_chunk_len())
    }

    pub fn encrypt_final(&mut self) -> Result<Vec<u8>, Error> {
        let encrypt_ctx = self
            .encrypt_ctx
            .as_mut()
            .ok_or(Error::OperationNotInitialized)?;

        encrypt_ctx.encrypt_final(&self.login_ctx)
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

        let key = {
            let db = self.db.0.lock()?;
            match db.object(key_handle) {
                Some(object) => Ok(object.clone()),

                None => {
                    error!("Failed to get key: invalid handle");
                    Err(Error::InvalidObjectHandle(key_handle))
                }
            }
        }?;

        self.decrypt_ctx = Some(DecryptCtx::init(mechanism.clone(), &key, &self.login_ctx)?);

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

        decrypt_ctx.decrypt_final(&self.login_ctx)
    }

    pub fn decrypt(&mut self, data: &[u8]) -> Result<Vec<u8>, Error> {
        self.decrypt_update(data)?;
        self.decrypt_final()
    }

    pub fn decrypt_clear(&mut self) {
        self.decrypt_ctx = None;
    }

    pub fn rename_objects(&self, old_id: &str, new_id: &str) -> Result<(), Error> {
        self.login_ctx.try_(
            |api_config| {
                default_api::keys_key_id_move_post(
                    api_config,
                    old_id,
                    MoveKeyRequest::new(new_id.to_owned()),
                )
            },
            crate::backend::login::UserMode::Administrator,
        )?;
        let mut db = self.db.0.lock().unwrap();
        db.rename(old_id, new_id);
        Ok(())
    }

    pub fn get_object(&self, handle: CK_OBJECT_HANDLE) -> Option<Object> {
        let db = self.db.0.lock().unwrap();

        db.object(handle).cloned()
    }

    pub(super) fn find_key(
        &mut self,
        requirements: KeyRequirements,
    ) -> Result<Vec<CK_OBJECT_HANDLE>, Error> {
        let result = match requirements.id {
            Some(key_id) => {
                // try to search in the db first
                let mut results: Vec<(CK_OBJECT_HANDLE, Object)> = {
                    let db = self.db.0.lock()?;
                    db.iter()
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
                            &self.login_ctx,
                            &self.db.0,
                        )?;
                    }

                    if (requirements.kind.is_none() && !results.is_empty())
                        || matches!(requirements.kind, Some(ObjectKind::Certificate))
                    {
                        match fetch_certificate(
                            &key_id,
                            requirements.raw_id,
                            &self.login_ctx,
                            &self.db.0,
                        ) {
                            Ok(cert) => {
                                trace!("Fetched certificate: {cert:?}");
                                results.push(cert);
                            }
                            Err(err) => {
                                debug!("Failed to fetch certificate: {err:?}");
                            }
                        }
                    }
                }
                Ok(results)
            }

            None => self.fetch_all_keys(),
        }?;

        Ok(result
            .into_iter()
            .filter(|(_, obj)| {
                if let Some(kind) = requirements.kind {
                    kind == obj.kind
                } else {
                    true
                }
            })
            .map(|(handle, _)| handle)
            .collect())
    }

    fn fetch_all_keys(&mut self) -> Result<Vec<(CK_OBJECT_HANDLE, Object)>, Error> {
        let condvar = &self.db.1;

        {
            let mut db = self.db.0.lock()?;

            if db.fetched_all_keys() {
                debug!("All keys already in cache. Returning");
                return Ok(db
                    .iter()
                    .map(|(handle, obj)| (handle, obj.clone()))
                    .collect());
            } else if db.is_being_fetched() {
                debug!("Fetch in progress, waiting");
                let mut db_inner = db;
                db_inner = condvar
                    .wait_while(db_inner, |db| {
                        debug!("Woken up");
                        db.is_being_fetched()
                    })
                    .unwrap();
                debug!("Waited for fetch");

                // If for some reason the waiting did not lead to keys being fetched, refetch everything.
                if db_inner.fetched_all_keys() {
                    return Ok(db_inner
                        .iter()
                        .map(|(handle, obj)| (handle, obj.clone()))
                        .collect());
                }
                db = db_inner;
            }

            // The cache is empty or the fetching failed, we are now the one fetching.
            db.set_is_being_fetched(true);
            debug!("Preparing to fetch");
        }

        /// Drop the Condvar to notify on close
        struct NotifyAllGuard<'a>(Option<&'a (Mutex<Db>, Condvar)>);
        impl Drop for NotifyAllGuard<'_> {
            fn drop(&mut self) {
                if let Some(cv) = self.0 {
                    cv.0.lock().unwrap().set_is_being_fetched(false);
                    cv.1.notify_all();
                }
            }
        }

        impl<'a> NotifyAllGuard<'a> {
            fn success(&mut self, mut lock: MutexGuard<'a, Db>) {
                let cv = self.0.take().unwrap();
                lock.set_is_being_fetched(false);
                lock.set_fetched_all_keys(true);
                drop(lock);
                cv.1.notify_all();
            }
        }

        let mut guard = NotifyAllGuard(Some(&self.db));

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
                |api_config| default_api::keys_get(api_config, None),
                super::login::UserMode::OperatorOrAdministrator,
            )?
            .entity;

        let results: Result<Vec<Vec<Object>>, _> = if THREADS_ALLOWED.load(Ordering::Relaxed) {
            use rayon::prelude::*;
            keys.par_iter()
                .map(|k| super::key::fetch_one(k, &self.login_ctx, None))
                .collect()
        } else {
            keys.iter()
                .map(|k| super::key::fetch_one(k, &self.login_ctx, None))
                .collect()
        };

        let results = results?;

        let mut db = self.db.0.lock()?;
        let handles = results
            .into_iter()
            .flatten()
            .map(|o| db.add_object(o))
            .collect();
        guard.success(db);

        Ok(handles)
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

        let key_info = create_key_from_template(template, &self.login_ctx)?;

        let db = self.db.clone();

        match key_info.1 {
            ObjectKind::Certificate => Ok(vec![fetch_certificate(
                &key_info.0,
                None,
                &self.login_ctx,
                &db.0,
            )?]),
            _ => fetch_key(&key_info.0, None, &self.login_ctx, &db.0),
        }
    }

    pub fn delete_object(&mut self, handle: CK_OBJECT_HANDLE) -> Result<(), Error> {
        if !self.login_ctx.can_run_mode(UserMode::Administrator) {
            return Err(Error::NotLoggedIn(UserMode::Administrator));
        }

        // get key id from the handle

        let key = {
            let db = self.db.0.lock()?;
            match db.object(handle) {
                Some(object) => Ok(object.clone()),

                None => Err(Error::InvalidObjectHandle(handle)),
            }
        }?;

        debug!("Deleting key {} {:?}", key.id, key.kind);

        match key.kind {
            ObjectKind::Certificate => {
                self.login_ctx.try_(
                    |api_config| default_api::keys_key_id_cert_delete(api_config, &key.id),
                    crate::backend::login::UserMode::Administrator,
                )?;
            }
            ObjectKind::SecretKey | ObjectKind::PrivateKey => {
                self.login_ctx.try_(
                    |api_config| default_api::keys_key_id_delete(api_config, &key.id),
                    crate::backend::login::UserMode::Administrator,
                )?;
            }
            _ => {
                // we don't support deleting other objects
            }
        }

        {
            let mut db = self.db.0.lock()?;
            match db.remove(handle) {
                Some(object) => Ok(object),

                None => Err(Error::InvalidObjectHandle(handle)),
            }
        }?;

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
            &self.login_ctx,
            &self.db.0,
        )
    }
}

#[cfg(test)]
mod test {
    use crate::{
        backend::{
            slot::{get_slot, init_for_tests},
            ApiError,
        },
        config::config_file::RetryConfig,
    };
    use std::thread;

    use super::*;

    // Ignored by default due to network access
    // Run with cargo test -- --test-threads=1 --ignored
    #[test]
    #[ignore]
    fn parrallel_fetch_all_keys() {
        init_for_tests();
        let slot = get_slot(0).unwrap();

        let db = Arc::new((Mutex::new(Db::new()), Condvar::new()));
        let mut sessions = Vec::new();
        for _ in 0..10 {
            let session = Session {
                db: db.clone(),
                decrypt_ctx: None,
                encrypt_ctx: None,
                sign_ctx: None,
                device_error: 0,
                enum_ctx: None,
                flags: 0,
                login_ctx: LoginCtx::new(slot.clone(), false, true),
                slot_id: 0,
            };
            sessions.push(session);
        }

        thread::scope(|s| {
            for session in &mut sessions {
                s.spawn(|| session.fetch_all_keys().unwrap());
            }
        })
    }

    // Ignored by default due to network access
    // Run with cargo test -- --test-threads=1 --ignored
    #[test]
    #[ignore]
    fn parrallel_fetch_all_keys_fail() {
        THREADS_ALLOWED.store(false, Ordering::Relaxed);
        init_for_tests();
        let mut slot = get_slot(0).unwrap();
        let mut sessions = Vec::new();
        for _ in 0..10 {
            let slot_mut = Arc::make_mut(&mut slot);

            slot_mut.db = Arc::new((Mutex::new(Db::new()), Condvar::new()));
            slot_mut.retries = Some(RetryConfig {
                count: 2,
                delay_seconds: 0,
            });
            let bad_instance = &mut slot_mut.instances[0];
            bad_instance
                .config_mut()
                .base_path
                .push_str("/corrupted_url");
            let session = Session {
                db: slot_mut.db.clone(),
                decrypt_ctx: None,
                encrypt_ctx: None,
                sign_ctx: None,
                device_error: 0,
                enum_ctx: None,
                flags: 0,
                login_ctx: LoginCtx::new(slot.clone(), false, true),
                slot_id: 0,
            };
            sessions.push(session);
        }

        thread::scope(|s| {
            for session in &mut sessions {
                s.spawn(|| {
                    match session.fetch_all_keys() {
                        Err(Error::Api(ApiError::Ureq(r))) => {
                            assert!(
                                r.ends_with(": status code 404"),
                                "expected 404 error, got {r}"
                            );
                        }
                        // FIXME: check for error 404 here
                        Err(Error::Api(ApiError::Serde(_))) => {}
                        res => panic!("{res:?}"),
                    };
                });
            }
        })
    }
}
