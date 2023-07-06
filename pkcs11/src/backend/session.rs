use std::collections::HashMap;

use cryptoki_sys::{
    CKR_OK, CKS_RO_PUBLIC_SESSION, CK_FLAGS, CK_RV, CK_SESSION_HANDLE, CK_SLOT_ID, CK_STATE,
};

use super::mechanism::Mechanism;

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

    pub fn create_session(&mut self, slot_id: CK_SLOT_ID, flags: CK_FLAGS) -> CK_SESSION_HANDLE {
        let session = Session::new(slot_id, flags);
        let handle = self.next_session_handle;
        self.sessions.insert(handle, session);

        self.next_session_handle += 1;
        handle
    }

    pub fn get_session(&self, handle: CK_SESSION_HANDLE) -> Option<&Session> {
        self.sessions.get(&handle)
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
    pub flags: CK_FLAGS,
    pub state: CK_STATE,
    pub device_error: CK_RV,
    pub sign_ctx: Option<SignCtx>,
    pub encrypt_ctx: Option<EncryptCtx>,
    pub decrypt_ctx: Option<DecryptCtx>,
}

impl Session {
    pub fn new(slot_id: CK_SLOT_ID, flags: CK_FLAGS) -> Self {
        Self {
            slot_id,
            flags,
            state: CKS_RO_PUBLIC_SESSION,
            device_error: CKR_OK,
            sign_ctx: None,
            encrypt_ctx: None,
            decrypt_ctx: None,
        }
    }
    pub fn get_ck_info(&self) -> cryptoki_sys::CK_SESSION_INFO {
        cryptoki_sys::CK_SESSION_INFO {
            slotID: self.slot_id,
            state: self.state,
            flags: self.flags,
            ulDeviceError: self.device_error,
        }
    }
}

#[derive(Clone, Debug)]
pub struct SignCtx {}
#[derive(Clone, Debug)]
pub struct EncryptCtx {}
#[derive(Clone, Debug)]
pub struct DecryptCtx {}
