use std::collections::HashMap;

use cryptoki_sys::{
    CKR_OK, CKS_RO_PUBLIC_SESSION, CK_FLAGS, CK_SESSION_HANDLE, CK_SESSION_INFO, CK_SLOT_ID,
};

#[derive(Clone, Debug)]
pub struct SessionManager {
    pub sessions: HashMap<CK_SESSION_HANDLE, CK_SESSION_INFO>,
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
        let session = CK_SESSION_INFO {
            slotID: slot_id,
            flags,
            state: CKS_RO_PUBLIC_SESSION,
            ulDeviceError: CKR_OK,
        };
        let handle = self.next_session_handle;
        self.sessions.insert(handle, session);

        self.next_session_handle += 1;
        handle
    }

    pub fn get_session_info(&self, handle: CK_SESSION_HANDLE) -> Option<&CK_SESSION_INFO> {
        self.sessions.get(&handle)
    }

    pub fn delete_session(
        &mut self,
        handle: CK_SESSION_HANDLE,
    ) -> Option<(CK_SESSION_HANDLE, CK_SESSION_INFO)> {
        self.sessions.remove_entry(&handle)
    }

    pub fn delete_all_slot_sessions(&mut self, slot_id: CK_SLOT_ID) {
        let mut deleted_sessions = Vec::new();
        self.sessions.iter().for_each(|(handle, session)| {
            if session.slotID == slot_id {
                deleted_sessions.push((*handle, *session));
            }
        });
        for (handle, _) in deleted_sessions.iter() {
            self.sessions.remove(handle);
        }
    }
}
