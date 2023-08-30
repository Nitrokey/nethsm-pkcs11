use cryptoki_sys::CK_SLOT_ID;
use nethsm_sdk_rs::{apis::default_api, models::SystemState};

use crate::data::{DEVICE, EVENTS_MANAGER, TOKENS_STATE};

use super::login::LoginCtx;

pub struct EventsManager {
    pub events: Vec<CK_SLOT_ID>, // list of slots that changed

    // Used when CKF_DONT_BLOCK is clear and C_Finalize is called, then every blocking call to C_WaitForSlotEvent should return CKR_CRYPTOKI_NOT_INITIALIZED
    pub finalized: bool,
}

impl EventsManager {
    pub fn new() -> Self {
        EventsManager {
            events: Vec::new(),
            finalized: false,
        }
    }
}

pub fn update_slot_state(slot_id: CK_SLOT_ID, present: bool) {
    let mut tokens_state = TOKENS_STATE.lock().unwrap();
    if let Some(prev) = tokens_state.get(&slot_id) {
        if *prev == present {
            return;
        } else {
            // new event
            EVENTS_MANAGER.write().unwrap().events.push(slot_id);
        }
    }
    tokens_state.insert(slot_id, present);
}

pub fn fetch_slots_state() {
    for (index, slot) in DEVICE.slots.iter().enumerate() {
        let mut login_ctx = LoginCtx::new(None, None, slot.instances.clone());
        let status = login_ctx
            .try_(
                |conf| default_api::health_state_get(&conf),
                super::login::UserMode::Guest,
            )
            .map(|state| state.entity.state == SystemState::Operational)
            .unwrap_or(false);

        update_slot_state(index as CK_SLOT_ID, status);
    }
}
