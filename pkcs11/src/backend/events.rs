use std::sync::Arc;

use arc_swap::ArcSwap;
use cryptoki_sys::CK_SLOT_ID;
use nethsm_sdk_rs::{apis::default_api, models::SystemState};

use crossbeam::channel::{bounded, Receiver, Sender, TrySendError};

use crate::data::{self, EVENTS_MANAGER, TOKENS_STATE};

use super::{login::LoginCtx, Pkcs11Error};

pub struct EventsManager {
    pub sender: ArcSwap<Sender<CK_SLOT_ID>>,
    pub receiver: ArcSwap<Receiver<CK_SLOT_ID>>,
}

impl EventsManager {
    pub fn new() -> Self {
        let (tx, rx) = bounded(128);
        EventsManager {
            sender: ArcSwap::new(Arc::new(tx)),
            receiver: ArcSwap::new(Arc::new(rx)),
        }
    }

    pub fn reset(&self) {
        let (tx, rx) = bounded(128);
        self.sender.store(Arc::new(tx));
        self.receiver.store(Arc::new(rx));
    }
}

pub fn update_slot_state(slot_id: CK_SLOT_ID, present: bool) {
    let mut tokens_state = TOKENS_STATE.lock().unwrap();
    if let Some(prev) = tokens_state.get(&slot_id) {
        if *prev == present {
            return;
        } else {
            // new event
            loop {
                match EVENTS_MANAGER.sender.load().try_send(slot_id) {
                    Ok(_) => break,
                    Err(TrySendError::Full(_)) => {
                        log::warn!("Dropping slot event to avoid filling up memory")
                    }
                    Err(TrySendError::Disconnected(_)) => {
                        continue;
                    }
                };
            }
        }
    }
    tokens_state.insert(slot_id, present);
}

pub fn fetch_slots_state() -> Result<(), Pkcs11Error> {
    let device = data::load_device()?;
    for (index, slot) in device.slots.iter().enumerate() {
        let login_ctx = LoginCtx::new(slot.clone(), false, false);
        let status = login_ctx
            .try_(default_api::health_state_get, super::login::UserMode::Guest)
            .map(|state| state.entity.state == SystemState::Operational)
            .unwrap_or(false);

        update_slot_state(index as CK_SLOT_ID, status);
    }
    Ok(())
}
