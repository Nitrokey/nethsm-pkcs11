use log::error;

use crate::{config, data::GLOBAL_CONFIG};

pub fn get_slot_config(slot_id: usize) -> Result<config::SlotConfig, cryptoki_sys::CK_RV> {
    let config = GLOBAL_CONFIG.read().map_err(|e| {
        error!("Error reading clients: {:?}", e);
        cryptoki_sys::CKR_FUNCTION_FAILED
    })?;
    config
        .slots
        .get(slot_id)
        .ok_or_else(|| {
            error!("No client found for slotID: {}", slot_id);
            cryptoki_sys::CKR_SLOT_ID_INVALID
        })
        .map(|client| client.clone())
}
