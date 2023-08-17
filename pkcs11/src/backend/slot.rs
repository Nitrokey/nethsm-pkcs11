use std::sync::Arc;

use crate::{config::device::Slot, data::DEVICE};

pub fn get_slot(slot_id: usize) -> Result<Arc<Slot>, cryptoki_sys::CK_RV> {
    let slot = DEVICE
        .slots
        .get(slot_id)
        .ok_or(cryptoki_sys::CKR_SLOT_ID_INVALID)?;
    Ok(slot.clone())
}

#[cfg(test)]
pub fn set_test_config_env() {
    std::env::set_var("P11NETHSM_CONFIG_FILE", "../p11nethsm.conf");
}
