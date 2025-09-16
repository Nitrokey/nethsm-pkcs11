use std::sync::Arc;

use crate::{backend::Pkcs11Error, config::device::Slot, data::DEVICE};
use log::error;

pub fn get_slot(slot_id: usize) -> Result<Arc<Slot>, Pkcs11Error> {
    let Some(device) = DEVICE.load_full() else {
        error!("Initialization was not performed or failed");
        return Err(Pkcs11Error::CryptokiNotInitialized);
    };

    let slot = device
        .slots
        .get(slot_id)
        .ok_or(Pkcs11Error::SlotIdInvalid)?;
    Ok(slot.clone())
}

#[cfg(test)]
pub fn init_for_tests() {
    use std::ptr;

    use crate::api::C_Initialize;

    if DEVICE.load().is_none() {
        std::env::set_var("P11NETHSM_CONFIG_FILE", "../p11nethsm.conf");
        assert_eq!(C_Initialize(ptr::null_mut()), cryptoki_sys::CKR_OK);
    }
}
