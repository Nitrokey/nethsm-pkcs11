use std::sync::Arc;

use crate::{config::device::Slot, data::DEVICE};
use log::error;

pub fn get_slot(slot_id: usize) -> Result<Arc<Slot>, cryptoki_sys::CK_RV> {
    let Some(device) = DEVICE.get() else {
        error!("Initialization was not performed or failed");
        return Err(cryptoki_sys::CKR_CRYPTOKI_NOT_INITIALIZED);
    };

    let slot = device
        .slots
        .get(slot_id)
        .ok_or(cryptoki_sys::CKR_SLOT_ID_INVALID)?;
    Ok(slot.clone())
}

#[cfg(test)]
pub fn init_for_tests() {
    use std::ptr;
    use std::sync::Once;

    use crate::api::C_Initialize;

    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        std::env::set_var("P11NETHSM_CONFIG_FILE", "../p11nethsm.conf");
        assert_eq!(C_Initialize(ptr::null_mut()), cryptoki_sys::CKR_OK);
    })
}
