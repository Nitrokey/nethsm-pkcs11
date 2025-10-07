use std::sync::Arc;

use cryptoki_sys::CK_SLOT_ID;

use crate::{backend::Pkcs11Error, config::device::Slot, data};

pub fn get_slot(slot_id: CK_SLOT_ID) -> Result<Arc<Slot>, Pkcs11Error> {
    let device = data::load_device()?;
    let slot_id = usize::try_from(slot_id).map_err(|_| Pkcs11Error::SlotIdInvalid)?;
    let slot = device
        .slots
        .get(slot_id)
        .ok_or(Pkcs11Error::SlotIdInvalid)?;
    Ok(slot.clone())
}

#[cfg(test)]
pub fn init_for_tests() -> std::sync::MutexGuard<'static, ()> {
    use std::{ptr, sync::Mutex};

    use crate::{api::C_Initialize, data::DEVICE};

    static MUTEX: Mutex<()> = Mutex::new(());

    let guard = MUTEX.lock().unwrap_or_else(|err| err.into_inner());

    if DEVICE.load().is_none() {
        std::env::set_var("P11NETHSM_CONFIG_FILE", "../p11nethsm.conf");
        assert_eq!(C_Initialize(ptr::null_mut()), cryptoki_sys::CKR_OK);
    }

    guard
}
