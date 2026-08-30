pub mod constants;
pub mod network;
pub mod setup;

use cryptoki::{
    context::{CInitializeArgs, CInitializeFlags, Pkcs11},
    slot::Slot,
};

pub fn run_test<F: FnOnce(&Pkcs11, Slot) -> R, R>(f: F) -> R {
    let _guard = setup::setup();
    setup::with_default_pkcs11_config(|| {
        let pkcs11 = Pkcs11::new("../target/release/libnethsm_pkcs11.so").unwrap();
        pkcs11
            .initialize(CInitializeArgs::new(CInitializeFlags::empty()))
            .unwrap();
        let slots = pkcs11.get_all_slots().unwrap();
        assert_eq!(slots.len(), 1);
        f(&pkcs11, slots[0])
    })
}
