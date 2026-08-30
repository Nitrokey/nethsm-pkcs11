pub mod constants;
pub mod network;
pub mod setup;

use pkcs11::Ctx;

pub fn run_test<F: FnOnce(&mut Ctx)>(f: F) {
    let _guard = setup::setup();
    setup::with_default_pkcs11_config(|| {
        let mut ctx = Ctx::new_and_initialize("../target/release/libnethsm_pkcs11.so").unwrap();
        f(&mut ctx)
    })
}
