use std::env::set_var;
use std::io::BufWriter;

pub use config_file::P11Config;

use pkcs11::Ctx;
use tempfile::NamedTempFile;

pub fn run_tests(config: P11Config, f: impl FnOnce(&mut Ctx)) {
    let mut tmpfile: NamedTempFile = NamedTempFile::new().unwrap();

    serde_yaml::to_writer(BufWriter::new(tmpfile.as_file_mut()), &config).unwrap();
    let path = tmpfile.path();
    set_var(config_file::ENV_VAR_CONFIG_FILE, path);
    let mut ctx = Ctx::new_and_initialize("../target/release/libnethsm_pkcs11.so").unwrap();
    f(&mut ctx);
}
