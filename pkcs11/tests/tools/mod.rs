use std::io::{BufWriter, Read};
use std::process::{Child, Stdio};
use std::sync::Arc;
use std::thread::sleep;
use std::time::Duration;
use std::{env::set_var, process::Command};

pub use config_file::P11Config;

use nethsm_sdk_rs::{
    apis::{
        configuration::Configuration,
        default_api::{provision_post, users_user_id_put},
    },
    models::{ProvisionRequestData, UserPostData, UserRole},
};
use pkcs11::Ctx;
use rustls::{
    client::danger::ServerCertVerifier,
    crypto::{verify_tls12_signature, verify_tls13_signature, CryptoProvider},
};
use tempfile::NamedTempFile;
use time::format_description;
use ureq::AgentBuilder;

pub const TEST_NETHSM_INSTANCE: &str = match option_env!("TEST_NETHSM_INSTANCE") {
    Some(v) => v,
    None => "https://localhost:8443/api/v1",
};

#[derive(Debug)]
struct DangerIgnoreVerifier;

impl ServerCertVerifier for DangerIgnoreVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        let default_provider = CryptoProvider::get_default().unwrap();
        verify_tls12_signature(
            message,
            cert,
            dss,
            &default_provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        let default_provider = CryptoProvider::get_default().unwrap();
        verify_tls13_signature(
            message,
            cert,
            dss,
            &default_provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        let default_provider = CryptoProvider::get_default().unwrap();

        default_provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

fn tls_conf() -> rustls::ClientConfig {
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();
    rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(DangerIgnoreVerifier))
        .with_no_client_auth()
}

struct Dropper(Child);

impl Drop for Dropper {
    fn drop(&mut self) {
        Command::new("kill")
            .args([self.0.id().to_string()])
            .spawn()
            .unwrap()
            .wait()
            .unwrap();
        self.0.wait().unwrap();
        let mut buf = String::new();
        self.0
            .stdout
            .take()
            .unwrap()
            .read_to_string(&mut buf)
            .unwrap();
        buf.push('\n');
        self.0
            .stderr
            .take()
            .unwrap()
            .read_to_string(&mut buf)
            .unwrap();
        println!("{buf}");
    }
}

pub fn run_tests(config: P11Config, f: impl FnOnce(&mut Ctx)) {
    let _dropper = Dropper(
        Command::new("podman")
            .args([
                "run",
                "--rm",
                "-ti",
                "-p8443:8443",
                "-p8080:8080",
                "docker.io/nitrokey/nethsm:testing",
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    );

    let client = AgentBuilder::new().tls_config(Arc::new(tls_conf())).build();

    let sdk_config = Configuration {
        client,
        base_path: TEST_NETHSM_INSTANCE.into(),
        basic_auth: Some(("admin".into(), Some("Administrator".into()))),
        ..Default::default()
    };

    sleep(Duration::from_secs(2));

    // match system_factory_reset_post(&sdk_config) {
    //     Ok(_) => {}
    //     Err(nethsm_sdk_rs::apis::Error::ResponseError(ResponseContent {
    //         entity: SystemFactoryResetPostError::Status412(),
    //         ..
    //     })) => {}
    //     Err(nethsm_sdk_rs::apis::Error::Ureq(ureq::Error::Status(412, _))) => {}
    //     Err(e) => panic!("{e}"),
    // };
    provision_post(
        &sdk_config,
        ProvisionRequestData {
            unlock_passphrase: "1234567890".into(),
            admin_passphrase: "Administrator".into(),
            system_time: time::OffsetDateTime::now_utc()
                .format(
                    &format_description::parse("[year]-[month]-[day]T[hour]:[minute]:[second]Z")
                        .unwrap(),
                )
                .unwrap(),
        },
    )
    .unwrap();
    users_user_id_put(
        &sdk_config,
        "operator",
        UserPostData {
            real_name: "Operator".into(),
            role: UserRole::Operator,
            passphrase: "opPassphrase".into(),
        },
    )
    .unwrap();

    let mut tmpfile: NamedTempFile = NamedTempFile::new().unwrap();

    serde_yaml::to_writer(BufWriter::new(tmpfile.as_file_mut()), &config).unwrap();
    let path = tmpfile.path();
    set_var(config_file::ENV_VAR_CONFIG_FILE, path);
    let mut ctx = Ctx::new_and_initialize("../target/release/libnethsm_pkcs11.so").unwrap();
    f(&mut ctx);
    ctx.close_all_sessions(0).unwrap();
}
