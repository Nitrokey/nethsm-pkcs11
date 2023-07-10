use base64::{engine::general_purpose, Engine};
use cryptoki_sys::{CKR_ARGUMENTS_BAD, CKR_DEVICE_ERROR};
use log::{error, trace};
use openapi::apis::default_api;

use super::mechanism::Mechanism;

#[derive(Clone, Debug)]
pub struct DecryptCtx {
    pub mechanism: Mechanism,
    pub key_id: String,
    pub data: Vec<u8>,
    api_config: openapi::apis::configuration::Configuration,
}

impl DecryptCtx {
    pub fn new(
        mechanism: Mechanism,
        key_id: String,
        api_config: openapi::apis::configuration::Configuration,
    ) -> Self {
        Self {
            mechanism,
            key_id,
            data: Vec::new(),
            api_config,
        }
    }
    pub fn update(&mut self, data: &[u8]) {
        self.data.extend_from_slice(data);
    }

    pub fn decrypt_final(&self) -> Result<Vec<u8>, cryptoki_sys::CK_RV> {
        let b64_message = general_purpose::STANDARD.encode(self.data.as_slice());

        let mode = self.mechanism.decrypt_name().ok_or(CKR_ARGUMENTS_BAD)?;
        trace!("Signing with mode: {:?}", mode);

        let iv = self
            .mechanism
            .iv()
            .map(|iv| general_purpose::STANDARD.encode(iv.as_slice()));

        let output = default_api::keys_key_id_decrypt_post(
            &self.api_config,
            &self.key_id,
            openapi::models::DecryptRequestData {
                mode,
                encrypted: b64_message,
                iv,
            },
        )
        .map_err(|err| {
            error!("Failed to decrypt: {:?}", err);
            CKR_DEVICE_ERROR
        })?;

        general_purpose::STANDARD
            .decode(output.decrypted)
            .map_err(|err: base64::DecodeError| {
                error!("Failed to decode signature: {:?}", err);
                CKR_DEVICE_ERROR
            })
    }
}
