use super::mechanism::Mechanism;
use base64::{engine::general_purpose, Engine as _};
use cryptoki_sys::{CKR_ARGUMENTS_BAD, CKR_DEVICE_ERROR};
use log::{error, trace};
use openapi::apis::default_api;

#[derive(Clone, Debug)]
pub struct SignCtx {
    pub mechanism: Mechanism,
    pub key_id: String,
    pub key_size: Option<usize>,
    pub data: Vec<u8>,
    pub api_config: openapi::apis::configuration::Configuration,
}

impl SignCtx {
    pub fn new(
        mechanism: Mechanism,
        key_id: String,
        key_size: Option<usize>,
        api_config: openapi::apis::configuration::Configuration,
    ) -> Self {
        Self {
            mechanism,
            key_id,
            data: Vec::new(),
            api_config,
            key_size,
        }
    }
    pub fn update(&mut self, data: &[u8]) {
        self.data.extend_from_slice(data);
    }

    pub fn sign_final(&self) -> Result<Vec<u8>, cryptoki_sys::CK_RV> {
        let b64_message = general_purpose::STANDARD.encode(self.data.as_slice());

        let mode = self.mechanism.sign_name().ok_or(CKR_ARGUMENTS_BAD)?;
        trace!("Signing with mode: {:?}", mode);

        let signature = default_api::keys_key_id_sign_post(
            &self.api_config,
            &self.key_id,
            openapi::models::SignRequestData {
                mode,
                message: b64_message,
            },
        )
        .map_err(|err| {
            error!("Failed to sign: {:?}", err);
            CKR_DEVICE_ERROR
        })?;

        general_purpose::STANDARD
            .decode(signature.signature)
            .map_err(|err| {
                error!("Failed to decode signature: {:?}", err);
                CKR_DEVICE_ERROR
            })
    }

    pub fn get_theoretical_size(&self) -> usize {
        self.mechanism.get_theoretical_signed_size(self.key_size)
    }
}
