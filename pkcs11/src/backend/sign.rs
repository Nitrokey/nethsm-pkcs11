use super::{
    db::Object,
    mechanism::{MechMode, Mechanism},
};
use base64::{engine::general_purpose, Engine as _};
use cryptoki_sys::{CKR_DEVICE_ERROR, CKR_MECHANISM_INVALID, CK_RV};
use log::{debug, error, trace};
use openapi::{apis::default_api, models::SignMode};

#[derive(Clone, Debug)]
pub struct SignCtx {
    pub mechanism: Mechanism,
    pub sign_name: SignMode,
    pub key: Object,
    pub data: Vec<u8>,
    pub api_config: openapi::apis::configuration::Configuration,
}

impl SignCtx {
    pub fn init(
        mechanism: Mechanism,
        key: Object,
        api_config: openapi::apis::configuration::Configuration,
    ) -> Result<Self, CK_RV> {
        let sign_name = mechanism.sign_name().ok_or_else(|| {
            debug!("Tried to sign with an invalid mechanism: {:?}", mechanism);
            CKR_MECHANISM_INVALID
        })?;

        let api_mech = match mechanism.to_api_mech(MechMode::Sign) {
            Some(mech) => mech,
            None => {
                debug!("Tried to sign with an invalid mechanism: {:?}", mechanism);
                return Err(CKR_MECHANISM_INVALID);
            }
        };

        if !key.mechanisms.contains(&api_mech) {
            debug!("Tried to sign with an invalid mechanism: {:?}", mechanism);
            return Err(CKR_MECHANISM_INVALID);
        }

        Ok(Self {
            mechanism,
            key,
            sign_name,
            data: Vec::new(),
            api_config,
        })
    }
    pub fn update(&mut self, data: &[u8]) {
        self.data.extend_from_slice(data);
    }

    pub fn sign_final(&self) -> Result<Vec<u8>, cryptoki_sys::CK_RV> {
        let b64_message = general_purpose::STANDARD.encode(self.data.as_slice());

        let mode = self.sign_name;
        trace!("Signing with mode: {:?}", mode);

        let signature = default_api::keys_key_id_sign_post(
            &self.api_config,
            &self.key.id,
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
        self.mechanism.get_theoretical_signed_size(self.key.size)
    }
}
