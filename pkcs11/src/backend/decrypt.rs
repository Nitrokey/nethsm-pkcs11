use base64::{engine::general_purpose, Engine};
use cryptoki_sys::{
    CKR_ARGUMENTS_BAD, CKR_DEVICE_ERROR, CKR_MECHANISM_INVALID, CKR_USER_NOT_LOGGED_IN, CK_RV,
};
use log::{error, trace};
use openapi::apis::default_api;

use super::{
    db::Object,
    login::{self, LoginCtx},
    mechanism::{MechMode, Mechanism},
};

#[derive(Clone, Debug)]
pub struct DecryptCtx {
    pub mechanism: Mechanism,
    pub key_id: String,
    pub data: Vec<u8>,
    login_ctx: LoginCtx,
}

impl DecryptCtx {
    pub fn init(mechanism: Mechanism, key: &Object, login_ctx: &LoginCtx) -> Result<Self, CK_RV> {
        let login_ctx = login_ctx.clone();

        if !login_ctx.can_run_mode(login::UserMode::Operator) {
            error!("No operator is logged in");
            return Err(CKR_USER_NOT_LOGGED_IN);
        }

        let api_mech = match mechanism.to_api_mech(MechMode::Decrypt) {
            Some(mech) => mech,
            None => {
                error!(
                    "Tried to decrypt with an invalid mechanism: {:?}",
                    mechanism
                );
                return Err(CKR_MECHANISM_INVALID);
            }
        };

        if !key.mechanisms.contains(&api_mech) {
            error!(
                "Tried to decrypt with an invalid mechanism: {:?}",
                mechanism
            );
            return Err(CKR_MECHANISM_INVALID);
        }

        Ok(Self {
            mechanism,
            key_id: key.id.clone(),
            data: Vec::new(),
            login_ctx,
        })
    }
    pub fn update(&mut self, data: &[u8]) {
        self.data.extend_from_slice(data);
    }

    pub fn decrypt_final(&mut self) -> Result<Vec<u8>, cryptoki_sys::CK_RV> {
        let b64_message = general_purpose::STANDARD.encode(self.data.as_slice());

        let mode = self.mechanism.decrypt_name().ok_or(CKR_ARGUMENTS_BAD)?;
        trace!("Signing with mode: {:?}", mode);

        let iv = self
            .mechanism
            .iv()
            .map(|iv| general_purpose::STANDARD.encode(iv.as_slice()));

        let output = self
            .login_ctx
            .try_(
                |api_config| {
                    default_api::keys_key_id_decrypt_post(
                        api_config,
                        &self.key_id,
                        openapi::models::DecryptRequestData {
                            mode,
                            encrypted: b64_message,
                            iv,
                        },
                    )
                },
                login::UserMode::Operator,
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
