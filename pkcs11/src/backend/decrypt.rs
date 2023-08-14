use base64::{engine::general_purpose, Engine};

use log::trace;
use nethsm_sdk_rs::apis::default_api;

use crate::utils::get_tokio_rt;

use super::{
    db::Object,
    login::{self, LoginCtx},
    mechanism::{MechMode, Mechanism},
    Error,
};

#[derive(Clone, Debug)]
pub struct DecryptCtx {
    pub mechanism: Mechanism,
    pub key_id: String,
    pub data: Vec<u8>,
    login_ctx: LoginCtx,
}

impl DecryptCtx {
    pub fn init(mechanism: Mechanism, key: &Object, login_ctx: LoginCtx) -> Result<Self, Error> {
        if !login_ctx.can_run_mode(crate::backend::login::UserMode::Operator) {
            return Err(Error::NotLoggedIn(login::UserMode::Operator));
        }

        let api_mech =
            mechanism
                .to_api_mech(MechMode::Decrypt)
                .ok_or(Error::InvalidMechanismMode(
                    MechMode::Decrypt,
                    mechanism.clone(),
                ))?;

        if !key.mechanisms.contains(&api_mech) {
            return Err(Error::InvalidMechanism(
                (key.id.clone(), key.kind),
                mechanism,
            ));
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

    pub fn decrypt_final(&mut self) -> Result<Vec<u8>, Error> {
        let b64_message = general_purpose::STANDARD.encode(self.data.as_slice());

        let mode = self
            .mechanism
            .decrypt_name()
            .ok_or(Error::InvalidMechanismMode(
                MechMode::Decrypt,
                self.mechanism.clone(),
            ))?;
        trace!("Decrypt with mode: {:?}", mode);

        let iv = self
            .mechanism
            .iv()
            .map(|iv| general_purpose::STANDARD.encode(iv.as_slice()));

        let key_id = self.key_id.as_str();

        let output = get_tokio_rt().block_on(async {
            self.login_ctx
                .try_(
                    |api_config| async move {
                        default_api::keys_key_id_decrypt_post(
                            &api_config,
                            key_id,
                            nethsm_sdk_rs::models::DecryptRequestData {
                                mode,
                                encrypted: b64_message,
                                iv,
                            },
                        )
                        .await
                    },
                    login::UserMode::Operator,
                )
                .await
        })?;

        Ok(general_purpose::STANDARD.decode(output.entity.decrypted)?)
    }
}
