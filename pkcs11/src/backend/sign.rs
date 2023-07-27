use super::{
    db::Object,
    login::{self, LoginCtx},
    mechanism::{MechMode, Mechanism},
    Error,
};
use base64::{engine::general_purpose, Engine as _};

use log::{debug, trace};
use openapi::{apis::default_api, models::SignMode};

#[derive(Clone, Debug)]
pub struct SignCtx {
    pub mechanism: Mechanism,
    pub sign_name: SignMode,
    pub key: Object,
    pub data: Vec<u8>,
    pub login_ctx: LoginCtx,
}

impl SignCtx {
    pub fn init(mechanism: Mechanism, key: Object, login_ctx: &LoginCtx) -> Result<Self, Error> {
        let login_ctx = login_ctx.clone();

        trace!("key_type: {:?}", key.kind);

        if !login_ctx.can_run_mode(login::UserMode::Operator) {
            return Err(Error::NotLoggedIn(login::UserMode::Operator));
        }

        let sign_name = mechanism.sign_name().ok_or_else(|| {
            debug!("Tried to sign with an invalid mechanism: {:?}", mechanism);
            Error::InvalidMechanismMode(MechMode::Sign, mechanism.clone())
        })?;

        let api_mech = match mechanism.to_api_mech(MechMode::Sign) {
            Some(mech) => mech,
            None => {
                debug!("Tried to sign with an invalid mechanism: {:?}", mechanism);
                return Err(Error::InvalidMechanismMode(MechMode::Sign, mechanism));
            }
        };

        trace!("Signing with mechanism: {:?}", mechanism);
        trace!("key mechanisms: {:?}", key.mechanisms);

        if !key.mechanisms.contains(&api_mech) {
            debug!(
                "Tried to sign with an invalid mechanism for this key: {:?}",
                mechanism
            );
            return Err(Error::InvalidMechanism((key.id, key.kind), mechanism));
        }

        Ok(Self {
            mechanism,
            key,
            sign_name,
            data: Vec::new(),
            login_ctx,
        })
    }
    pub fn update(&mut self, data: &[u8]) {
        self.data.extend_from_slice(data);
    }

    pub fn sign_final(&mut self) -> Result<Vec<u8>, Error> {
        let b64_message = general_purpose::STANDARD.encode(self.data.as_slice());

        let mode = self.sign_name;
        trace!("Signing with mode: {:?}", mode);

        let signature = self.login_ctx.try_(
            |conf| {
                default_api::keys_key_id_sign_post(
                    conf,
                    &self.key.id.clone(),
                    openapi::models::SignRequestData {
                        mode,
                        message: b64_message,
                    },
                )
            },
            login::UserMode::Operator,
        )?;

        Ok(general_purpose::STANDARD.decode(signature.signature)?)
    }

    pub fn get_theoretical_size(&self) -> usize {
        self.mechanism.get_theoretical_signed_size(self.key.size)
    }
}
