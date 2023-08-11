use base64::{engine::general_purpose, Engine};

use log::{debug, trace};
use openapi::apis::default_api;

use crate::backend::mechanism::MechMode;
use crate::backend::ApiError;
use crate::utils::get_tokio_rt;

use super::Error;

use super::{
    db::Object,
    login::{self, LoginCtx},
    mechanism::Mechanism,
};

// we only handle AES-CBC for now that has a block size of 16
pub const ENCRYPT_BLOCK_SIZE: usize = 16;

#[derive(Clone, Debug)]
pub struct EncryptCtx {
    pub mechanism: Mechanism,
    pub key_id: String,
    pub data: Vec<u8>,
    login_ctx: LoginCtx,
}

impl EncryptCtx {
    pub fn init(mechanism: Mechanism, key: &Object, login_ctx: LoginCtx) -> Result<Self, Error> {
        if !login_ctx.can_run_mode(crate::backend::login::UserMode::Operator) {
            return Err(Error::NotLoggedIn(login::UserMode::Operator));
        }

        let api_mech = match mechanism.to_api_mech(MechMode::Encrypt) {
            Some(mech) => mech,
            None => {
                debug!(
                    "Tried to encrypt with an invalid mechanism: {:?}",
                    mechanism
                );
                return Err(Error::InvalidMechanismMode(MechMode::Encrypt, mechanism));
            }
        };

        if !key.mechanisms.contains(&api_mech) {
            debug!(
                "Tried to encrypt with an invalid mechanism: {:?}",
                mechanism
            );
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

    pub fn add_data(&mut self, data: &[u8]) {
        self.data.extend_from_slice(data);
    }

    pub fn get_biggest_chunk_len(&self) -> usize {
        let full_blocks = self.data.len() / ENCRYPT_BLOCK_SIZE;

        full_blocks * ENCRYPT_BLOCK_SIZE
    }

    pub fn encrypt_available_data(&mut self) -> Result<Vec<u8>, Error> {
        let chunk_size = self.get_biggest_chunk_len();

        // if there is no data to encrypt, return an empty vector
        if chunk_size == 0 {
            return Ok(Vec::new());
        }

        // drain the data to encrypt from the data vector

        let input_data = self.data.drain(..chunk_size).collect::<Vec<u8>>();
        encrypt_data(
            &self.key_id,
            self.login_ctx.clone(),
            &input_data,
            &self.mechanism,
        )
    }

    pub fn encrypt_final(&self) -> Result<Vec<u8>, Error> {
        encrypt_data(
            &self.key_id,
            self.login_ctx.clone(),
            self.data.as_slice(),
            &self.mechanism,
        )
    }
}

fn encrypt_data(
    key_id: &str,
    mut login_ctx: LoginCtx,
    data: &[u8],
    mechanism: &Mechanism,
) -> Result<Vec<u8>, Error> {
    let b64_message = general_purpose::STANDARD.encode(data);

    let mode = mechanism.encrypt_name().ok_or(Error::InvalidMechanismMode(
        MechMode::Encrypt,
        mechanism.clone(),
    ))?;
    trace!("Signing with mode: {:?}", mode);

    let iv = mechanism
        .iv()
        .map(|iv| general_purpose::STANDARD.encode(iv.as_slice()));
    trace!("iv: {:?}", iv);

    let output = get_tokio_rt()
        .block_on(async {
            login_ctx
                .try_(
                    |api_config| async move {
                        default_api::keys_key_id_encrypt_post(
                            &api_config,
                            key_id,
                            openapi::models::EncryptRequestData {
                                mode,
                                message: b64_message,
                                iv,
                            },
                        )
                        .await
                    },
                    login::UserMode::Operator,
                )
                .await
        })
        .map_err(|err| {
            if let Error::Api(ApiError::ResponseError(ref resp)) = err {
                if resp.status == reqwest::StatusCode::BAD_REQUEST {
                    if resp.content.contains("argument length") {
                        return Error::InvalidDataLength;
                    }
                    return Error::InvalidData;
                }
            }
            err
        })?;

    Ok(general_purpose::STANDARD.decode(output.entity.encrypted)?)
}
