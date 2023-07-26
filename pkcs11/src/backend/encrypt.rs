use base64::{engine::general_purpose, Engine};
use cryptoki_sys::{
    CKR_ARGUMENTS_BAD, CKR_DATA_INVALID, CKR_DATA_LEN_RANGE, CKR_DEVICE_ERROR,
    CKR_MECHANISM_INVALID, CKR_USER_NOT_LOGGED_IN, CK_RV,
};
use log::{debug, error, trace};
use openapi::apis::default_api;

use crate::backend::login::LoginCtxError;

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
    pub fn init(mechanism: Mechanism, key: &Object, login_ctx: &LoginCtx) -> Result<Self, CK_RV> {
        let login_ctx = login_ctx.clone();

        if !login_ctx.can_run_mode(login::UserMode::Operator) {
            debug!("No operator is logged in");
            return Err(CKR_USER_NOT_LOGGED_IN);
        }

        let api_mech = match mechanism.to_api_mech(super::mechanism::MechMode::Encrypt) {
            Some(mech) => mech,
            None => {
                debug!(
                    "Tried to encrypt with an invalid mechanism: {:?}",
                    mechanism
                );
                return Err(CKR_MECHANISM_INVALID);
            }
        };

        if !key.mechanisms.contains(&api_mech) {
            debug!(
                "Tried to encrypt with an invalid mechanism: {:?}",
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

    pub fn add_data(&mut self, data: &[u8]) {
        self.data.extend_from_slice(data);
    }

    pub fn get_biggest_chunk_len(&self) -> usize {
        let full_blocks = self.data.len() / ENCRYPT_BLOCK_SIZE;

        full_blocks * ENCRYPT_BLOCK_SIZE
    }

    pub fn encrypt_available_data(&mut self) -> Result<Vec<u8>, cryptoki_sys::CK_RV> {
        let chunk_size = self.get_biggest_chunk_len();

        // if there is no data to encrypt, return an empty vector
        if chunk_size == 0 {
            return Ok(Vec::new());
        }

        // drain the data to encrypt from the data vector

        let input_data = self.data.drain(..chunk_size).collect::<Vec<u8>>();
        encrypt_data(
            &self.key_id,
            &mut self.login_ctx,
            &input_data,
            &self.mechanism,
        )
    }

    pub fn encrypt_final(&mut self) -> Result<Vec<u8>, cryptoki_sys::CK_RV> {
        encrypt_data(
            &self.key_id,
            &mut self.login_ctx,
            self.data.as_slice(),
            &self.mechanism,
        )
    }
}

fn encrypt_data(
    key_id: &str,
    login_ctx: &mut LoginCtx,
    data: &[u8],
    mechanism: &Mechanism,
) -> Result<Vec<u8>, CK_RV> {
    let b64_message = general_purpose::STANDARD.encode(data);

    let mode = mechanism.encrypt_name().ok_or(CKR_ARGUMENTS_BAD)?;
    trace!("Signing with mode: {:?}", mode);

    let iv = mechanism
        .iv()
        .map(|iv| general_purpose::STANDARD.encode(iv.as_slice()));
    trace!("iv: {:?}", iv);

    let output = login_ctx
        .try_(
            |api_config| {
                default_api::keys_key_id_encrypt_post(
                    api_config,
                    key_id,
                    openapi::models::EncryptRequestData {
                        mode,
                        message: b64_message,
                        iv,
                    },
                )
            },
            login::UserMode::Operator,
        )
        .map_err(|err| {
            if let LoginCtxError::Api(openapi::apis::Error::ResponseError(ref resp)) = err {
                if resp.status == reqwest::StatusCode::BAD_REQUEST {
                    if resp.content.contains("argument length") {
                        return CKR_DATA_LEN_RANGE;
                    }
                    return CKR_DATA_INVALID;
                }
            }
            error!("Failed to decrypt: {:?}", err);
            CKR_DEVICE_ERROR
        })?;

    general_purpose::STANDARD
        .decode(output.encrypted)
        .map_err(|err: base64::DecodeError| {
            error!("Failed to decode signature: {:?}", err);
            CKR_DEVICE_ERROR
        })
}
