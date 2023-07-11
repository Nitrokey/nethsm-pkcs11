use base64::{engine::general_purpose, Engine};
use cryptoki_sys::{
    CKR_ARGUMENTS_BAD, CKR_DATA_INVALID, CKR_DATA_LEN_RANGE, CKR_DEVICE_ERROR, CK_RV,
};
use log::{error, trace};
use openapi::apis::{configuration, default_api};

use super::mechanism::Mechanism;

// we only handle AES-CBC for now that has a block size of 16
pub const ENCRYPT_BLOCK_SIZE: usize = 16;

#[derive(Clone, Debug)]
pub struct EncryptCtx {
    pub mechanism: Mechanism,
    pub key_id: String,
    pub data: Vec<u8>,
    api_config: openapi::apis::configuration::Configuration,
}

impl EncryptCtx {
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
        encrypt_data(&self.key_id, &self.api_config, &input_data, &self.mechanism)
    }

    pub fn encrypt_final(&self) -> Result<Vec<u8>, cryptoki_sys::CK_RV> {
        encrypt_data(
            &self.key_id,
            &self.api_config,
            self.data.as_slice(),
            &self.mechanism,
        )
    }
}

fn encrypt_data(
    key_id: &str,
    api_config: &configuration::Configuration,
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

    let output = default_api::keys_key_id_encrypt_post(
        api_config,
        key_id,
        openapi::models::EncryptRequestData {
            mode,
            message: b64_message,
            iv,
        },
    )
    .map_err(|err| {
        if let openapi::apis::Error::ResponseError(ref resp) = err {
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
