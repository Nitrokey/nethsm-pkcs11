use crate::backend::mechanism::MechDigest;

use super::{
    db::Object,
    login::{self, LoginCtx},
    mechanism::{MechMode, Mechanism},
    Error,
};
use base64ct::{Base64, Encoding};
use der::Decode;
use log::{debug, trace};
use nethsm_sdk_rs::{apis::default_api, models::SignMode};
use sha2::Digest;

#[derive(Clone, Debug)]
pub struct SignCtx {
    pub mechanism: Mechanism,
    pub sign_name: SignMode,
    pub key: Object,
    pub data: Vec<u8>,
}

impl SignCtx {
    pub fn init(mechanism: Mechanism, key: Object, login_ctx: &LoginCtx) -> Result<Self, Error> {
        trace!("key_type: {:?}", key.kind);

        if !login_ctx.can_run_mode(crate::backend::login::UserMode::Operator) {
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
        })
    }
    pub fn update(&mut self, data: &[u8]) {
        self.data.extend_from_slice(data);
    }

    pub fn sign_final(&self, login_ctx: &LoginCtx) -> Result<Vec<u8>, Error> {
        // helper function to hash the data with the correct algorithm
        fn hasher<D: Digest>(data: &[u8]) -> Vec<u8> {
            let mut hasher = D::new();
            hasher.update(data);
            hasher.finalize().to_vec()
        }

        let mut data = if let Some(digest) = self.mechanism.internal_digest() {
            let hasher_fn = match digest {
                MechDigest::Sha1 => hasher::<sha1::Sha1>,
                MechDigest::Sha224 => hasher::<sha2::Sha224>,
                MechDigest::Sha256 => hasher::<sha2::Sha256>,
                MechDigest::Sha384 => hasher::<sha2::Sha384>,
                MechDigest::Sha512 => hasher::<sha2::Sha512>,
                // should never happen
                _ => hasher::<sha1::Sha1>,
            };
            hasher_fn(&self.data)
        } else {
            self.data.clone()
        };

        // with ecdsa we need to send the correct size, so we truncate/pad the data to the correct size
        if matches!(self.mechanism, Mechanism::Ecdsa(_)) {
            let size = self.mechanism.get_input_size(self.key.size);
            let mut out = vec![0; size];
            let len = data.len().min(size);
            out[(size - len)..size].copy_from_slice(&data[..len]);
            data = out;
        }

        let b64_message = Base64::encode_string(data.as_slice());

        let mode = self.sign_name;
        trace!("Signing with mode: {:?}", mode);

        let signature = login_ctx.try_(
            |conf| {
                default_api::keys_key_id_sign_post(
                    conf,
                    &self.key.id.clone(),
                    nethsm_sdk_rs::models::SignRequestData {
                        mode,
                        message: b64_message,
                    },
                )
            },
            login::UserMode::Operator,
        )?;

        let mut output = Base64::decode_vec(&signature.entity.signature)?;

        // ECDSA signatures returned by the API are DER encoded, we need to remove the DER encoding
        if matches!(self.mechanism, Mechanism::Ecdsa(_)) {
            let size = self.mechanism.get_key_size(self.key.size);

            let sig: der::asn1::SequenceOf<der::asn1::Uint, 2> =
                der::asn1::SequenceOf::from_der(&output).map_err(Error::Der)?;

            let r = sig.get(0).ok_or(Error::InvalidData)?.as_bytes();
            let s = sig.get(1).ok_or(Error::InvalidData)?.as_bytes();

            let mut o = Vec::new();

            if r.len() > size || s.len() > size {
                return Err(Error::InvalidData);
            }

            // copy with padding

            o.extend_from_slice(&vec![0; size - r.len()]);
            o.extend_from_slice(r);

            o.extend_from_slice(&vec![0; size - s.len()]);
            o.extend_from_slice(s);

            output = o;
        }

        Ok(output)
    }

    pub fn get_theoretical_size(&self) -> usize {
        self.mechanism.get_signature_size(self.key.size)
    }
}
