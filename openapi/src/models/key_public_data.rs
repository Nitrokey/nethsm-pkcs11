/*
 * NetHSM
 *
 * All endpoints expect exactly the specified JSON. Additional properties will cause a Bad Request Error (400). All HTTP errors contain a JSON structure with an explanation of type string. All [base64](https://tools.ietf.org/html/rfc4648#section-4) encoded values are Big Endian.
 *
 * The version of the OpenAPI document: v1
 *
 * Generated by: https://openapi-generator.tech
 */

/// KeyPublicData : The public key data is either a *modulus* and a *publicExponent* or a *data* field. The *data* field is used for EC keys. This field is null for Generic keys.

#[derive(Clone, Debug, PartialEq, Default, Serialize, Deserialize)]
pub struct KeyPublicData {
    #[serde(rename = "modulus", skip_serializing_if = "Option::is_none")]
    pub modulus: Option<String>,
    #[serde(rename = "publicExponent", skip_serializing_if = "Option::is_none")]
    pub public_exponent: Option<String>,
    #[serde(rename = "data", skip_serializing_if = "Option::is_none")]
    pub data: Option<String>,
}

impl KeyPublicData {
    /// The public key data is either a *modulus* and a *publicExponent* or a *data* field. The *data* field is used for EC keys. This field is null for Generic keys.
    pub fn new() -> KeyPublicData {
        KeyPublicData {
            modulus: None,
            public_exponent: None,
            data: None,
        }
    }
}
