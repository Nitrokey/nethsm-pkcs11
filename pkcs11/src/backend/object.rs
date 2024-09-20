use cryptoki_sys::{CKA_CLASS, CKA_ID, CKA_LABEL, CKA_SUBJECT, CK_OBJECT_CLASS, CK_SESSION_HANDLE};
use log::{debug, trace};

use super::{
    db::{
        attr::{CkRawAttr, CkRawAttrTemplate},
        object::ObjectKind,
    },
    session::Session,
    Error,
};

// context to find objects
#[derive(Clone, Debug)]
pub struct EnumCtx {
    pub handles: Vec<CK_SESSION_HANDLE>,
    index: usize,
}

#[derive(Clone, Debug)]
pub struct KeyRequirements {
    pub kind: Option<ObjectKind>,
    pub id: Option<String>,
    pub raw_id: Option<Vec<u8>>,
    pub cka_subject: Option<Vec<u8>>,
}

fn parse_key_requirements(template: Option<CkRawAttrTemplate>) -> Result<KeyRequirements, Error> {
    match template {
        Some(template) => {
            let mut key_id = None;
            let mut kind = None;
            let mut raw_id = None;
            let mut cka_subject = None;
            for attr in template.iter() {
                debug!("attr {:?}: {:?}", attr.type_(), attr.val_bytes());

                if attr.type_() == CKA_CLASS {
                    kind = unsafe { attr.read_value::<CK_OBJECT_CLASS>() }.map(ObjectKind::from)
                }

                if attr.type_() == CKA_ID {
                    if let Some(bytes) = attr.val_bytes() {
                        let str_result = String::from_utf8(bytes.to_vec());
                        let mut output = None;
                        if let Ok(str) = str_result {
                            // check if the string contains only alphanumeric characters
                            if str.chars().all(|c| c.is_alphanumeric()) {
                                output = Some(str);
                            }
                        }

                        if output.is_none() {
                            // store as hex value string
                            output = Some(hex::encode(bytes));
                            raw_id = Some(bytes.to_vec());
                        }
                        key_id = output;
                    }
                }
                if attr.type_() == CKA_LABEL && key_id.is_none() {
                    key_id = Some(parse_str_from_attr(&attr)?);
                }

                if attr.type_() == CKA_SUBJECT {
                    let bytes = attr
                        .val_bytes()
                        .ok_or(Error::InvalidAttribute(attr.type_()))?;
                    cka_subject = Some(bytes.to_vec());
                }
            }
            Ok(KeyRequirements {
                kind,
                id: key_id,
                raw_id,
                cka_subject,
            })
        }
        None => Ok(KeyRequirements {
            kind: None,
            id: None,
            raw_id: None,
            cka_subject: None,
        }),
    }
}

fn parse_str_from_attr(attr: &CkRawAttr) -> Result<String, Error> {
    let bytes = attr
        .val_bytes()
        .ok_or(Error::InvalidAttribute(attr.type_()))?;
    Ok(String::from_utf8(bytes.to_vec())?)
}

impl EnumCtx {
    pub fn enum_init(
        session: &mut Session,
        template: Option<CkRawAttrTemplate>,
    ) -> Result<Self, Error> {
        let key_req = parse_key_requirements(template)?;

        let handles = session.find_key(key_req)?;
        Ok(EnumCtx::new(handles))
    }

    pub fn new(handles: Vec<CK_SESSION_HANDLE>) -> Self {
        Self { handles, index: 0 }
    }
    pub fn next_chunck(&mut self, chunk_size: usize) -> Vec<CK_SESSION_HANDLE> {
        let mut result = Vec::new();
        for _ in 0..chunk_size {
            trace!("index: {}", self.index);

            if let Some(handle) = self.handles.get(self.index) {
                result.push(*handle);
                self.index += 1;
            } else {
                break;
            }
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use cryptoki_sys::_CK_ATTRIBUTE;

    use super::*;

    #[test]
    fn test_parse_key_requirements_none_template() -> Result<(), Error> {
        let template = None;
        let res = parse_key_requirements(template)?;

        assert_eq!(res.kind, None);
        assert_eq!(res.id, None);
        assert_eq!(res.raw_id, None);

        Ok(())
    }

    #[test]
    fn test_parse_key_requirements_non_utf8_id() -> Result<(), Error> {
        let mut bytes: Vec<u8> = vec![0x00, 0xFF, 0x00, 0xFF];

        let mut attributes = vec![_CK_ATTRIBUTE {
            type_: CKA_ID,
            pValue: bytes.as_mut_ptr() as *mut _,
            ulValueLen: 4,
        }];

        let template = Some(
            unsafe { CkRawAttrTemplate::from_raw_ptr(attributes.as_mut_ptr(), 1) }
                .ok_or(Error::InvalidAttribute(CKA_ID))?,
        );

        let res = parse_key_requirements(template)?;

        assert_eq!(res.kind, None);
        assert_eq!(res.id, Some("00ff00ff".to_string()));
        assert_eq!(res.raw_id, Some(vec![0x00, 0xFF, 0x00, 0xFF]));

        Ok(())
    }

    #[test]
    fn test_parse_key_requirements_id_from_label() -> Result<(), Error> {
        let mut bytes = "test".to_string().into_bytes();

        let mut attributes = vec![_CK_ATTRIBUTE {
            type_: CKA_LABEL,
            pValue: bytes.as_mut_ptr() as *mut _,
            ulValueLen: 4,
        }];

        let template = Some(
            unsafe { CkRawAttrTemplate::from_raw_ptr(attributes.as_mut_ptr(), 1) }
                .ok_or(Error::InvalidAttribute(CKA_ID))?,
        );

        let res = parse_key_requirements(template)?;

        assert_eq!(res.kind, None);
        assert_eq!(res.id, Some("test".to_string()));
        assert_eq!(res.raw_id, None);

        Ok(())
    }
}
