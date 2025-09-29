use cryptoki_sys::{CKA_CLASS, CKA_ID, CKA_LABEL, CK_OBJECT_CLASS, CK_SESSION_HANDLE};
use log::{debug, trace, warn};

use super::{
    db::{
        attr::{CkRawAttr, CkRawAttrTemplate},
        object::ObjectKind,
    },
    key::Id,
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
    pub invalid_id: bool,
}

fn parse_key_requirements(template: Option<CkRawAttrTemplate>) -> Result<KeyRequirements, Error> {
    match template {
        Some(template) => {
            let mut key_id = None;
            let mut kind = None;
            let mut invalid_id = false;
            for attr in template.iter() {
                debug!("attr {:?}: {:?}", attr.type_(), attr.val_bytes());

                if attr.type_() == CKA_CLASS {
                    kind = unsafe { attr.read_value::<CK_OBJECT_CLASS>() }.map(ObjectKind::from)
                }

                if attr.type_() == CKA_ID {
                    if let Some(bytes) = attr.val_bytes() {
                        if let Ok(id) = Id::try_from(bytes.to_owned()) {
                            key_id = Some(id.into());
                        } else {
                            warn!("Invalid ID in key requirements");
                            invalid_id = true;
                        }
                    }
                }
                if attr.type_() == CKA_LABEL && key_id.is_none() {
                    key_id = Some(parse_str_from_attr(&attr)?);
                }
            }
            Ok(KeyRequirements {
                kind,
                id: key_id,
                invalid_id,
            })
        }
        None => Ok(KeyRequirements {
            kind: None,
            id: None,
            invalid_id: false,
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

        // Elements with a non-compliant ID are no longer supported
        let handles = if key_req.invalid_id {
            vec![]
        } else {
            session.find_key(key_req.id.as_deref(), key_req.kind)?
        };
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
    use cryptoki_sys::CK_ATTRIBUTE;

    use super::*;

    #[test]
    fn test_parse_key_requirements_none_template() -> Result<(), Error> {
        let template = None;
        let res = parse_key_requirements(template)?;

        assert_eq!(res.kind, None);
        assert_eq!(res.id, None);
        assert!(!res.invalid_id);

        Ok(())
    }

    #[test]
    fn test_parse_key_requirements_non_utf8_id() -> Result<(), Error> {
        let mut bytes: Vec<u8> = vec![0x00, 0xFF, 0x00, 0xFF];

        let mut attributes = vec![CK_ATTRIBUTE {
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
        assert_eq!(res.id, None);
        assert!(res.invalid_id);

        Ok(())
    }

    #[test]
    fn test_parse_key_requirements_id_from_label() -> Result<(), Error> {
        let mut bytes = "test".to_string().into_bytes();

        let mut attributes = vec![CK_ATTRIBUTE {
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
        assert!(!res.invalid_id);

        Ok(())
    }
}
