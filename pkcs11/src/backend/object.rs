use cryptoki_sys::CK_OBJECT_CLASS;
use log::{debug, trace};

use super::{
    db::{
        attr::{CkRawAttr, CkRawAttrTemplate},
        object::ObjectKind,
    },
    key::{NetHSMId, Pkcs11Id},
    session::Session,
    Error,
};
use crate::ck::{CkAttributeType, CkObjectClass, CkObjectHandle};

// context to find objects
#[derive(Clone, Debug)]
pub struct EnumCtx {
    pub handles: Vec<CkObjectHandle>,
    index: usize,
}

#[derive(Clone, Debug)]
pub struct KeyRequirements {
    pub class: Option<CkObjectClass>,
    pub id: Option<NetHSMId>,
    pub label: Option<String>,
}

fn parse_key_requirements(template: Option<CkRawAttrTemplate>) -> Result<KeyRequirements, Error> {
    match template {
        Some(template) => {
            let mut key_id = None;
            let mut class = None;
            let mut label = None;
            for attr in template.iter() {
                debug!("attr {:?}: {:?}", attr.type_(), attr.val_bytes());

                match attr.type_() {
                    CkAttributeType::Class => {
                        class =
                            unsafe { attr.read_value::<CK_OBJECT_CLASS>() }.map(CkObjectClass::from)
                    }
                    CkAttributeType::Id => {
                        key_id = Some(parse_nethsm_id(&attr)?);
                    }
                    CkAttributeType::Label => {
                        if let Some(bytes) = attr.val_bytes() {
                            let s = str::from_utf8(bytes)
                                .map_err(|_| Error::InvalidAttribute(attr.type_()))?;
                            label = Some(s.to_owned());
                        } else {
                            label = Some(String::new());
                        }
                    }
                    _ => {}
                }
            }
            Ok(KeyRequirements {
                class,
                id: key_id,
                label,
            })
        }
        None => Ok(KeyRequirements {
            class: None,
            id: None,
            label: None,
        }),
    }
}

fn parse_nethsm_id(attr: &CkRawAttr) -> Result<NetHSMId, Error> {
    let bytes = attr
        .val_bytes()
        .ok_or(Error::InvalidAttribute(attr.type_()))?;
    let pkcs11_id = Pkcs11Id::from(bytes);
    NetHSMId::try_from(&pkcs11_id).map_err(|_| Error::InvalidAttribute(attr.type_()))
}

impl EnumCtx {
    pub fn enum_init(
        session: &mut Session,
        template: Option<CkRawAttrTemplate>,
    ) -> Result<Self, Error> {
        let key_req = parse_key_requirements(template)?;
        let kind = key_req.class.map(ObjectKind::try_from).transpose();
        let handles = if let Ok(kind) = kind {
            session.find_key(key_req.id.as_ref(), kind, key_req.label.as_deref())?
        } else {
            // searching for an unsupported object class can never return results
            Vec::new()
        };
        Ok(EnumCtx::new(handles))
    }

    pub fn new(handles: Vec<CkObjectHandle>) -> Self {
        Self { handles, index: 0 }
    }
    pub fn next_chunck(&mut self, chunk_size: usize) -> Vec<CkObjectHandle> {
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
    use cryptoki_sys::{CKA_ID, CKA_LABEL, CK_ATTRIBUTE};

    use super::*;

    #[test]
    fn test_parse_key_requirements_none_template() -> Result<(), Error> {
        let template = None;
        let res = parse_key_requirements(template)?;

        assert_eq!(res.class, None);
        assert_eq!(res.id, None);
        assert_eq!(res.label, None);

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
                .ok_or(Error::InvalidAttribute(CkAttributeType::Id))?,
        );

        let res = parse_key_requirements(template)?;

        assert_eq!(res.class, None);
        assert_eq!(res.id.as_ref().map(|id| id.as_str()), Some("0---00FF00FF"));
        assert_eq!(res.label, None);

        Ok(())
    }

    #[test]
    fn test_parse_key_requirements_label() -> Result<(), Error> {
        let mut bytes = "test".to_string().into_bytes();

        let mut attributes = vec![CK_ATTRIBUTE {
            type_: CKA_LABEL,
            pValue: bytes.as_mut_ptr() as *mut _,
            ulValueLen: 4,
        }];

        let template = Some(
            unsafe { CkRawAttrTemplate::from_raw_ptr(attributes.as_mut_ptr(), 1) }
                .ok_or(Error::InvalidAttribute(CkAttributeType::Label))?,
        );

        let res = parse_key_requirements(template)?;

        assert_eq!(res.class, None);
        assert_eq!(res.id, None);
        assert_eq!(res.label.as_deref(), Some("test"));

        Ok(())
    }
}
