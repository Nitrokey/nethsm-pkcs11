use cryptoki_sys::{
    CKA_CLASS, CKA_ID, CKA_LABEL, CKR_ARGUMENTS_BAD, CK_OBJECT_CLASS, CK_RV, CK_SESSION_HANDLE,
};
use log::debug;

use super::{
    db::{
        attr::{CkRawAttr, CkRawAttrTemplate},
        object::ObjectKind,
    },
    session::Session,
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
}

fn find_key_id(template: Option<CkRawAttrTemplate>) -> Result<KeyRequirements, CK_RV> {
    match template {
        Some(template) => {
            let mut key_id = None;
            let mut kind = None;
            for attr in template.iter() {
                debug!("attr: {:?}", attr.type_());
                debug!("attr: {:?}", attr.val_bytes());

                if attr.type_() == CKA_CLASS {
                    kind = attr.read_value::<CK_OBJECT_CLASS>().map(ObjectKind::from)
                }

                if attr.type_() == CKA_ID {
                    key_id = Some(parse_str_from_attr(&attr)?);
                }
                if attr.type_() == CKA_LABEL && key_id.is_none() {
                    key_id = Some(parse_str_from_attr(&attr)?);
                }
            }
            Ok(KeyRequirements { kind, id: key_id })
        }
        None => Ok(KeyRequirements {
            kind: None,
            id: None,
        }),
    }
}

fn parse_str_from_attr(attr: &CkRawAttr) -> Result<String, CK_RV> {
    let bytes = attr.val_bytes().ok_or(CKR_ARGUMENTS_BAD)?;
    String::from_utf8(bytes.to_vec()).map_err(|_| CKR_ARGUMENTS_BAD)
}

impl EnumCtx {
    pub fn enum_init(
        session: &mut Session,
        template: Option<CkRawAttrTemplate>,
    ) -> Result<Self, CK_RV> {
        let key_id = find_key_id(template)?;

        let handles = session.find_key(key_id)?;
        Ok(EnumCtx::new(handles))
    }

    pub fn new(handles: Vec<CK_SESSION_HANDLE>) -> Self {
        Self { handles, index: 0 }
    }
    pub fn next_chunck(&mut self, chunk_size: usize) -> Vec<CK_SESSION_HANDLE> {
        let mut result = Vec::new();
        for _ in 0..chunk_size {
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
