use cryptoki_sys::{CKA_CLASS, CKA_ID, CKA_LABEL, CK_OBJECT_CLASS, CK_SESSION_HANDLE};
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
}

fn find_key_id(template: Option<CkRawAttrTemplate>) -> Result<KeyRequirements, Error> {
    match template {
        Some(template) => {
            let mut key_id = None;
            let mut kind = None;
            let mut raw_id = None;
            for attr in template.iter() {
                debug!("attr: {:?}", attr.type_());
                debug!("attr: {:?}", attr.val_bytes());

                if attr.type_() == CKA_CLASS {
                    kind = attr.read_value::<CK_OBJECT_CLASS>().map(ObjectKind::from)
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
            }
            Ok(KeyRequirements {
                kind,
                id: key_id,
                raw_id,
            })
        }
        None => Ok(KeyRequirements {
            kind: None,
            id: None,
            raw_id: None,
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
        let key_req = find_key_id(template)?;

        let handles = tokio::runtime::Builder::new_current_thread()
            .worker_threads(4)
            .enable_all()
            .build()
            .unwrap()
            .block_on(session.find_key(key_req))?;
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
