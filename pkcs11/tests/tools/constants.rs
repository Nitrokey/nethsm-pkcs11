use core::ptr;

use pkcs11::types::{
    CKA_MODULUS_BITS, CKA_PUBLIC_EXPONENT, CKA_SIGN, CKA_TOKEN, CKA_VERIFY, CKM_RSA_PKCS,
    CK_ATTRIBUTE, CK_BBOOL, CK_FALSE, CK_MECHANISM, CK_TRUE, CK_ULONG,
};

pub const RSA_PRIVATE_KEY_ATTRIBUTES: &[CK_ATTRIBUTE] = &[
    CK_ATTRIBUTE {
        attrType: CKA_SIGN,
        pValue: &CK_TRUE as *const _ as *mut _,
        ulValueLen: size_of::<CK_BBOOL>() as _,
    },
    CK_ATTRIBUTE {
        attrType: CKA_TOKEN,
        pValue: &CK_FALSE as *const _ as *mut _,
        ulValueLen: size_of::<CK_BBOOL>() as _,
    },
];

pub const RSA_PUBLIC_KEY_ATTRIBUTES: &[CK_ATTRIBUTE] = &[
    CK_ATTRIBUTE {
        attrType: CKA_VERIFY,
        pValue: &CK_TRUE as *const _ as *mut _,
        ulValueLen: size_of::<CK_BBOOL>() as _,
    },
    CK_ATTRIBUTE {
        attrType: CKA_MODULUS_BITS,
        pValue: &(2048 as CK_ULONG) as *const _ as *mut _,
        ulValueLen: size_of::<CK_ULONG>() as _,
    },
    CK_ATTRIBUTE {
        attrType: CKA_TOKEN,
        pValue: &CK_FALSE as *const _ as *mut _,
        ulValueLen: size_of::<CK_BBOOL>() as _,
    },
    CK_ATTRIBUTE {
        attrType: CKA_PUBLIC_EXPONENT,
        pValue: [0x01, 0x00, 0x01].as_ptr() as *mut _,
        ulValueLen: 3 as _,
    },
];

pub const RSA_MECHANISM: CK_MECHANISM = CK_MECHANISM {
    mechanism: CKM_RSA_PKCS,
    pParameter: ptr::null_mut(),
    ulParameterLen: 0,
};
