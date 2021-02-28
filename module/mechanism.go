package module

import (
	"p11nethsm/api"
	"unsafe"
)

// Mechanism represents a cryptographic operation that the HSM supports.
type Mechanism struct {
	Type      CK_MECHANISM_TYPE // Mechanism Type
	Parameter []byte            // Parameters for the mechanism
}

func (mechanism *Mechanism) SignMode() (mode api.SignMode, err error) {
	switch mechanism.Type {
	case CKM_RSA_PKCS:
		mode = api.SIGNMODE_PKCS1
	case CKM_MD5_RSA_PKCS:
		// XXX this is wrong I think
		mode = api.SIGNMODE_PSS_MD5
	case CKM_SHA1_RSA_PKCS_PSS:
		mode = api.SIGNMODE_PSS_SHA1
	case CKM_SHA224_RSA_PKCS_PSS:
		mode = api.SIGNMODE_PSS_SHA224
	case CKM_SHA256_RSA_PKCS_PSS:
		mode = api.SIGNMODE_PSS_SHA256
	case CKM_SHA384_RSA_PKCS_PSS:
		mode = api.SIGNMODE_PSS_SHA384
	case CKM_SHA512_RSA_PKCS_PSS:
		mode = api.SIGNMODE_PSS_SHA512
	// case CKM_EDDSA:
	// 	mode = api.SIGNMODE_ED25519
	default:
		err = NewError("Mechanism.SignMode", "mechanism not supported for signing", CKR_MECHANISM_INVALID)
		return
	}
	return
}

func (mechanism *Mechanism) DecryptMode() (mode api.DecryptMode, err error) {
	switch mechanism.Type {
	case CKM_RSA_X_509:
		mode = api.DECRYPTMODE_RAW
	case CKM_RSA_PKCS:
		mode = api.DECRYPTMODE_PKCS1
	case CKM_RSA_PKCS_OAEP:
		if len(mechanism.Parameter) == 0 {
			err = NewError("Mechanism.DecryptMode", "OAEP mechanism needs parameter", CKR_MECHANISM_INVALID)
			return
		}
		params := (*CK_RSA_PKCS_OAEP_PARAMS)(unsafe.Pointer(&mechanism.Parameter[0]))
		switch params.HashAlg {
		case CKM_MD5:
			mode = api.DECRYPTMODE_OAEP_MD5
		case CKM_SHA_1:
			mode = api.DECRYPTMODE_OAEP_SHA1
		case CKM_SHA224:
			mode = api.DECRYPTMODE_OAEP_SHA224
		case CKM_SHA256:
			mode = api.DECRYPTMODE_OAEP_SHA256
		case CKM_SHA384:
			mode = api.DECRYPTMODE_OAEP_SHA384
		case CKM_SHA512:
			mode = api.DECRYPTMODE_OAEP_SHA512
		default:
			err = NewError("Mechanism.DecryptMode", "unsupported hash for OAEP mechanism", CKR_MECHANISM_INVALID)
			return
		}
	default:
		err = NewError("Mechanism.SignMode", "mechanism not supported for signing", CKR_MECHANISM_INVALID)
		return
	}
	return
}
