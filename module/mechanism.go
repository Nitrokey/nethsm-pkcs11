package module

import (
	"fmt"
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
	// case CKM_MD5_RSA_PKCS:
	case CKM_RSA_PKCS_PSS:
		if len(mechanism.Parameter) == 0 {
			err = NewError("Mechanism.SignMode", "PSS mechanism needs parameter", CKR_MECHANISM_PARAM_INVALID)
			return
		}
		params := (*CK_RSA_PKCS_PSS_PARAMS)(unsafe.Pointer(&mechanism.Parameter[0]))
		switch params.HashAlg {
		case CKM_MD5:
			mode = api.SIGNMODE_PSS_MD5
		case CKM_SHA_1:
			mode = api.SIGNMODE_PSS_SHA1
		case CKM_SHA224:
			mode = api.SIGNMODE_PSS_SHA224
		case CKM_SHA256:
			mode = api.SIGNMODE_PSS_SHA256
		case CKM_SHA384:
			mode = api.SIGNMODE_PSS_SHA384
		case CKM_SHA512:
			mode = api.SIGNMODE_PSS_SHA512
		default:
			err = NewError("Mechanism.SignMode", fmt.Sprintf("unsupported hash for PSS: %v", CKMString(params.HashAlg)), CKR_MECHANISM_PARAM_INVALID)
			return
		}
	case CKM_EDDSA:
		mode = api.SIGNMODE_ED25519
	case CKM_ECDSA:
		mode = api.SIGNMODE_ECDSA_P256
	default:
		err = NewError("Mechanism.SignMode", fmt.Sprintf("mechanism not supported for signing: %v", CKMString(mechanism.Type)), CKR_MECHANISM_INVALID)
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
			err = NewError("Mechanism.DecryptMode", "OAEP mechanism needs parameter", CKR_MECHANISM_PARAM_INVALID)
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
			err = NewError("Mechanism.DecryptMode", fmt.Sprintf("unsupported hash for OAEP: %v", CKMString(params.HashAlg)), CKR_MECHANISM_PARAM_INVALID)
			return
		}
	default:
		err = NewError("Mechanism.SignMode", fmt.Sprintf("mechanism not supported for decryption: %v", CKMString(mechanism.Type)), CKR_MECHANISM_INVALID)
		return
	}
	return
}
