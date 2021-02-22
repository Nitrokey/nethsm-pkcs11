package core

/*
#include <stdlib.h>
#include <string.h>
#include "pkcs11go.h"
*/
import "C"
import (
	"p11nethsm/api"
	"unsafe"
)

// Mechanism represents a cryptographic operation that the HSM supports.
type Mechanism struct {
	Type      C.CK_MECHANISM_TYPE // Mechanism Type
	Parameter []byte              // Parameters for the mechanism
}

// CToMechanism transforms a C mechanism into a Mechanism Golang structure.
func CToMechanism(pMechanism C.CK_MECHANISM_PTR) *Mechanism {
	cMechanism := (*C.CK_MECHANISM)(unsafe.Pointer(pMechanism))
	mechanismType := cMechanism.mechanism
	mechanismVal := C.GoBytes(unsafe.Pointer(cMechanism.pParameter), C.int(cMechanism.ulParameterLen))
	return &Mechanism{
		Type:      mechanismType,
		Parameter: mechanismVal,
	}

}

// ToC transforms a Mechanism Golang Structure into a C structure.
func (mechanism *Mechanism) ToC(cDst C.CK_MECHANISM_PTR) error {
	cMechanism := (*C.CK_MECHANISM)(unsafe.Pointer(cDst))
	paramLen := C.CK_ULONG(len(mechanism.Parameter))
	if cMechanism.ulParameterLen >= paramLen {
		cMechanism.mechanism = mechanism.Type
		cMechanism.ulParameterLen = paramLen
		C.memcpy(unsafe.Pointer(cMechanism.pParameter), unsafe.Pointer(&mechanism.Parameter[0]), paramLen)
	} else {
		return NewError("Mechanism.ToC", "Buffer too small", CKR_BUFFER_TOO_SMALL)
	}
	return nil
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
		params := (*C.CK_RSA_PKCS_OAEP_PARAMS)(unsafe.Pointer(&mechanism.Parameter[0]))
		switch params.hashAlg {
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
