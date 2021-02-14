package core

/*
#include <stdlib.h>
#include <string.h>
#include "pkcs11go.h"
*/
import "C"
import (
	"crypto"
	"io"
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
	if cMechanism.ulParameterLen >= C.CK_ULONG(len(mechanism.Parameter)) {
		cMechanism.mechanism = mechanism.Type
		cMechanism.ulParameterLen = C.CK_ULONG(len(mechanism.Parameter))
		cParameter := C.CBytes(mechanism.Parameter)
		defer C.free(unsafe.Pointer(cParameter))
		C.memcpy(unsafe.Pointer(cMechanism.pParameter), cParameter, cMechanism.ulParameterLen)
	} else {
		return NewError("Mechanism.ToC", "Buffer too small", C.CKR_BUFFER_TOO_SMALL)
	}
	return nil
}

// GetHashType returns the crypto.Hash object related to the mechanism type of the receiver.
func (mechanism *Mechanism) GetHashType() (h crypto.Hash, err error) {
	switch mechanism.Type {
	case C.CKM_RSA_PKCS, C.CKM_ECDSA:
		return crypto.Hash(0), nil
	case C.CKM_MD5_RSA_PKCS, C.CKM_MD5:
		h = crypto.MD5
	case C.CKM_SHA1_RSA_PKCS_PSS, C.CKM_SHA1_RSA_PKCS, C.CKM_SHA_1, C.CKM_ECDSA_SHA1:
		h = crypto.SHA1
	case C.CKM_SHA256_RSA_PKCS_PSS, C.CKM_SHA256_RSA_PKCS, C.CKM_SHA256, C.CKM_ECDSA_SHA256:
		h = crypto.SHA256
	case C.CKM_SHA384_RSA_PKCS_PSS, C.CKM_SHA384_RSA_PKCS, C.CKM_SHA384, C.CKM_ECDSA_SHA384:
		h = crypto.SHA384
	case C.CKM_SHA512_RSA_PKCS_PSS, C.CKM_SHA512_RSA_PKCS, C.CKM_SHA512, C.CKM_ECDSA_SHA512:
		h = crypto.SHA512
	default:
		err = NewError("Mechanism.Sign", "mechanism not supported yet for hashing", C.CKR_MECHANISM_INVALID)
		return
	}
	return
}

// Prepare hashes the data to sign using the mechanism method. It also receives a random source, that is used in PSS padding mechanism.
func (mechanism *Mechanism) Prepare(randSrc io.Reader, nBits int, data []byte) (prepared []byte, err error) {
	hashType, err := mechanism.GetHashType()
	var hash []byte
	if err != nil {
		return
	}
	switch mechanism.Type {
	case C.CKM_RSA_PKCS, C.CKM_MD5_RSA_PKCS, C.CKM_SHA1_RSA_PKCS, C.CKM_SHA256_RSA_PKCS, C.CKM_SHA384_RSA_PKCS, C.CKM_SHA512_RSA_PKCS:
		if hashType == crypto.Hash(0) {
			hash = data
		} else {
			hashFunc := hashType.New()
			_, err = hashFunc.Write(data)
			if err != nil {
				return
			}
			hash = hashFunc.Sum(nil)
		}
		prepared, err = padPKCS1v15(hashType, nBits, hash)
		return
	case C.CKM_SHA1_RSA_PKCS_PSS, C.CKM_SHA256_RSA_PKCS_PSS, C.CKM_SHA384_RSA_PKCS_PSS, C.CKM_SHA512_RSA_PKCS_PSS:
		if hashType == crypto.Hash(0) {
			err = NewError("Mechanism.Sign", "mechanism hash type is not supported with PSS padding", C.CKR_MECHANISM_INVALID)
		}
		hashFunc := hashType.New()
		_, err = hashFunc.Write(data)
		if err != nil {
			return
		}
		hash = hashFunc.Sum(nil)
		prepared, err = padPSS(randSrc, hashType, nBits, hash)
		return
	case C.CKM_ECDSA, C.CKM_ECDSA_SHA1, C.CKM_ECDSA_SHA256, C.CKM_ECDSA_SHA384, C.CKM_ECDSA_SHA512:
		if hashType == crypto.Hash(0) {
			prepared = data
			return
		}
		hashFunc := hashType.New()
		_, err = hashFunc.Write(data)
		if err != nil {
			return
		}
		prepared = hashFunc.Sum(nil)
		return
	default:
		err = NewError("Mechanism.Sign", "mechanism not supported yet for preparing", C.CKR_MECHANISM_INVALID)
		return
	}
}

func (mechanism *Mechanism) SignMode() (mode api.SignMode, err error) {
	switch mechanism.Type {
	case C.CKM_RSA_PKCS:
		mode = api.SIGNMODE_PKCS1
	case C.CKM_MD5_RSA_PKCS:
		// XXX this is wrong I think
		mode = api.SIGNMODE_PSS_MD5
	case C.CKM_SHA1_RSA_PKCS_PSS:
		mode = api.SIGNMODE_PSS_SHA1
	case C.CKM_SHA224_RSA_PKCS_PSS:
		mode = api.SIGNMODE_PSS_SHA224
	case C.CKM_SHA256_RSA_PKCS_PSS:
		mode = api.SIGNMODE_PSS_SHA256
	case C.CKM_SHA384_RSA_PKCS_PSS:
		mode = api.SIGNMODE_PSS_SHA384
	case C.CKM_SHA512_RSA_PKCS_PSS:
		mode = api.SIGNMODE_PSS_SHA512
	// case C.CKM_EDDSA:
	// 	mode = api.SIGNMODE_ED25519
	default:
		err = NewError("Mechanism.SignMode", "mechanism not supported for signing", C.CKR_MECHANISM_INVALID)
		return
	}
	return
}

func (mechanism *Mechanism) DecryptMode() (mode api.DecryptMode, err error) {
	switch mechanism.Type {
	case C.CKM_RSA_X_509:
		mode = api.DECRYPTMODE_RAW
	case C.CKM_RSA_PKCS:
		mode = api.DECRYPTMODE_PKCS1
	case C.CKM_RSA_PKCS_OAEP:
		if len(mechanism.Parameter) == 0 {
			err = NewError("Mechanism.DecryptMode", "OAEP mechanism needs parameter", C.CKR_MECHANISM_INVALID)
			return
		}
		params := (*C.CK_RSA_PKCS_OAEP_PARAMS)(unsafe.Pointer(&mechanism.Parameter[0]))
		switch params.hashAlg {
		case C.CKM_MD5:
			mode = api.DECRYPTMODE_OAEP_MD5
		case C.CKM_SHA_1:
			mode = api.DECRYPTMODE_OAEP_SHA1
		case C.CKM_SHA224:
			mode = api.DECRYPTMODE_OAEP_SHA224
		case C.CKM_SHA256:
			mode = api.DECRYPTMODE_OAEP_SHA256
		case C.CKM_SHA384:
			mode = api.DECRYPTMODE_OAEP_SHA384
		case C.CKM_SHA512:
			mode = api.DECRYPTMODE_OAEP_SHA512
		default:
			err = NewError("Mechanism.DecryptMode", "unsupported hash for OAEP mechanism", C.CKR_MECHANISM_INVALID)
			return
		}
	default:
		err = NewError("Mechanism.SignMode", "mechanism not supported for signing", C.CKR_MECHANISM_INVALID)
		return
	}
	return
}
