package core

/*
#include "pkcs11go.h"
*/
import "C"

import (
	"encoding/base64"
	"p11nethsm/api"
)

type OpContextRSA struct {
	session     *Session
	mechanism   *Mechanism // Mechanism used to sign in a Sign session.
	keyID       string     // Key ID used in signing.
	data        []byte     // Data to sign.
	initialized bool       // // True if the user executed a Sign method and it has not finished yet.
}

type SignContextRSA struct {
	OpContextRSA
}

type DecryptContextRSA struct {
	OpContextRSA
}

//type VerifyContextRSA contextRSA

func (context *OpContextRSA) Initialized() bool {
	return context.initialized
}

func (context *OpContextRSA) Init() (err error) {
	context.initialized = true
	return
}

func (context *OpContextRSA) ResultLength() int {
	// log.Debugf("context: %v", context)
	return 0 // XXX
}

func (context *OpContextRSA) Update(data []byte) error {
	context.data = append(context.data, data...)
	return nil
}

func (context *SignContextRSA) Final() ([]byte, error) {
	var err error
	// _ /*prepared*/, err := context.mechanism.Prepare(
	// 	context.randSrc,
	// 	context.pubKey.Size(),
	// 	context.data,
	// )
	// if err != nil {
	// 	return nil, err
	// }
	// XXX signature, err := context.dtc.RSASignData(context.keyID,
	// context.keyMeta, prepared)

	var reqBody api.SignRequestData
	reqBody.SetMessage(base64.StdEncoding.EncodeToString(context.data))
	mode, err := context.mechanism.SignMode()
	if err != nil {
		return nil, err
	}
	reqBody.SetMode(mode)
	sigData, r, err := App.Api.KeysKeyIDSignPost(
		context.session.Slot.token.ApiCtx(), context.keyID).Body(reqBody).Execute()
	if err != nil {
		// log.Debugf("%v\n", r)
		// log.Debugf("%v\n", r.Request.Body)
		return nil, NewAPIError("SignContextRSA.Final()", "Signing failed.", r, err)
	}
	signature, err := base64.StdEncoding.DecodeString(sigData.GetSignature())
	if err != nil {
		return nil, err
	}
	return signature, nil
}

func (context *DecryptContextRSA) Final() ([]byte, error) {
	var err error
	// _ /*prepared*/, err := context.mechanism.Prepare(
	// 	context.randSrc,
	// 	context.pubKey.Size(),
	// 	context.data,
	// )
	// if err != nil {
	// 	return nil, err
	// }
	// XXX signature, err := context.dtc.RSASignData(context.keyID,
	// context.keyMeta, prepared)

	var reqBody api.DecryptRequestData
	reqBody.SetEncrypted(base64.StdEncoding.EncodeToString(context.data))
	mode, err := context.mechanism.DecryptMode()
	if err != nil {
		return nil, err
	}
	reqBody.SetMode(mode)
	decryptData, r, err := App.Api.KeysKeyIDDecryptPost(
		context.session.Slot.token.ApiCtx(), context.keyID).Body(reqBody).Execute()
	if err != nil {
		// log.Debugf("%v\n", r)
		// log.Debugf("%v\n", r.Request.Body)
		return nil, NewAPIError("DecryptContextRSA.Final()", "Decryption failed.", r, err)
	}
	decrypted, err := base64.StdEncoding.DecodeString(decryptData.GetDecrypted())
	if err != nil {
		return nil, err
	}
	return decrypted, nil
}

// func (context *VerifyContextRSA) Initialized() bool {
// 	return context.initialized
// }

// func (context *VerifyContextRSA) Init(metaBytes []byte) (err error) {
// 	// context.keyMeta, err = message.DecodeRSAKeyMeta(metaBytes)
// 	context.initialized = true
// 	return
// }

// func (context *VerifyContextRSA) Length() int {
// 	return 0 //context.pubKey.Size()
// }

// func (context *VerifyContextRSA) Update(data []byte) error {
// 	context.data = append(context.data, data...)
// 	return nil
// }

// func (context *VerifyContextRSA) Final(signature []byte) error {
// 	return verifyRSA(
// 		context.mechanism,
// 		// context.pubKey,
// 		context.data,
// 		signature,
// 	)
// }

// func verifyRSA(mechanism *Mechanism /* pubKey crypto.PublicKey ,*/, data []byte, signature []byte) (err error) {
// 	var hash []byte
// 	hashType, err := mechanism.GetHashType()
// 	if err != nil {
// 		return
// 	}
// 	rsaPK, ok := pubKey.(*rsa.PublicKey)
// 	if !ok {
// 		return NewError("verifyRSA", "public key invalid for this type of signature", CKR_ARGUMENTS_BAD)

// 	}
// 	switch mechanism.Type {
// 	case CKM_RSA_PKCS, CKM_MD5_RSA_PKCS, CKM_SHA1_RSA_PKCS, CKM_SHA256_RSA_PKCS, CKM_SHA384_RSA_PKCS, CKM_SHA512_RSA_PKCS:
// 		if hashType == crypto.Hash(0) {
// 			hash = data
// 		} else {
// 			hashFunc := hashType.New()
// 			_, err = hashFunc.Write(data)
// 			if err != nil {
// 				return
// 			}
// 			hash = hashFunc.Sum(nil)
// 		}
// 		if err = rsa.VerifyPKCS1v15(rsaPK, hashType, hash, signature); err != nil {
// 			return NewError("verifyRSA", "invalid signature", CKR_SIGNATURE_INVALID)
// 		}
// 	case CKM_SHA1_RSA_PKCS_PSS, CKM_SHA256_RSA_PKCS_PSS, CKM_SHA384_RSA_PKCS_PSS, CKM_SHA512_RSA_PKCS_PSS:
// 		hashFunc := hashType.New()
// 		_, err = hashFunc.Write(data)
// 		if err != nil {
// 			return
// 		}
// 		hash = hashFunc.Sum(nil)
// 		if err = rsa.VerifyPSS(rsaPK, hashType, hash, signature, nil); err != nil {
// 			return NewError("verifyRSA", "invalid signature", CKR_SIGNATURE_INVALID)
// 		}
// 	default:
// 		err = NewError("verifyRSA", "mechanism not supported yet for verifying", CKR_MECHANISM_INVALID)
// 		return
// 	}
// 	return
// }

// func createRSAPublicKey(keyID string, pkAttrs Attributes, key *rsa.PublicKey) (Attributes, error) {

// 	eBytes := make([]byte, unsafe.Sizeof(key.E))
// 	binary.BigEndian.PutUint64(eBytes, uint64(key.E)) // Exponent is BigNumber

// 	// encodedKeyMeta, err := message.EncodeRSAKeyMeta(keyMeta)
// 	// if err != nil {
// 	// 	return nil, NewError("Session.createRSAPublicKey", fmt.Sprintf("%s", err.Error()), CKR_ARGUMENTS_BAD)
// 	// }

// 	// This fields are defined in SoftHSM implementation
// 	pkAttrs.SetIfUndefined(
// 		&Attribute{CKA_CLASS, ulongToArr(CKO_PUBLIC_KEY)},
// 		&Attribute{CKA_KEY_TYPE, ulongToArr(CKK_RSA)},
// 		&Attribute{CKA_KEY_GEN_MECHANISM, ulongToArr(CKM_RSA_PKCS_KEY_PAIR_GEN)},
// 		&Attribute{CKA_LOCAL, ulongToArr(C.CK_TRUE)},

// 		// This fields are our defaults
// 		&Attribute{CKA_LABEL, nil},
// 		&Attribute{CKA_ID, nil},
// 		&Attribute{CKA_SUBJECT, nil},
// 		&Attribute{CKA_PRIVATE, ulongToArr(C.CK_FALSE)},
// 		&Attribute{CKA_MODIFIABLE, ulongToArr(C.CK_TRUE)},
// 		&Attribute{CKA_TOKEN, ulongToArr(C.CK_FALSE)},
// 		&Attribute{CKA_DERIVE, ulongToArr(C.CK_FALSE)},
// 		&Attribute{CKA_ENCRYPT, ulongToArr(C.CK_TRUE)},
// 		&Attribute{CKA_VERIFY, ulongToArr(C.CK_TRUE)},
// 		&Attribute{CKA_VERIFY_RECOVER, ulongToArr(C.CK_TRUE)},
// 		&Attribute{CKA_WRAP, ulongToArr(C.CK_TRUE)},
// 		&Attribute{CKA_TRUSTED, ulongToArr(C.CK_FALSE)},
// 		&Attribute{CKA_START_DATE, make([]byte, 8)},
// 		&Attribute{CKA_END_DATE, make([]byte, 8)},
// 		&Attribute{CKA_MODULUS_BITS, nil},
// 		&Attribute{CKA_PUBLIC_EXPONENT, eBytes},
// 	)

// 	pkAttrs.Set(
// 		// E and N from PK
// 		&Attribute{CKA_MODULUS, key.N.Bytes()},

// 		// Custom Fields
// 		// &Attribute{AttrTypeKeyHandler, []byte(keyID)},
// 		// &Attribute{AttrTypeKeyMeta, encodedKeyMeta},
// 	)

// 	return pkAttrs, nil
// }

// func createRSAPrivateKey(keyID string, skAttrs Attributes, key *rsa.PublicKey) (Attributes, error) {

// 	eBytes := make([]byte, unsafe.Sizeof(key.E))
// 	binary.BigEndian.PutUint64(eBytes, uint64(key.E))

// 	// encodedKeyMeta, err := message.EncodeRSAKeyMeta(keyMeta)
// 	// if err != nil {
// 	// 	return nil, NewError("Session.createRSAPrivateKey", fmt.Sprintf("%s", err.Error()), CKR_ARGUMENTS_BAD)
// 	// }

// 	// This fields are defined in SoftHSM implementation
// 	skAttrs.SetIfUndefined(
// 		&Attribute{CKA_CLASS, ulongToArr(CKO_PRIVATE_KEY)},
// 		&Attribute{CKA_KEY_TYPE, ulongToArr(CKK_RSA)},
// 		&Attribute{CKA_KEY_GEN_MECHANISM, ulongToArr(CKM_RSA_PKCS_KEY_PAIR_GEN)},
// 		&Attribute{CKA_LOCAL, ulongToArr(C.CK_TRUE)},

// 		// This fields are our defaults
// 		&Attribute{CKA_LABEL, nil},
// 		&Attribute{CKA_ID, nil},
// 		&Attribute{CKA_SUBJECT, nil},
// 		&Attribute{CKA_PRIVATE, ulongToArr(C.CK_TRUE)},
// 		&Attribute{CKA_MODIFIABLE, ulongToArr(C.CK_TRUE)},
// 		&Attribute{CKA_TOKEN, ulongToArr(C.CK_FALSE)},
// 		&Attribute{CKA_DERIVE, ulongToArr(C.CK_FALSE)},

// 		&Attribute{CKA_WRAP_WITH_TRUSTED, ulongToArr(C.CK_TRUE)},
// 		&Attribute{CKA_ALWAYS_AUTHENTICATE, ulongToArr(C.CK_FALSE)},
// 		&Attribute{CKA_SENSITIVE, ulongToArr(C.CK_TRUE)},
// 		&Attribute{CKA_ALWAYS_SENSITIVE, ulongToArr(C.CK_TRUE)},
// 		&Attribute{CKA_DECRYPT, ulongToArr(C.CK_TRUE)},
// 		&Attribute{CKA_SIGN, ulongToArr(C.CK_TRUE)},
// 		&Attribute{CKA_SIGN_RECOVER, ulongToArr(C.CK_TRUE)},
// 		&Attribute{CKA_UNWRAP, ulongToArr(C.CK_TRUE)},
// 		&Attribute{CKA_EXTRACTABLE, ulongToArr(C.CK_FALSE)},
// 		&Attribute{CKA_NEVER_EXTRACTABLE, ulongToArr(C.CK_TRUE)},

// 		&Attribute{CKA_START_DATE, make([]byte, 8)},
// 		&Attribute{CKA_END_DATE, make([]byte, 8)},
// 		&Attribute{CKA_PUBLIC_EXPONENT, eBytes},
// 	)

// 	skAttrs.Set(
// 		// E and N from PK
// 		&Attribute{CKA_MODULUS, key.N.Bytes()},

// 		// Custom Fields
// 		// &Attribute{AttrTypeKeyHandler, []byte(keyID)},
// 		// &Attribute{AttrTypeKeyMeta, encodedKeyMeta},
// 	)

// 	return skAttrs, nil
// }
