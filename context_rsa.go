package main

/*
#include "pkcs11go.h"
*/
import "C"

import (
	"crypto"
	"crypto/rsa"
	"encoding/binary"
	"fmt"
	"io"
	"reflect"

	"github.com/niclabs/dtcnode/v3/message"
	"github.com/niclabs/tcrsa"
)

type SignContextRSA struct {
	dtc         *DTC
	randSrc     io.Reader
	keyMeta     *tcrsa.KeyMeta // Key Metainfo used in signing.
	mechanism   *Mechanism     // Mechanism used to sign in a Sign session.
	keyID       string         // Key ID used in signing.
	data        []byte         // Data to sign.
	initialized bool           // // True if the user executed a Sign method and it has not finished yet.
}

type VerifyContextRSA struct {
	dtc         *DTC
	randSrc     io.Reader
	keyMeta     *tcrsa.KeyMeta // Key Metainfo used in sign verification.
	mechanism   *Mechanism     // Mechanism used to verify a signature in a Verify session.
	keyID       string         // Key ID used in sign verification.
	data        []byte         // Data to verify.
	initialized bool           // True if the user executed a Verify method and it has not finished yet.
}

func (context *SignContextRSA) Initialized() bool {
	return context.initialized
}

func (context *SignContextRSA) Init(metaBytes []byte) (err error) {
	context.keyMeta, err = message.DecodeRSAKeyMeta(metaBytes)
	context.initialized = true
	return
}

func (context *SignContextRSA) SignatureLength() int {
	return context.keyMeta.PublicKey.Size()
}

func (context *SignContextRSA) Update(data []byte) error {
	context.data = append(context.data, data...)
	return nil
}

func (context *SignContextRSA) Final() ([]byte, error) {
	prepared, err := context.mechanism.Prepare(
		context.randSrc,
		context.keyMeta.PublicKey.Size(),
		context.data,
	)
	if err != nil {
		return nil, err
	}
	signature, err := context.dtc.RSASignData(context.keyID, context.keyMeta, prepared)
	if err != nil {
		return nil, err
	}
	if err = verifyRSA(
		context.mechanism,
		context.keyMeta.PublicKey,
		context.data,
		signature,
	); err != nil {
		return nil, err
	}
	return signature, nil
}

func (context *VerifyContextRSA) Initialized() bool {
	return context.initialized
}

func (context *VerifyContextRSA) Init(metaBytes []byte) (err error) {
	context.keyMeta, err = message.DecodeRSAKeyMeta(metaBytes)
	context.initialized = true
	return
}

func (context *VerifyContextRSA) Length() int {
	return context.keyMeta.PublicKey.Size()
}

func (context *VerifyContextRSA) Update(data []byte) error {
	context.data = append(context.data, data...)
	return nil
}

func (context *VerifyContextRSA) Final(signature []byte) error {
	return verifyRSA(
		context.mechanism,
		context.keyMeta.PublicKey,
		context.data,
		signature,
	)
}

func verifyRSA(mechanism *Mechanism, pubKey crypto.PublicKey, data []byte, signature []byte) (err error) {
	var hash []byte
	hashType, err := mechanism.GetHashType()
	if err != nil {
		return
	}
	rsaPK, ok := pubKey.(*rsa.PublicKey)
	if !ok {
		return NewError("verifyRSA", "public key invalid for this type of signature", C.CKR_ARGUMENTS_BAD)

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
		if err = rsa.VerifyPKCS1v15(rsaPK, hashType, hash, signature); err != nil {
			return NewError("verifyRSA", "invalid signature", C.CKR_SIGNATURE_INVALID)
		}
	case C.CKM_SHA1_RSA_PKCS_PSS, C.CKM_SHA256_RSA_PKCS_PSS, C.CKM_SHA384_RSA_PKCS_PSS, C.CKM_SHA512_RSA_PKCS_PSS:
		hashFunc := hashType.New()
		_, err = hashFunc.Write(data)
		if err != nil {
			return
		}
		hash = hashFunc.Sum(nil)
		if err = rsa.VerifyPSS(rsaPK, hashType, hash, signature, nil); err != nil {
			return NewError("verifyRSA", "invalid signature", C.CKR_SIGNATURE_INVALID)
		}
	default:
		err = NewError("verifyRSA", "mechanism not supported yet for verifying", C.CKR_MECHANISM_INVALID)
		return
	}
	return
}

func createRSAPublicKey(keyID string, pkAttrs Attributes, keyMeta *tcrsa.KeyMeta) (Attributes, error) {

	eBytes := make([]byte, reflect.TypeOf(keyMeta.PublicKey.E).Size())
	binary.BigEndian.PutUint64(eBytes, uint64(keyMeta.PublicKey.E)) // Exponent is BigNumber

	encodedKeyMeta, err := message.EncodeRSAKeyMeta(keyMeta)
	if err != nil {
		return nil, NewError("Session.createRSAPublicKey", fmt.Sprintf("%s", err.Error()), C.CKR_ARGUMENTS_BAD)
	}

	// This fields are defined in SoftHSM implementation
	pkAttrs.SetIfUndefined(
		&Attribute{C.CKA_CLASS, ulongToArr(C.CKO_PUBLIC_KEY)},
		&Attribute{C.CKA_KEY_TYPE, ulongToArr(C.CKK_RSA)},
		&Attribute{C.CKA_KEY_GEN_MECHANISM, ulongToArr(C.CKM_RSA_PKCS_KEY_PAIR_GEN)},
		&Attribute{C.CKA_LOCAL, ulongToArr(C.CK_TRUE)},

		// This fields are our defaults
		&Attribute{C.CKA_LABEL, nil},
		&Attribute{C.CKA_ID, nil},
		&Attribute{C.CKA_SUBJECT, nil},
		&Attribute{C.CKA_PRIVATE, ulongToArr(C.CK_FALSE)},
		&Attribute{C.CKA_MODIFIABLE, ulongToArr(C.CK_TRUE)},
		&Attribute{C.CKA_TOKEN, ulongToArr(C.CK_FALSE)},
		&Attribute{C.CKA_DERIVE, ulongToArr(C.CK_FALSE)},
		&Attribute{C.CKA_ENCRYPT, ulongToArr(C.CK_TRUE)},
		&Attribute{C.CKA_VERIFY, ulongToArr(C.CK_TRUE)},
		&Attribute{C.CKA_VERIFY_RECOVER, ulongToArr(C.CK_TRUE)},
		&Attribute{C.CKA_WRAP, ulongToArr(C.CK_TRUE)},
		&Attribute{C.CKA_TRUSTED, ulongToArr(C.CK_FALSE)},
		&Attribute{C.CKA_START_DATE, make([]byte, 8)},
		&Attribute{C.CKA_END_DATE, make([]byte, 8)},
		&Attribute{C.CKA_MODULUS_BITS, nil},
		&Attribute{C.CKA_PUBLIC_EXPONENT, eBytes},
	)

	pkAttrs.Set(
		// E and N from PK
		&Attribute{C.CKA_MODULUS, keyMeta.PublicKey.N.Bytes()},

		// Custom Fields
		&Attribute{AttrTypeKeyHandler, []byte(keyID)},
		&Attribute{AttrTypeKeyMeta, encodedKeyMeta},
	)

	return pkAttrs, nil
}

func createRSAPrivateKey(keyID string, skAttrs Attributes, keyMeta *tcrsa.KeyMeta) (Attributes, error) {

	eBytes := make([]byte, reflect.TypeOf(keyMeta.PublicKey.E).Size())
	binary.BigEndian.PutUint64(eBytes, uint64(keyMeta.PublicKey.E))

	encodedKeyMeta, err := message.EncodeRSAKeyMeta(keyMeta)
	if err != nil {
		return nil, NewError("Session.createRSAPrivateKey", fmt.Sprintf("%s", err.Error()), C.CKR_ARGUMENTS_BAD)
	}

	// This fields are defined in SoftHSM implementation
	skAttrs.SetIfUndefined(
		&Attribute{C.CKA_CLASS, ulongToArr(C.CKO_PRIVATE_KEY)},
		&Attribute{C.CKA_KEY_TYPE, ulongToArr(C.CKK_RSA)},
		&Attribute{C.CKA_KEY_GEN_MECHANISM, ulongToArr(C.CKM_RSA_PKCS_KEY_PAIR_GEN)},
		&Attribute{C.CKA_LOCAL, ulongToArr(C.CK_TRUE)},

		// This fields are our defaults
		&Attribute{C.CKA_LABEL, nil},
		&Attribute{C.CKA_ID, nil},
		&Attribute{C.CKA_SUBJECT, nil},
		&Attribute{C.CKA_PRIVATE, ulongToArr(C.CK_TRUE)},
		&Attribute{C.CKA_MODIFIABLE, ulongToArr(C.CK_TRUE)},
		&Attribute{C.CKA_TOKEN, ulongToArr(C.CK_FALSE)},
		&Attribute{C.CKA_DERIVE, ulongToArr(C.CK_FALSE)},

		&Attribute{C.CKA_WRAP_WITH_TRUSTED, ulongToArr(C.CK_TRUE)},
		&Attribute{C.CKA_ALWAYS_AUTHENTICATE, ulongToArr(C.CK_FALSE)},
		&Attribute{C.CKA_SENSITIVE, ulongToArr(C.CK_TRUE)},
		&Attribute{C.CKA_ALWAYS_SENSITIVE, ulongToArr(C.CK_TRUE)},
		&Attribute{C.CKA_DECRYPT, ulongToArr(C.CK_TRUE)},
		&Attribute{C.CKA_SIGN, ulongToArr(C.CK_TRUE)},
		&Attribute{C.CKA_SIGN_RECOVER, ulongToArr(C.CK_TRUE)},
		&Attribute{C.CKA_UNWRAP, ulongToArr(C.CK_TRUE)},
		&Attribute{C.CKA_EXTRACTABLE, ulongToArr(C.CK_FALSE)},
		&Attribute{C.CKA_NEVER_EXTRACTABLE, ulongToArr(C.CK_TRUE)},

		&Attribute{C.CKA_START_DATE, make([]byte, 8)},
		&Attribute{C.CKA_END_DATE, make([]byte, 8)},
		&Attribute{C.CKA_PUBLIC_EXPONENT, eBytes},
	)

	skAttrs.Set(
		// E and N from PK
		&Attribute{C.CKA_MODULUS, keyMeta.PublicKey.N.Bytes()},

		// Custom Fields
		&Attribute{AttrTypeKeyHandler, []byte(keyID)},
		&Attribute{AttrTypeKeyMeta, encodedKeyMeta},
	)

	return skAttrs, nil
}
