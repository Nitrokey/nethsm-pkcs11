package main

/*
#include "pkcs11go.h"
*/
import "C"

import (
	"crypto"
	"crypto/ecdsa"
	"fmt"
	"github.com/niclabs/dtc/v3/utils"
	"github.com/niclabs/dtcnode/v3/message"
	"github.com/niclabs/tcecdsa"
	"io"
	"log"
	"math/big"
)

type ECDSASignContext struct {
	dtc         *DTC
	randSrc     io.Reader
	keyMeta     *tcecdsa.KeyMeta // Key Metainfo used in signing.
	pubKey      *ecdsa.PublicKey // Public Key used in signing.
	mechanism   *Mechanism       // Mechanism used to sign in a Sign session.
	keyID       string           // Key ID used in signing.
	data        []byte           // Data to sign.
	initialized bool             // // True if the user executed a Sign method and it has not finished yet.
}

type ECDSAVerifyContext struct {
	dtc         *DTC
	randSrc     io.Reader
	keyMeta     *tcecdsa.KeyMeta // Key Metainfo used in sign verification.
	pubKey      *ecdsa.PublicKey // Public Key used in signing verification.
	mechanism   *Mechanism       // Mechanism used to verify a signature in a Verify session.
	keyID       string           // Key ID used in sign verification.
	data        []byte           // Data to verify.
	initialized bool             // True if the user executed a Verify method and it has not finished yet.
}

func (context *ECDSASignContext) Initialized() bool {
	return context.initialized
}

func (context *ECDSASignContext) Init(metaBytes []byte) (err error) {
	context.keyMeta, err = message.DecodeECDSAKeyMeta(metaBytes)
	context.initialized = true
	return
}

func (context *ECDSASignContext) SignatureLength() int {
	// Signature is composed by two numbers of bitsize = pubkey size
	// ASN.1 has overhead so we multiply it by 3 instead of two
	// (it is not so costly, and on signaturefinal we correct the final size)
	// of the signature
	return 3 * int((context.pubKey.Params().BitSize + 7) / 8)
}

func (context *ECDSASignContext) Update(data []byte) error {
	context.data = append(context.data, data...)
	return nil
}

func (context *ECDSASignContext) Final() ([]byte, error) {
	prepared, err := context.mechanism.Prepare(
		context.randSrc,
		context.SignatureLength(),
		context.data,
	)
	if err != nil {
		return nil, err
	}
	log.Printf("Signing data with key of curve=%s and id=%s", context.keyMeta.CurveName, context.keyID)
	// Round 1
	sig, err := context.dtc.ECDSASignData(context.keyID, context.keyMeta, prepared)
	if err != nil {
		return nil, err
	}
	if err = verifyECDSA(
		context.mechanism,
		context.pubKey,
		context.data,
		sig,
	); err != nil {
		return nil, err
	}
	return sig, nil
}

func (context *ECDSAVerifyContext) Initialized() bool {
	return context.initialized
}

func (context *ECDSAVerifyContext) Init(metaBytes []byte) (err error) {
	context.keyMeta, err = message.DecodeECDSAKeyMeta(metaBytes)
	context.initialized = true
	return
}

func (context *ECDSAVerifyContext) Length() int {
	return int((context.pubKey.Params().BitSize + 7) / 8)
}

func (context *ECDSAVerifyContext) Update(data []byte) error {
	context.data = append(context.data, data...)
	return nil
}

func (context *ECDSAVerifyContext) Final(sig []byte) error {
	return verifyECDSA(
		context.mechanism,
		context.pubKey,
		context.data,
		sig,
	)
}

func verifyECDSA(mechanism *Mechanism, pubKey crypto.PublicKey, data []byte, signature []byte) (err error) {
	var hash []byte
	hashType, err := mechanism.GetHashType()
	if err != nil {
		return
	}
	ecdsaPK, ok := pubKey.(*ecdsa.PublicKey)
	if !ok {
		return NewError("verifyECDSA", "public key invalid for this type of signature", C.CKR_ARGUMENTS_BAD)
	}
	switch mechanism.Type {
	case C.CKM_ECDSA, C.CKM_ECDSA_SHA1, C.CKM_ECDSA_SHA256, C.CKM_ECDSA_SHA384, C.CKM_ECDSA_SHA512:
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
		// https://www.oasis-open.org/committees/download.php/50389/CKM_ECDSA_FIPS_186_4_v03.pdf Section 2.3.1
		// >>> For signatures passed to a token for verification, the signature may have a shorter length
		// >>> but must be composed as specified before.
		big.NewInt(0).SetBytes(signature[:len(signature)])
		r := big.NewInt(0).SetBytes(signature[:len(signature)/2])
		s := big.NewInt(0).SetBytes(signature[len(signature)/2:])
		if !ecdsa.Verify(ecdsaPK, hash, r, s) {
			return NewError("verifyECDSA", "invalid signature", C.CKR_SIGNATURE_INVALID)
		}
	default:
		err = NewError("verifyECDSA", "mechanism not supported yet for verifying", C.CKR_MECHANISM_INVALID)
		return
	}
	return
}

func createECDSAPublicKey(keyID string, pkAttrs Attributes, pk *ecdsa.PublicKey, keyMeta *tcecdsa.KeyMeta) (Attributes, error) {

	encodedKeyMeta, err := message.EncodeECDSAKeyMeta(keyMeta)
	if err != nil {
		return nil, NewError("Session.createECDSAPublicKey", fmt.Sprintf("%s", err.Error()), C.CKR_ARGUMENTS_BAD)
	}

	ecPointSerialized, err := utils.PubKeyToASN1Bytes(pk)
	if err != nil {
		return nil, NewError("Session.createECDSAPublicKey", "cannot interpret ec point", C.CKR_ARGUMENTS_BAD)
	}

	// This fields are defined in SoftHSM implementation
	pkAttrs.SetIfUndefined(
		&Attribute{C.CKA_CLASS, ulongToArr(C.CKO_PUBLIC_KEY)},
		&Attribute{C.CKA_KEY_TYPE, ulongToArr(C.CKK_EC)},
		&Attribute{C.CKA_KEY_GEN_MECHANISM, ulongToArr(C.CKM_EC_KEY_PAIR_GEN)},
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
	)

	pkAttrs.Set(
		// ECDSA Public Key
		&Attribute{C.CKA_EC_POINT, ecPointSerialized},

		// Custom fields
		&Attribute{AttrTypeKeyHandler, []byte(keyID)},
		&Attribute{AttrTypeKeyMeta, encodedKeyMeta},
	)

	return pkAttrs, nil
}

func createECDSAPrivateKey(keyID string, skAttrs Attributes, pk *ecdsa.PublicKey, keyMeta *tcecdsa.KeyMeta) (Attributes, error) {

	encodedKeyMeta, err := message.EncodeECDSAKeyMeta(keyMeta)
	if err != nil {
		return nil, NewError("Session.createECDSAPublicKey", fmt.Sprintf("%s", err.Error()), C.CKR_ARGUMENTS_BAD)
	}

	ecPointSerialized, err := utils.PubKeyToASN1Bytes(pk)
	if err != nil {
		return nil, NewError("Session.createECDSAPublicKey", "cannot interpret ec point", C.CKR_ARGUMENTS_BAD)
	}

	// This fields are defined in SoftHSM implementation
	skAttrs.SetIfUndefined(
		&Attribute{C.CKA_CLASS, ulongToArr(C.CKO_PRIVATE_KEY)},
		&Attribute{C.CKA_KEY_TYPE, ulongToArr(C.CKK_EC)},
		&Attribute{C.CKA_KEY_GEN_MECHANISM, ulongToArr(C.CKM_EC_KEY_PAIR_GEN)},
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

	)
	skAttrs.Set(
		// ECDSA Public Key
		&Attribute{C.CKA_EC_POINT, ecPointSerialized},
		// Custom Fields
		&Attribute{AttrTypeKeyHandler, []byte(keyID)},
		&Attribute{AttrTypeKeyMeta, encodedKeyMeta},
	)

	return skAttrs, nil
}
