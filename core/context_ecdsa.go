package core

// type ECDSASignContext struct {
// 	// randSrc io.Reader
// 	// keyMeta     *tcecdsa.KeyMeta // Key Metainfo used in signing.
// 	// pubKey      *ecdsa.PublicKey // Public Key used in signing.
// 	mechanism   *Mechanism // Mechanism used to sign in a Sign session.
// 	keyID       string     // Key ID used in signing.
// 	data        []byte     // Data to sign.
// 	initialized bool       // // True if the user executed a Sign method and it has not finished yet.
// }

// type ECDSAVerifyContext struct {
// 	// randSrc io.Reader
// 	// keyMeta     *tcecdsa.KeyMeta // Key Metainfo used in sign verification.
// 	pubKey      *ecdsa.PublicKey // Public Key used in signing verification.
// 	mechanism   *Mechanism       // Mechanism used to verify a signature in a Verify session.
// 	keyID       string           // Key ID used in sign verification.
// 	data        []byte           // Data to verify.
// 	initialized bool             // True if the user executed a Verify method and it has not finished yet.
// }

// func (context *ECDSASignContext) Initialized() bool {
// 	return context.initialized
// }

// func (context *ECDSASignContext) Init(metaBytes []byte) (err error) {
// 	// context.keyMeta, err = message.DecodeECDSAKeyMeta(metaBytes)
// 	context.initialized = true
// 	return
// }

// func (context *ECDSASignContext) SignatureLength() int {
// 	// Signature is composed by two numbers of bitsize = pubkey size
// 	// ASN.1 has overhead so we multiply it by 3 instead of two
// 	// (it is not so costly, and on signaturefinal we correct the final size)
// 	// of the signature
// 	// return 3 * int((context.pubKey.Params().BitSize+7)/8)
// 	return 0
// }

// func (context *ECDSASignContext) Update(data []byte) error {
// 	context.data = append(context.data, data...)
// 	return nil
// }

// func (context *ECDSASignContext) Final() ([]byte, error) {
// 	// _ /*prepared*/, err := context.mechanism.Prepare(
// 	// 	context.randSrc,
// 	// 	context.SignatureLength(),
// 	// 	context.data,
// 	// )
// 	// if err != nil {
// 	// 	return nil, err
// 	// }
// 	// log.Debugf("Signing data with key of curve=%s and id=%s", context.pubKey.Curve, context.keyID)
// 	// Round 1
// 	var sig []byte
// 	// XXX sig, err := context.dtc.ECDSASignData(context.keyID, context.keyMeta, prepared)
// 	// if err != nil {
// 	// 	return nil, err
// 	// }
// 	// if err = verifyECDSA(
// 	// 	context.mechanism,
// 	// 	context.pubKey,
// 	// 	context.data,
// 	// 	sig,
// 	// ); err != nil {
// 	// 	return nil, err
// 	// }
// 	return sig, nil
// }

// func (context *ECDSAVerifyContext) Initialized() bool {
// 	return context.initialized
// }

// func (context *ECDSAVerifyContext) Init(metaBytes []byte) (err error) {
// 	// context.keyMeta, err = message.DecodeECDSAKeyMeta(metaBytes)
// 	context.initialized = true
// 	return
// }

// func (context *ECDSAVerifyContext) Length() int {
// 	return int((context.pubKey.Params().BitSize + 7) / 8)
// }

// func (context *ECDSAVerifyContext) Update(data []byte) error {
// 	context.data = append(context.data, data...)
// 	return nil
// }

// func (context *ECDSAVerifyContext) Final(sig []byte) error {
// 	return verifyECDSA(
// 		context.mechanism,
// 		context.pubKey,
// 		context.data,
// 		sig,
// 	)
// }

// func verifyECDSA(mechanism *Mechanism, pubKey crypto.PublicKey, data []byte, signature []byte) (err error) {
// 	var hash []byte
// 	hashType, err := mechanism.GetHashType()
// 	if err != nil {
// 		return
// 	}
// 	ecdsaPK, ok := pubKey.(*ecdsa.PublicKey)
// 	if !ok {
// 		return NewError("verifyECDSA", "public key invalid for this type of signature", CKR_ARGUMENTS_BAD)
// 	}
// 	switch mechanism.Type {
// 	case CKM_ECDSA, CKM_ECDSA_SHA1, CKM_ECDSA_SHA256, CKM_ECDSA_SHA384, CKM_ECDSA_SHA512:
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
// 		// https://www.oasis-open.org/committees/download.php/50389/CKM_ECDSA_FIPS_186_4_v03.pdf Section 2.3.1
// 		// >>> For signatures passed to a token for verification, the signature may have a shorter length
// 		// >>> but must be composed as specified before.
// 		big.NewInt(0).SetBytes(signature[:])
// 		r := big.NewInt(0).SetBytes(signature[:len(signature)/2])
// 		s := big.NewInt(0).SetBytes(signature[len(signature)/2:])
// 		if !ecdsa.Verify(ecdsaPK, hash, r, s) {
// 			return NewError("verifyECDSA", "invalid signature", CKR_SIGNATURE_INVALID)
// 		}
// 	default:
// 		err = NewError("verifyECDSA", "mechanism not supported yet for verifying", CKR_MECHANISM_INVALID)
// 		return
// 	}
// 	return
// }

// func createECDSAPublicKey(keyID string, pkAttrs Attributes, pk *ecdsa.PublicKey /*, keyMeta *tcecdsa.KeyMeta*/) (Attributes, error) {

// 	// encodedKeyMeta, err := message.EncodeECDSAKeyMeta(keyMeta)
// 	// if err != nil {
// 	// 	return nil, NewError("Session.createECDSAPublicKey", fmt.Sprintf("%s", err.Error()), CKR_ARGUMENTS_BAD)
// 	// }

// 	ecPointSerialized, err := utils.PubKeyToASN1Bytes(pk)
// 	if err != nil {
// 		return nil, NewError("Session.createECDSAPublicKey", "cannot interpret ec point", CKR_ARGUMENTS_BAD)
// 	}

// 	// This fields are defined in SoftHSM implementation
// 	pkAttrs.SetIfUndefined(
// 		&Attribute{CKA_CLASS, ulongToArr(CKO_PUBLIC_KEY)},
// 		&Attribute{CKA_KEY_TYPE, ulongToArr(CKK_EC)},
// 		&Attribute{CKA_KEY_GEN_MECHANISM, ulongToArr(CKM_EC_KEY_PAIR_GEN)},
// 		&Attribute{CKA_LOCAL, ulongToArr(CK_TRUE)},

// 		// This fields are our defaults
// 		&Attribute{CKA_LABEL, nil},
// 		&Attribute{CKA_ID, nil},
// 		&Attribute{CKA_SUBJECT, nil},
// 		&Attribute{CKA_PRIVATE, ulongToArr(CK_FALSE)},
// 		&Attribute{CKA_MODIFIABLE, ulongToArr(CK_TRUE)},
// 		&Attribute{CKA_TOKEN, ulongToArr(CK_FALSE)},
// 		&Attribute{CKA_DERIVE, ulongToArr(CK_FALSE)},
// 		&Attribute{CKA_ENCRYPT, ulongToArr(CK_TRUE)},
// 		&Attribute{CKA_VERIFY, ulongToArr(CK_TRUE)},
// 		&Attribute{CKA_VERIFY_RECOVER, ulongToArr(CK_TRUE)},
// 		&Attribute{CKA_WRAP, ulongToArr(CK_TRUE)},
// 		&Attribute{CKA_TRUSTED, ulongToArr(CK_FALSE)},
// 		&Attribute{CKA_START_DATE, make([]byte, 8)},
// 		&Attribute{CKA_END_DATE, make([]byte, 8)},
// 	)

// 	pkAttrs.Set(
// 		// ECDSA Public Key
// 		&Attribute{CKA_EC_POINT, ecPointSerialized},

// 		// Custom fields
// 		// &Attribute{AttrTypeKeyHandler, []byte(keyID)},
// 		// &Attribute{AttrTypeKeyMeta, encodedKeyMeta},
// 	)

// 	return pkAttrs, nil
// }

// func createECDSAPrivateKey(keyID string, skAttrs Attributes, pk *ecdsa.PublicKey /*, keyMeta *tcecdsa.KeyMeta*/) (Attributes, error) {

// 	// encodedKeyMeta, err := message.EncodeECDSAKeyMeta(keyMeta)
// 	// if err != nil {
// 	// 	return nil, NewError("Session.createECDSAPublicKey", fmt.Sprintf("%s", err.Error()), CKR_ARGUMENTS_BAD)
// 	// }

// 	ecPointSerialized, err := utils.PubKeyToASN1Bytes(pk)
// 	if err != nil {
// 		return nil, NewError("Session.createECDSAPublicKey", "cannot interpret ec point", CKR_ARGUMENTS_BAD)
// 	}

// 	// This fields are defined in SoftHSM implementation
// 	skAttrs.SetIfUndefined(
// 		&Attribute{CKA_CLASS, ulongToArr(CKO_PRIVATE_KEY)},
// 		&Attribute{CKA_KEY_TYPE, ulongToArr(CKK_EC)},
// 		&Attribute{CKA_KEY_GEN_MECHANISM, ulongToArr(CKM_EC_KEY_PAIR_GEN)},
// 		&Attribute{CKA_LOCAL, ulongToArr(CK_TRUE)},

// 		// This fields are our defaults
// 		&Attribute{CKA_LABEL, nil},
// 		&Attribute{CKA_ID, nil},
// 		&Attribute{CKA_SUBJECT, nil},
// 		&Attribute{CKA_PRIVATE, ulongToArr(CK_TRUE)},
// 		&Attribute{CKA_MODIFIABLE, ulongToArr(CK_TRUE)},
// 		&Attribute{CKA_TOKEN, ulongToArr(CK_FALSE)},
// 		&Attribute{CKA_DERIVE, ulongToArr(CK_FALSE)},

// 		&Attribute{CKA_WRAP_WITH_TRUSTED, ulongToArr(CK_TRUE)},
// 		&Attribute{CKA_ALWAYS_AUTHENTICATE, ulongToArr(CK_FALSE)},
// 		&Attribute{CKA_SENSITIVE, ulongToArr(CK_TRUE)},
// 		&Attribute{CKA_ALWAYS_SENSITIVE, ulongToArr(CK_TRUE)},
// 		&Attribute{CKA_DECRYPT, ulongToArr(CK_TRUE)},
// 		&Attribute{CKA_SIGN, ulongToArr(CK_TRUE)},
// 		&Attribute{CKA_SIGN_RECOVER, ulongToArr(CK_TRUE)},
// 		&Attribute{CKA_UNWRAP, ulongToArr(CK_TRUE)},
// 		&Attribute{CKA_EXTRACTABLE, ulongToArr(CK_FALSE)},
// 		&Attribute{CKA_NEVER_EXTRACTABLE, ulongToArr(CK_TRUE)},
// 		&Attribute{CKA_START_DATE, make([]byte, 8)},
// 		&Attribute{CKA_END_DATE, make([]byte, 8)},
// 	)
// 	skAttrs.Set(
// 		// ECDSA Public Key
// 		&Attribute{CKA_EC_POINT, ecPointSerialized},
// 		// Custom Fields
// 		// &Attribute{AttrTypeKeyHandler, []byte(keyID)},
// 		// &Attribute{AttrTypeKeyMeta, encodedKeyMeta},
// 	)

// 	return skAttrs, nil
// }
