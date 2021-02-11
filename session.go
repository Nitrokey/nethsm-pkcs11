package main

/*
#include "pkcs11go.h"
*/
import "C"
import (
	"crypto"
	"encoding/binary"
	"fmt"
	"github.com/google/uuid"
	"github.com/niclabs/dtc/v3/utils"
	"github.com/niclabs/tcrsa"
	"hash"
	"log"
	"math/rand"
	"sync"
	"unsafe"
)

const AttrTypeKeyHandler = 1 << 31
const AttrTypeKeyMeta = 1<<31 + 1

// Session represents a session in the HSM. It saves all the session variables needed to preserve the user state.
type Session struct {
	sync.Mutex
	Slot              *Slot                // The slot where the session is being used
	Handle            C.CK_SESSION_HANDLE  // A session handle
	flags             C.CK_FLAGS           // Session flags
	refreshedToken    bool                 // True if the token have been refreshed
	foundObjects      []C.CK_OBJECT_HANDLE // List of found objects
	findInitialized   bool                 // True if the user executed a Find method and it has not finished yet.
	signCtx           SignContext          // Signing Context
	verifyCtx         VerifyContext        // Verification Context
	digestHash        hash.Hash            // Hash used for hashing
	digestInitialized bool                 // True if the user executed a Hash method and it has not finished yet
	randSrc           *rand.Rand           // Seedable random source.
}

// Map of sessions identified by their handle. It's very similar to an array because the handles are integers.
type Sessions map[C.CK_SESSION_HANDLE]*Session

// A global variable that defines the session handles of the system.
var SessionHandle = C.CK_SESSION_HANDLE(0)

// The mutex that protects the global variable
var SessionMutex = sync.Mutex{}

func NewSession(flags C.CK_FLAGS, currentSlot *Slot) *Session {
	SessionMutex.Lock()
	defer SessionMutex.Unlock()
	SessionHandle++
	return &Session{
		Slot:    currentSlot,
		Handle:  SessionHandle,
		flags:   flags,
		randSrc: rand.New(rand.NewSource(int64(rand.Int()))),
	}
}

// GetInfo dumps session information into a C pointer.
func (session *Session) GetInfo(pInfo C.CK_SESSION_INFO_PTR) error {
	if pInfo != nil {
		state, err := session.GetState()
		if err != nil {
			return err
		}
		info := (*C.CK_SESSION_INFO)(unsafe.Pointer(pInfo))
		info.slotID = C.CK_SLOT_ID(session.Slot.ID)
		info.state = C.CK_STATE(state)
		info.flags = C.CK_FLAGS(session.flags)
		return nil

	} else {
		return NewError("Session.GetSessionInfo", "got NULL pointer", C.CKR_ARGUMENTS_BAD)
	}
}

// CreateObject saves an object and sets its handle.
func (session *Session) CreateObject(attrs Attributes) (*CryptoObject, error) {
	if attrs == nil {
		return nil, NewError("Session.CreateObject", "got NULL pointer", C.CKR_ARGUMENTS_BAD)
	}

	isTokenAttr, err := attrs.GetAttributeByType(C.CKA_TOKEN)
	if err != nil {
		return nil, NewError("Session.CreateObject", "is_token attr not defined", C.CKR_ARGUMENTS_BAD)
	}

	isToken := isTokenAttr.Value[0] != 0
	var objType CryptoObjectType

	if isToken {
		objType = TokenObject
	} else {
		objType = SessionObject
	}

	object := &CryptoObject{
		Type:       objType,
		Attributes: attrs,
	}
	token := session.Slot.token
	isPrivate := true
	oClass := C.CK_OBJECT_CLASS(C.CKO_VENDOR_DEFINED)
	keyType := C.CK_KEY_TYPE(C.CKK_VENDOR_DEFINED)

	privAttr, err := object.Attributes.GetAttributeByType(C.CKA_PRIVATE)
	if err == nil && len(privAttr.Value) > 0 {
		isPrivate = C.CK_BBOOL(privAttr.Value[0]) == C.CK_TRUE
	}

	classAttr, err := object.Attributes.GetAttributeByType(C.CKA_CLASS)
	if err == nil && len(classAttr.Value) > 0 {
		oClass = C.CK_OBJECT_CLASS(classAttr.Value[0])
	}

	keyTypeAttr, err := object.Attributes.GetAttributeByType(C.CKA_KEY_TYPE)
	if err == nil && len(classAttr.Value) > 0 {
		keyType = C.CK_KEY_TYPE(keyTypeAttr.Value[0])
	}

	if isToken && session.isReadOnly() {
		return nil, NewError("Session.CreateObject", "session is read only", C.CKR_SESSION_READ_ONLY)
	}
	state, err := session.GetState()
	if err != nil {
		return nil, err
	}
	if !GetUserAuthorization(state, isToken, isPrivate, true) {
		return nil, NewError("Session.CreateObject", "user not logged in", C.CKR_USER_NOT_LOGGED_IN)
	}

	switch oClass {
	case C.CKO_PUBLIC_KEY, C.CKO_PRIVATE_KEY:
		switch keyType {
		case C.CKK_RSA, C.CKK_EC:
			token.AddObject(object)
			err := session.Slot.Application.Storage.SaveToken(token)
			if err != nil {
				return nil, NewError("Session.CreateObject", err.Error(), C.CKR_DEVICE_ERROR)
			}
			return object, nil
		default:
			return nil, NewError("Session.CreateObject", "key type not supported yet", C.CKR_ATTRIBUTE_VALUE_INVALID)
		}
	}
	return nil, NewError("Session.CreateObject", "object class not supported yet", C.CKR_ATTRIBUTE_VALUE_INVALID)
	// TODO: Verify if the objects are valid
}

// DestroyObject deletes an object from the storage.
func (session *Session) DestroyObject(hObject C.CK_OBJECT_HANDLE) error {
	token, err := session.Slot.GetToken()
	if err != nil {
		return err
	}
	if object, err := token.GetObject(hObject); err != nil {
		return err
	} else {

		// Is it secure to allow the server to delete the keys? Suspended by now.
		attr := object.FindAttribute(AttrTypeKeyHandler) // Key ID
		if attr != nil {
			keyID := string(attr.Value)
			privateAttr := object.FindAttribute(C.CKA_PRIVATE)
			if privateAttr != nil {
				isPrivate := C.CK_BBOOL(privateAttr.Value[0]) == C.CK_TRUE
				if isPrivate {
					dtc, err := session.GetDTC()
					if err != nil {
						return err
					}
					err = dtc.RSADeleteKey(keyID)
					if err != nil {
						return err
					}
					log.Printf("all nodes deleted key shares for keyid=%s", keyID)
				}
			}
		}
		_ = token.DeleteObject(hObject)
		err := session.Slot.Application.Storage.SaveToken(token)
		if err != nil {
			return NewError("Session.DestroyObject", err.Error(), C.CKR_DEVICE_ERROR)
		}
		return nil
	}
}

// FindObjectsInit initializes a Find Objects Operation. It finds objects that have the attributes provided by the method.
func (session *Session) FindObjectsInit(attrs Attributes) error {
	if session.findInitialized {
		return NewError("Session.FindObjectsInit", "operation already initialized", C.CKR_OPERATION_ACTIVE)
	}
	token, err := session.Slot.GetToken()
	if err != nil {
		return err
	}

	if len(attrs) == 0 {
		session.foundObjects = make([]C.CK_OBJECT_HANDLE, len(token.Objects))
		for i, object := range token.Objects {
			session.foundObjects[i] = object.Handle
		}
	} else {
		session.foundObjects = make([]C.CK_OBJECT_HANDLE, 0)
		for _, object := range token.Objects {
			if object.Match(attrs) {
				session.foundObjects = append(session.foundObjects, object.Handle)
			}
		}
	}

	// If the object was not found. We need to reload the database, because the object could have been created by another instance.
	if len(session.foundObjects) == 0 && !session.refreshedToken {
		session.refreshedToken = true
		slot := session.Slot
		token, err := slot.GetToken()
		if err != nil {
			return err
		}
		db := slot.Application.Storage
		newToken, err := db.GetToken(token.Label)
		if err != nil {
			return NewError("Session.FindObjectsInit", err.Error(), C.CKR_DEVICE_ERROR)
		}
		newToken.CopyState(token)
		slot.InsertToken(newToken)
		return session.FindObjectsInit(attrs)
	}

	// TODO: Verify access permissions
	session.findInitialized = true
	return nil
}

// FindObjects returns a number of objects defined in arguments that have been found.
func (session *Session) FindObjects(maxObjectCount C.CK_ULONG) ([]C.CK_OBJECT_HANDLE, error) {
	if !session.findInitialized {
		return nil, NewError("Session.FindObjects", "operation not initialized", C.CKR_OPERATION_NOT_INITIALIZED)
	}
	limit := len(session.foundObjects)
	if int(maxObjectCount) < limit {
		limit = int(maxObjectCount)
	}
	resul := session.foundObjects[:limit]
	session.foundObjects = session.foundObjects[limit:]
	return resul, nil
}

// FindObjectsFinal resets the status and finishes the finding objects session.
func (session *Session) FindObjectsFinal() error {
	if !session.findInitialized {
		return NewError("Session.FindObjectsFinal", "operation not initialized", C.CKR_OPERATION_NOT_INITIALIZED)
	} else {
		session.findInitialized = false
		session.refreshedToken = false
	}
	return nil
}

// GetObject returns a CryptoObject in the token.
func (session *Session) GetObject(handle C.CK_OBJECT_HANDLE) (*CryptoObject, error) {
	token, err := session.Slot.GetToken()
	if err != nil {
		return nil, err
	}
	object, err := token.GetObject(handle)
	if err != nil {
		return nil, err
	}
	return object, nil
}

// SaveObject Saves a CryptoObject in the token.
func (session *Session) SaveObject(object *CryptoObject) error {
	token, err := session.Slot.GetToken()
	if err != nil {
		return err
	}
	err = token.DeleteObject(object.Handle)
	if err != nil {
		return err
	}
	token.AddObject(object)
	err = session.Slot.Application.Storage.SaveToken(token)
	if err != nil {
		return err
	}
	return nil
}

// GetState returns the session state.
func (session *Session) GetState() (C.CK_STATE, error) {
	switch session.Slot.token.GetSecurityLevel() {
	case SecurityOfficer:
		return C.CKS_RW_SO_FUNCTIONS, nil
	case User:
		if session.isReadOnly() {
			return C.CKS_RO_USER_FUNCTIONS, nil
		} else {
			return C.CKS_RW_USER_FUNCTIONS, nil
		}
	case Public:
		if session.isReadOnly() {
			return C.CKS_RO_PUBLIC_SESSION, nil
		} else {
			return C.CKS_RW_PUBLIC_SESSION, nil
		}
	}
	return 0, NewError("Session.GetState", "invalid security level", C.CKR_ARGUMENTS_BAD)
}

// IsReadOnly returns true if the session is read only.
func (session *Session) isReadOnly() bool {
	return (session.flags & C.CKF_RW_SESSION) != C.CKF_RW_SESSION
}

// Login logs in on a token with a pin and a defined user type.
func (session *Session) Login(userType C.CK_USER_TYPE, pin string) error {
	token, err := session.Slot.GetToken()
	if err != nil {
		return err
	}
	return token.Login(userType, pin)
}

// Logout logs out of a token.
func (session *Session) Logout() error {
	slot := session.Slot
	if slot == nil {
		return NewError("Session.Logout", "Slot is null", C.CKR_DEVICE_ERROR)
	}
	token, err := slot.GetToken()
	if err != nil {
		return err
	}
	if token != nil {
		token.Logout()
	}
	return nil
}

// GetDTC returns DTC struct to session, checking step by step if all the objects necessary to retrieve the struct are defined.
func (session *Session) GetDTC() (*DTC, error) {
	if session.Slot == nil {
		return nil, NewError("Session.GetDTC", "slot null", C.CKR_DEVICE_ERROR)
	} else if session.Slot.Application == nil {
		return nil, NewError("Session.GetDTC", "application null in slot", C.CKR_DEVICE_ERROR)

	} else if session.Slot.Application.DTC == nil {
		return nil, NewError("Session.GetDTC", "dtc null in application", C.CKR_DEVICE_ERROR)
	}
	return session.Slot.Application.DTC, nil
}

// GenerateKeyPair creates a public and a private key, or an error if it fails.
func (session *Session) GenerateKeyPair(mechanism *Mechanism, pkTemplate, skTemplate Attributes) (pkObject, skObject *CryptoObject, err error) {
	// TODO: Verify access permissions
	if mechanism == nil || pkTemplate == nil || skTemplate == nil { // maybe this should be 0?
		err = NewError("Session.GenerateKeyPair", "got NULL pointer", C.CKR_ARGUMENTS_BAD)
		return
	}
	var pk, sk Attributes
	switch mechanism.Type {
	case C.CKM_EC_KEY_PAIR_GEN:
		pk, sk, err = session.generateECDSAKeyPair(pkTemplate, skTemplate)
	case C.CKM_RSA_PKCS_KEY_PAIR_GEN:
		pk, sk, err = session.generateRSAKeyPair(pkTemplate, skTemplate)
	}
	if err != nil {
		return
	}
	pkObject, err = session.CreateObject(pk)
	if err != nil {
		return
	}
	skObject, err = session.CreateObject(sk)
	if err != nil {
		return
	}
	return

}

// SignInit starts the signing process.
func (session *Session) SignInit(mechanism *Mechanism, hKey C.CK_OBJECT_HANDLE) error {
	if session.signCtx != nil && session.signCtx.Initialized() {
		return NewError("Session.SignInit", "operation active", C.CKR_OPERATION_ACTIVE)
	}
	if mechanism == nil {
		return NewError("Session.SignInit", "got NULL pointer", C.CKR_ARGUMENTS_BAD)
	}

	signCtx, err := NewSignContext(session, mechanism, hKey)
	if err != nil {
		return err
	}
	session.signCtx = signCtx
	return nil
}

// SignLength returns the signature length.
func (session *Session) SignLength() (C.ulong, error) {
	if session.signCtx == nil || !session.signCtx.Initialized() {
		return 0, NewError("Session.SignLength", "operation not initialized", C.CKR_OPERATION_NOT_INITIALIZED)
	}
	return C.ulong(session.signCtx.SignatureLength()), nil
}

// SignUpdate updates the signature with data to sign.
func (session *Session) SignUpdate(data []byte) error {
	if session.signCtx == nil || !session.signCtx.Initialized() {
		return NewError("Session.SignUpdate", "operation not initialized", C.CKR_OPERATION_NOT_INITIALIZED)
	}
	return session.signCtx.Update(data)
}

// SignFinal returns the signature and resets the state.
func (session *Session) SignFinal() ([]byte, error) {
	if session.signCtx == nil || !session.signCtx.Initialized() {
		return nil, NewError("Session.SignFinal", "operation not initialized", C.CKR_OPERATION_NOT_INITIALIZED)
	}
	defer func() {
		session.signCtx = nil
	}()
	return session.signCtx.Final()
}

// VerifyInit starts a signature verification session with the key with the provided ID.
func (session *Session) VerifyInit(mechanism *Mechanism, hKey C.CK_OBJECT_HANDLE) error {
	if session.verifyCtx != nil && session.verifyCtx.Initialized() {
		return NewError("Session.VerifyInit", "operation active", C.CKR_OPERATION_ACTIVE)
	}
	if mechanism == nil {
		return NewError("Session.VerifyInit", "got NULL pointer", C.CKR_ARGUMENTS_BAD)
	}
	verifyCtx, err := NewVerifyContext(session, mechanism, hKey)
	if err != nil {
		return err
	}
	session.verifyCtx = verifyCtx
	return nil
}

// VerifyLength returns the size of the verification key Public Key Size.
func (session *Session) VerifyLength() (C.ulong, error) {
	if session.verifyCtx == nil || !session.verifyCtx.Initialized() {
		return 0, NewError("Session.VerifyLength", "operation not initialized", C.CKR_OPERATION_NOT_INITIALIZED)
	}
	return C.ulong(session.verifyCtx.Length()), nil
}

// VerifyUpdate adds more data to verify the signature.
func (session *Session) VerifyUpdate(data []byte) error {
	if session.verifyCtx == nil || !session.verifyCtx.Initialized() {
		return NewError("Session.VerifyUpdate", "operation not initialized", C.CKR_OPERATION_NOT_INITIALIZED)
	}
	return session.verifyCtx.Update(data)
}

// VerifyFinal receives the signature and verifies it based on the key and data provided on earlier methods.
func (session *Session) VerifyFinal(signature []byte) error {
	if session.verifyCtx == nil || !session.verifyCtx.Initialized() {
		return NewError("Session.VerifyFinal", "operation not initialized", C.CKR_OPERATION_NOT_INITIALIZED)
	}
	defer func() {
		session.verifyCtx = nil
	}()
	return session.verifyCtx.Final(signature)
}

// DigestInit starts a digest session.
func (session *Session) DigestInit(mechanism *Mechanism) error {
	if session.digestInitialized {
		return NewError("Session.DigestInit", "operation active", C.CKR_OPERATION_ACTIVE)
	}
	if mechanism == nil {
		return NewError("Session.DigestInit", "got NULL pointer", C.CKR_ARGUMENTS_BAD)
	}

	hashType, err := mechanism.GetHashType()
	if err != nil {
		return err
	}

	if hashType <= 0 || hashType >= crypto.BLAKE2b_512 {
		return NewError("Session.DigestInit", "mechanism invalid", C.CKR_MECHANISM_INVALID)
	}

	session.digestHash = hashType.New()
	session.digestInitialized = true
	return nil
}

// Digest adds data to digest and returns the digest of the data.
// If reset is true, the digestHash resets afther the hash calculation.
func (session *Session) Digest(data []byte, reset bool) ([]byte, error) {
	if !session.digestInitialized || session.digestHash == nil {
		return nil, NewError("Session.Digest", "operation not initialized", C.CKR_OPERATION_NOT_INITIALIZED)
	}
	if data == nil {
		return nil, NewError("Session.Digest", "got NULL pointer", C.CKR_ARGUMENTS_BAD)
	}
	_, err := session.digestHash.Write(data)
	if err != nil {
		return nil, err
	}
	hashed := session.digestHash.Sum(nil)
	if reset {
		session.digestHash.Reset()
	}
	return hashed, nil
}

// DigestFinish finishes a digest operation.
func (session *Session) DigestFinish() error {
	if !session.digestInitialized || session.digestHash == nil {
		return NewError("Session.Digest", "operation not initialized", C.CKR_OPERATION_NOT_INITIALIZED)
	}
	session.digestInitialized = false
	session.digestHash = nil
	return nil
}

// GenerateRandom generates a random number and returns it as byte.
func (session *Session) GenerateRandom(size int) ([]byte, error) {
	out := make([]byte, size)
	randLen, err := session.randSrc.Read(out)
	if err != nil {
		return nil, NewError("Session.GenerateRandom", fmt.Sprintf("%s", err.Error()), C.CKR_DEVICE_ERROR)
	}
	if randLen != size {
		return nil, NewError("Session.GenerateRandom", "random data acquired is not as big as requested", C.CKR_DEVICE_ERROR)
	}
	return out, nil
}

// SeedRandom seeds the PRNG.
func (session *Session) SeedRandom(seed []byte) {
	seedInt := int64(0)
	for i := 0; i < len(seed); i += 8 {
		var f int
		if len(seed) < i+8 {
			f = len(seed)
		} else {
			f = i + 8
		}
		slice := seed[i:f]
		seedInt += int64(binary.LittleEndian.Uint64(slice)) // it overflows
	}
	session.randSrc.Seed(seedInt)
}

func (session *Session) generateECDSAKeyPair(pkTemplate, skTemplate Attributes) (pkAttrs, skAttrs Attributes, err error) {
	dtc, err := session.GetDTC()
	if err != nil {
		return nil, nil, err
	}
	keyID := uuid.New().String()
	curveParams, err := pkTemplate.GetAttributeByType(C.CKA_EC_PARAMS)
	if err != nil {
		err = NewError("Session.GenerateECDSAKeyPair", fmt.Sprintf("error getting curve: %s", err), C.CKR_TEMPLATE_INCOMPLETE)
		return
	}
	curveName, err := utils.ASN1ToCurveName(curveParams.Value)
	if err != nil {
		return nil, nil, NewError("Session.GenerateECDSAKeyPair", fmt.Sprintf("%s", err), C.CKR_ARGUMENTS_BAD)
	}
	keyMeta, ecPK, err := dtc.ECDSACreateKey(keyID, curveName)
	if err != nil {
		return
	}
	pk, err := createECDSAPublicKey(keyID, pkTemplate, ecPK, keyMeta)
	if err != nil {
		return
	}
	sk, err := createECDSAPrivateKey(keyID, skTemplate, ecPK, keyMeta)
	if err != nil {
		return
	}
	return pk, sk, nil
}

func (session *Session) generateRSAKeyPair(pkTemplate, skTemplate Attributes) (pk, sk Attributes, err error) {
	dtc, err := session.GetDTC()
	if err != nil {
		return nil, nil, err
	}
	var keyMeta *tcrsa.KeyMeta
	keyID := uuid.New().String()
	bitSizeAttr, err := pkTemplate.GetAttributeByType(C.CKA_MODULUS_BITS)
	if err != nil {
		err = NewError("Session.GenerateRSAKeyPair", "Modulus Bits undefined", C.CKR_TEMPLATE_INCOMPLETE)
		return
	}
	exponentAttr, err := pkTemplate.GetAttributeByType(C.CKA_PUBLIC_EXPONENT)
	if err != nil {
		err = NewError("Session.GenerateRSAKeyPair", "Public Exponent undefined", C.CKR_TEMPLATE_INCOMPLETE)
		return
	}
	bitSize := binary.LittleEndian.Uint64(bitSizeAttr.Value)
	extendedExpAttr := make([]byte, 8)
	if len(exponentAttr.Value) > 8 {
		err = NewError("Session.GenerateRSAKeyPair", "Exponent size should not be greater than 64 bits", C.CKR_ARGUMENTS_BAD)
		return
	}
	copy(extendedExpAttr[8 - len(exponentAttr.Value):], exponentAttr.Value)
	exponent := binary.BigEndian.Uint64(extendedExpAttr) // Big Integer
	log.Printf("creating key with bitsize=%d and exponent=%d", bitSize, exponent)
	keyMeta, err = dtc.RSACreateKey(keyID, int(bitSize), int(exponent))
	if err != nil {
		return
	}
	pk, err = createRSAPublicKey(keyID, pkTemplate, keyMeta)
	if err != nil {
		return
	}
	sk, err = createRSAPrivateKey(keyID, skTemplate, keyMeta)
	if err != nil {
		return
	}
	return
}

// GetUserAuthorization returns the authorization level of the state.
func GetUserAuthorization(state C.CK_STATE, isToken, isPrivate, userAction bool) bool {
	switch state {
	case C.CKS_RW_SO_FUNCTIONS:
		return !isPrivate
	case C.CKS_RW_USER_FUNCTIONS:
		return true
	case C.CKS_RO_USER_FUNCTIONS:
		if isToken {
			return !userAction
		} else {
			return true
		}
	case C.CKS_RW_PUBLIC_SESSION:
		return !isPrivate
	case C.CKS_RO_PUBLIC_SESSION:
		return false
	}
	return false
}
