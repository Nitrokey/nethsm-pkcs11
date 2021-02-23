package core

/*
#include "pkcs11go.h"
*/
import "C"
import (
	"p11nethsm/log"
	"sync"
	"unsafe"
)

// Session represents a session in the HSM. It saves all the session variables needed to preserve the user state.
type Session struct {
	sync.Mutex
	Slot            *Slot                // The slot where the session is being used
	Handle          C.CK_SESSION_HANDLE  // A session handle
	flags           C.CK_FLAGS           // Session flags
	refreshedToken  bool                 // True if the token have been refreshed
	foundObjects    []C.CK_OBJECT_HANDLE // List of found objects
	findInitialized bool                 // True if the user executed a Find method and it has not finished yet.
	signCtx         OpContext            // Signing Context
	decryptCtx      OpContext            // Decrypting Context
	Cache           []byte
	// digestHash        hash.Hash            // Hash used for hashing
	// digestInitialized bool                 // True if the user executed a Hash method and it has not finished yet
	// randSrc *rand.Rand // Seedable random source.
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
		Slot:   currentSlot,
		Handle: SessionHandle,
		flags:  flags,
		// randSrc: rand.New(rand.NewSource(int64(rand.Int()))),
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
		return NewError("Session.GetSessionInfo", "got NULL pointer", CKR_ARGUMENTS_BAD)
	}
}

// FindObjectsInit initializes a Find Objects Operation. It finds objects that have the attributes provided by the method.
func (session *Session) FindObjectsInit(attrs Attributes) error {
	if session.findInitialized {
		return NewError("Session.FindObjectsInit", "operation already initialized", CKR_OPERATION_ACTIVE)
	}
	token, err := session.Slot.GetToken()
	if err != nil {
		return err
	}

	log.Debugf("Attributes:\n")
	for k, v := range attrs {
		log.Debugf("0x%x: %v", k, v)
	}

	var id string
	for k, v := range attrs {
		if k == CKA_ID {
			id = string(v.Value)
			break
		}
		if k == CKA_LABEL {
			id = string(v.Value)
		}
	}
	objects, err := token.FetchObjects(id)
	if err != nil {
		return err
	}

	if len(attrs) == 0 {
		session.foundObjects = make([]C.CK_OBJECT_HANDLE, len(objects))
		for i, object := range objects {
			session.foundObjects[i] = object.Handle
		}
	} else {
		session.foundObjects = nil
		for _, object := range objects {
			if object.Match(attrs) {
				session.foundObjects = append(session.foundObjects, object.Handle)
			}
		}
		log.Debugf("foundObjects: %v", session.foundObjects)
	}

	session.findInitialized = true
	return nil
}

// FindObjects returns a number of objects defined in arguments that have been found.
func (session *Session) FindObjects(maxObjectCount C.CK_ULONG) ([]C.CK_OBJECT_HANDLE, error) {
	if !session.findInitialized {
		return nil, NewError("Session.FindObjects", "operation not initialized", CKR_OPERATION_NOT_INITIALIZED)
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
		return NewError("Session.FindObjectsFinal", "operation not initialized", CKR_OPERATION_NOT_INITIALIZED)
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

// GetState returns the session state.
func (session *Session) GetState() (C.CK_STATE, error) {
	loginData := session.Slot.token.GetLoginData()
	if loginData == nil {
		if session.isReadOnly() {
			return CKS_RO_PUBLIC_SESSION, nil
		} else {
			return CKS_RW_PUBLIC_SESSION, nil
		}
	}
	switch uint(loginData.userType) {
	case CKU_SO:
		return CKS_RW_SO_FUNCTIONS, nil
	case CKU_USER:
		if session.isReadOnly() {
			return CKS_RO_USER_FUNCTIONS, nil
		} else {
			return CKS_RW_USER_FUNCTIONS, nil
		}
	}
	return 0, NewError("Session.GetState", "invalid security level", CKR_ARGUMENTS_BAD)
}

// IsReadOnly returns true if the session is read only.
func (session *Session) isReadOnly() bool {
	return (session.flags & CKF_RW_SESSION) != CKF_RW_SESSION
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
		return NewError("Session.Logout", "Slot is null", CKR_DEVICE_ERROR)
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

// SignInit starts the signing process.
func (session *Session) SignInit(mechanism *Mechanism, hKey C.CK_OBJECT_HANDLE) error {
	if session.signCtx != nil && session.signCtx.Initialized() {
		return NewError("Session.SignInit", "operation active", CKR_OPERATION_ACTIVE)
	}
	if mechanism == nil {
		return NewError("Session.SignInit", "got NULL pointer", CKR_ARGUMENTS_BAD)
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
		return 0, NewError("Session.SignLength", "operation not initialized", CKR_OPERATION_NOT_INITIALIZED)
	}
	return C.ulong(session.signCtx.ResultLength()), nil
}

// SignUpdate updates the signature with data to sign.
func (session *Session) SignUpdate(data []byte) error {
	if session.signCtx == nil || !session.signCtx.Initialized() {
		return NewError("Session.SignUpdate", "operation not initialized", CKR_OPERATION_NOT_INITIALIZED)
	}
	return session.signCtx.Update(data)
}

// SignFinal returns the signature and resets the state.
func (session *Session) SignFinal() ([]byte, error) {
	if session.signCtx == nil || !session.signCtx.Initialized() {
		return nil, NewError("Session.SignFinal", "operation not initialized", CKR_OPERATION_NOT_INITIALIZED)
	}
	return session.signCtx.Final()
}

func (session *Session) SignClear() {
	session.signCtx = nil
}

func (session *Session) DecryptInit(mechanism *Mechanism, hKey C.CK_OBJECT_HANDLE) error {
	if session.decryptCtx != nil && session.decryptCtx.Initialized() {
		return NewError("Session.DecryptInit", "operation active", CKR_OPERATION_ACTIVE)
	}
	if mechanism == nil {
		return NewError("Session.DecryptInit", "got NULL pointer", CKR_ARGUMENTS_BAD)
	}

	decryptCtx, err := NewDecryptContext(session, mechanism, hKey)
	if err != nil {
		return err
	}
	session.decryptCtx = decryptCtx
	return nil
}

func (session *Session) DecryptLength() (C.ulong, error) {
	if session.decryptCtx == nil || !session.decryptCtx.Initialized() {
		return 0, NewError("Session.DecryptLength", "operation not initialized", CKR_OPERATION_NOT_INITIALIZED)
	}
	return C.ulong(session.decryptCtx.ResultLength()), nil
}

func (session *Session) DecryptUpdate(data []byte) error {
	if session.decryptCtx == nil || !session.decryptCtx.Initialized() {
		return NewError("Session.DecryptUpdate", "operation not initialized", CKR_OPERATION_NOT_INITIALIZED)
	}
	return session.decryptCtx.Update(data)
}

func (session *Session) DecryptFinal() ([]byte, error) {
	if session.decryptCtx == nil || !session.decryptCtx.Initialized() {
		return nil, NewError("Session.DecryptFinal", "operation not initialized", CKR_OPERATION_NOT_INITIALIZED)
	}
	return session.decryptCtx.Final()
}

func (session *Session) DecryptClear() {
	session.decryptCtx = nil
}

// GetUserAuthorization returns the authorization level of the state.
func GetUserAuthorization(state C.CK_STATE, isToken, isPrivate, userAction bool) bool {
	switch state {
	case CKS_RW_SO_FUNCTIONS:
		return !isPrivate
	case CKS_RW_USER_FUNCTIONS:
		return true
	case CKS_RO_USER_FUNCTIONS:
		if isToken {
			return !userAction
		} else {
			return true
		}
	case CKS_RW_PUBLIC_SESSION:
		return !isPrivate
	case CKS_RO_PUBLIC_SESSION:
		return false
	}
	return false
}
