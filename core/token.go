package core

/*
#include <stdlib.h>
#include <string.h>
#include "pkcs11go.h"
*/
import "C"
import (
	"context"
	"fmt"
	"p11nethsm/api"
	"sync"
	"time"
	"unsafe"
)

var nextObjectHandle = func() func() C.CK_OBJECT_HANDLE {
	var lastObjectHandle = C.CK_OBJECT_HANDLE(0)
	return func() C.CK_OBJECT_HANDLE {
		lastObjectHandle++
		return lastObjectHandle
	}
}()

type loginData struct {
	userType C.CK_USER_TYPE
	pin      string
}

// A token of the PKCS11 device.
type Token struct {
	sync.Mutex
	Label      string
	keyIDs     []string
	_objects   CryptoObjects
	fetchedAll bool
	tokenFlags uint64
	loginData  *loginData
	slot       *Slot
	info       *api.InfoData
}

// Creates a new token, but doesn't store it.
func NewToken(label string) (*Token, error) {
	if len(label) > 32 {
		return nil, NewError("objects.NewToken", "Label with more than 32 chars", CKR_ARGUMENTS_BAD)
	}
	newToken := &Token{
		Label: label,
		tokenFlags: CKF_RNG |
			CKF_WRITE_PROTECTED |
			// CKF_LOGIN_REQUIRED |
			// CKF_PROTECTED_AUTHENTICATION_PATH |
			CKF_USER_PIN_INITIALIZED |
			CKF_TOKEN_INITIALIZED,
	}
	return newToken, nil
}

// Gets security level set for the token at Login
func (token *Token) GetLoginData() *loginData {
	return token.loginData
}

func (token *Token) ApiCtx() context.Context {
	ctx := token.slot.ctx
	if token.loginData != nil {
		ctx = addBasicAuth(ctx, token.slot.conf.User, token.loginData.pin)
	}
	return ctx
}

func (token *Token) FetchObjectsByID(keyID string) (CryptoObjects, error) {
	if objects := token.GetObjectsByID(keyID); objects != nil {
		return objects, nil
	}
	key, r, err := App.Api.KeysKeyIDGet(token.ApiCtx(), keyID).Execute()
	if err != nil {
		err = NewAPIError("token.GetObjects", "KeysKeyIDGet", r, err)
		return nil, err
	}
	object := &CryptoObject{}
	// object.Type = TokenObject
	object.Handle = nextObjectHandle()
	object.ID = keyID
	object.Attributes = Attributes{}
	object.Attributes.Set(
		&Attribute{CKA_LABEL, []byte(keyID)},
		&Attribute{CKA_CLASS, ulongToArr(uint64(CKO_PRIVATE_KEY))},
		&Attribute{CKA_ID, []byte(keyID)},
		&Attribute{CKA_SUBJECT, nil},
		&Attribute{CKA_KEY_GEN_MECHANISM, ulongToArr(C.CK_UNAVAILABLE_INFORMATION)},
		&Attribute{CKA_LOCAL, boolToArr(C.CK_FALSE)},
		&Attribute{CKA_PRIVATE, boolToArr(C.CK_TRUE)},
		&Attribute{CKA_MODIFIABLE, boolToArr(C.CK_FALSE)},
		&Attribute{CKA_TOKEN, boolToArr(C.CK_TRUE)},
		&Attribute{CKA_ALWAYS_AUTHENTICATE, boolToArr(C.CK_FALSE)},
		&Attribute{CKA_SENSITIVE, boolToArr(C.CK_TRUE)},
		&Attribute{CKA_ALWAYS_SENSITIVE, boolToArr(C.CK_TRUE)},
		&Attribute{CKA_EXTRACTABLE, boolToArr(C.CK_FALSE)},
		&Attribute{CKA_NEVER_EXTRACTABLE, boolToArr(C.CK_TRUE)},
	)
	switch key.Algorithm {
	case api.KEYALGORITHM_RSA:
		object.Attributes.Set(
			&Attribute{CKA_KEY_TYPE, ulongToArr(CKK_RSA)},
			&Attribute{CKA_DERIVE, boolToArr(C.CK_FALSE)},
			&Attribute{CKA_DECRYPT, []byte{C.CK_TRUE}},
			&Attribute{CKA_SIGN, boolToArr(C.CK_TRUE)},
			&Attribute{CKA_SIGN_RECOVER, boolToArr(C.CK_TRUE)},
			&Attribute{CKA_UNWRAP, boolToArr(C.CK_FALSE)},
			&Attribute{CKA_WRAP_WITH_TRUSTED, boolToArr(C.CK_TRUE)},
			&Attribute{CKA_MODULUS, []byte(key.Key.GetModulus())},
			&Attribute{CKA_PUBLIC_EXPONENT, []byte(key.Key.GetPublicExponent())},
		)
	case api.KEYALGORITHM_ED25519:
		object.Attributes.Set(
			&Attribute{CKA_KEY_TYPE, ulongToArr(CKK_EC)},
			&Attribute{CKA_DERIVE, boolToArr(C.CK_TRUE)},
			&Attribute{CKA_DECRYPT, boolToArr(C.CK_FALSE)},
			&Attribute{CKA_SIGN, boolToArr(C.CK_TRUE)},
			&Attribute{CKA_SIGN_RECOVER, boolToArr(C.CK_TRUE)},
			&Attribute{CKA_UNWRAP, boolToArr(C.CK_FALSE)},
			&Attribute{CKA_WRAP_WITH_TRUSTED, boolToArr(C.CK_TRUE)},
			&Attribute{CKA_EC_POINT, []byte(key.Key.GetData())},
		)
	}
	token.AddObject(object)
	return CryptoObjects{object}, nil
}

func (token *Token) FetchKeyIDs() ([]string, error) {
	if token.keyIDs == nil {
		keys, r, err := App.Api.KeysGet(token.ApiCtx()).Execute()
		if err != nil {
			err = NewAPIError("token.FetchKeyIDs", "KeysGet", r, err)
			return nil, err
		}
		var ids []string
		for _, k := range keys {
			ids = append(ids, k.GetKey())
		}
		token.Lock()
		token.keyIDs = ids
		token.Unlock()
	}
	return token.keyIDs, nil
}

func (token *Token) FetchObjects(keyID string) (CryptoObjects, error) {
	if keyID != "" {
		return token.FetchObjectsByID(keyID)
	}
	if !token.fetchedAll {
		keyIDs, err := token.FetchKeyIDs()
		if err != nil {
			return nil, err
		}
		for _, id := range keyIDs {
			_, err := token.FetchObjectsByID(id)
			if err != nil {
				return nil, err
			}
		}
		token.Lock()
		token.fetchedAll = true
		token.Unlock()
	}
	return token._objects, nil
}

func (token *Token) GetInfo(pInfo C.CK_TOKEN_INFO_PTR) error {
	if pInfo == nil {
		return NewError("token.GetInfo", "got NULL pointer", CKR_ARGUMENTS_BAD)
	}
	info := (*C.CK_TOKEN_INFO)(unsafe.Pointer(pInfo))

	str2Buf(token.Label, info.label[:])

	if token.slot == nil {
		return NewError("token.GetInfo", "cannot get info: token is not bound to a slot", CKR_ARGUMENTS_BAD)
	}

	if token.info == nil {
		if token.slot.conf.Sparse {
			var info api.InfoData
			info.Product = "NetHSM"
			info.Vendor = libManufacturerID
			token.info = &info
		} else {
			info, r, err := App.Api.InfoGet(token.ApiCtx()).Execute()
			if err != nil {
				return NewAPIError("token.GetInfo", "InfoGet", r, err)
			}
			token.info = &info
		}
	}

	str2Buf(token.info.Vendor, info.manufacturerID[:])
	str2Buf(token.info.Product, info.model[:])
	str2Buf(serialNumber, info.serialNumber[:])

	info.flags = C.CK_ULONG(token.tokenFlags)
	info.ulMaxSessionCount = C.CK_ULONG(App.Config.MaxSessionCount)
	info.ulSessionCount = C.CK_UNAVAILABLE_INFORMATION
	info.ulMaxRwSessionCount = 0
	info.ulRwSessionCount = C.CK_UNAVAILABLE_INFORMATION
	info.ulMaxPinLen = C.CK_ULONG(maxPinLength)
	info.ulMinPinLen = C.CK_ULONG(minPinLength)
	info.ulTotalPublicMemory = C.CK_UNAVAILABLE_INFORMATION
	info.ulFreePublicMemory = C.CK_UNAVAILABLE_INFORMATION
	info.ulTotalPrivateMemory = C.CK_UNAVAILABLE_INFORMATION
	info.ulFreePrivateMemory = C.CK_UNAVAILABLE_INFORMATION
	info.hardwareVersion.major = 0
	info.hardwareVersion.minor = 1
	info.firmwareVersion.major = 0
	info.firmwareVersion.minor = 1

	now := time.Now()
	timeStr := []byte(now.Format("20060102150405") + "00")
	C.memcpy(unsafe.Pointer(&info.utcTime[0]), unsafe.Pointer(&timeStr[0]), 16)

	return nil
}

func (token *Token) CheckUserPin(pin string) error {
	authCtx := addBasicAuth(token.ApiCtx(), token.slot.conf.User, pin)
	_, r, err := App.Api.KeysGet(authCtx).Execute()
	if err != nil {
		if r.StatusCode == 401 {
			return NewError("Login", "Authorization failed", CKR_PIN_INCORRECT)
		}
		return NewAPIError("Login", "Login failed", r, err)
	}
	return nil
}

// Logs into the token, or returns an error if something goes wrong.
func (token *Token) Login(userType C.CK_USER_TYPE, pin string) error {
	if uint(userType) != CKU_CONTEXT_SPECIFIC && token.loginData != nil &&
		token.loginData.userType == userType {
		return NewError("token.Login", "another user already logged in", CKR_USER_ALREADY_LOGGED_IN)
	}

	switch uint(userType) {
	case CKU_USER:
		if !token.slot.conf.Sparse {
			err := token.CheckUserPin(pin)
			if err != nil {
				return err
			}
		}
	case CKU_SO:
		return NewError("token.Login", "CKU_SO not supperted", CKR_USER_TYPE_INVALID)
	case CKU_CONTEXT_SPECIFIC:
		return NewError("token.Login", "CKU_CONTEXT_SPECIFIC not supperted", CKR_USER_TYPE_INVALID)
	default:
		return NewError("token.Login", "Bad userType", CKR_USER_TYPE_INVALID)
	}
	var loginData loginData
	loginData.userType = userType
	loginData.pin = pin
	token.loginData = &loginData
	return nil
}

// Logs out from the token.
func (token *Token) Logout() {
	token.loginData = nil
}

// Adds a cryptoObject to the token
func (token *Token) AddObject(object *CryptoObject) {
	token.Lock()
	defer token.Unlock()
	token._objects = append(token._objects, object)
}

// Returns the label of the token (should remove. Label is a public property!
func (token *Token) GetLabel() string {
	return token.Label
}

// Returns an object that uses the handle provided.
func (token *Token) GetObject(handle C.CK_OBJECT_HANDLE) (*CryptoObject, error) {
	token.Lock()
	defer token.Unlock()
	for _, object := range token._objects {
		if object.Handle == handle {
			return object, nil
		}
	}
	return nil, NewError("Token.GetObject", fmt.Sprintf("object not found with handle %v", handle), CKR_OBJECT_HANDLE_INVALID)
}

func (token *Token) GetObjectsByID(keyID string) CryptoObjects {
	token.Lock()
	defer token.Unlock()
	var objects CryptoObjects
	for _, object := range token._objects {
		if object.ID == keyID {
			objects = append(objects, object)
		}
	}
	return objects
}
