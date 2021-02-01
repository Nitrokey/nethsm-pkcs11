package core

/*
#include <stdlib.h>
#include <string.h>
#include "pkcs11go.h"
*/
import "C"
import (
	"fmt"
	"p11nethsm/openapi"
	"sync"
	"time"
	"unsafe"
)

// Security level constant
type SecurityLevel int

const (
	Error SecurityLevel = iota
	SecurityOfficer
	User
	Public
)

var nextObjectHandle = func() func() C.CK_OBJECT_HANDLE {
	var lastObjectHandle = C.CK_OBJECT_HANDLE(0)
	return func() C.CK_OBJECT_HANDLE {
		lastObjectHandle++
		return lastObjectHandle
	}
}()

// A token of the PKCS11 device.
type Token struct {
	sync.Mutex
	Label         string
	Pin           string
	SoPin         string
	_objects      CryptoObjects
	tokenFlags    uint64
	securityLevel SecurityLevel
	loggedIn      bool
	slot          *Slot
}

// Creates a new token, but doesn't store it.
func NewToken(label, userPin, soPin string) (*Token, error) {
	if len(label) > 32 {
		return nil, NewError("objects.NewToken", "Label with more than 32 chars", C.CKR_ARGUMENTS_BAD)
	}
	newToken := &Token{
		Label: label,
		Pin:   userPin,
		SoPin: soPin,
		tokenFlags: C.CKF_RNG |
			C.CKF_WRITE_PROTECTED |
			C.CKF_LOGIN_REQUIRED |
			C.CKF_USER_PIN_INITIALIZED |
			C.CKF_TOKEN_INITIALIZED,
	}
	return newToken, nil
}

// Equals returns true if the token objects are equal.
func (token *Token) Equals(token2 *Token) bool {
	return token.Label == token2.Label &&
		token.Pin == token2.Pin &&
		token.SoPin == token2.SoPin &&
		token._objects.Equals(token2._objects)
}

func (token *Token) GetObjects() (objects CryptoObjects, err error) {
	if token._objects != nil {
		objects = token._objects
		return
	}
	keys, r, e := App.Service.KeysGet(token.slot.ctx).Execute()
	if e != nil {
		err = NewAPIError("token.GetObjects", "KeysGet", r, e)
		return
	}
	for _, k := range keys {
		keyID := k.GetKey()
		key, r, e := App.Service.KeysKeyIDGet(token.slot.ctx, keyID).Execute()
		if e != nil {
			err = NewAPIError("token.GetObjects", "KeysKeyIDGet", r, e)
			return
		}
		object := CryptoObject{}
		object.Type = TokenObject
		object.Handle = nextObjectHandle()
		object.Attributes = Attributes{}
		object.Attributes.Set(
			&Attribute{C.CKA_LABEL, []byte(keyID)},
			&Attribute{C.CKA_CLASS, ulongToArr(C.CKO_PRIVATE_KEY)},
			&Attribute{C.CKA_ID, nil},
			&Attribute{C.CKA_SUBJECT, nil},
			&Attribute{C.CKA_KEY_GEN_MECHANISM, ulongToArr(C.CK_UNAVAILABLE_INFORMATION)},
			&Attribute{C.CKA_LOCAL, boolToArr(C.CK_FALSE)},
			&Attribute{C.CKA_PRIVATE, boolToArr(C.CK_TRUE)},
			&Attribute{C.CKA_MODIFIABLE, boolToArr(C.CK_FALSE)},
			&Attribute{C.CKA_TOKEN, boolToArr(C.CK_TRUE)},
			&Attribute{C.CKA_ALWAYS_AUTHENTICATE, boolToArr(C.CK_FALSE)},
			&Attribute{C.CKA_SENSITIVE, boolToArr(C.CK_TRUE)},
			&Attribute{C.CKA_ALWAYS_SENSITIVE, boolToArr(C.CK_TRUE)},
			&Attribute{C.CKA_EXTRACTABLE, boolToArr(C.CK_FALSE)},
			&Attribute{C.CKA_NEVER_EXTRACTABLE, boolToArr(C.CK_TRUE)},
		)
		switch key.Algorithm {
		case openapi.RSA:
			object.Attributes.Set(
				&Attribute{C.CKA_KEY_TYPE, ulongToArr(C.CKK_RSA)},
				&Attribute{C.CKA_DERIVE, boolToArr(C.CK_FALSE)},
				&Attribute{C.CKA_DECRYPT, []byte{C.CK_TRUE}},
				&Attribute{C.CKA_SIGN, boolToArr(C.CK_TRUE)},
				&Attribute{C.CKA_SIGN_RECOVER, boolToArr(C.CK_TRUE)},
				&Attribute{C.CKA_UNWRAP, boolToArr(C.CK_FALSE)},
				&Attribute{C.CKA_WRAP_WITH_TRUSTED, boolToArr(C.CK_TRUE)},
				&Attribute{C.CKA_MODULUS, []byte(key.Key.GetModulus())},
				&Attribute{C.CKA_PUBLIC_EXPONENT, []byte(key.Key.GetPublicExponent())},
			)
		case openapi.ED25519:
			object.Attributes.Set(
				&Attribute{C.CKA_KEY_TYPE, ulongToArr(C.CKK_EC)},
				&Attribute{C.CKA_DERIVE, boolToArr(C.CK_TRUE)},
				&Attribute{C.CKA_DECRYPT, boolToArr(C.CK_FALSE)},
				&Attribute{C.CKA_SIGN, boolToArr(C.CK_TRUE)},
				&Attribute{C.CKA_SIGN_RECOVER, boolToArr(C.CK_TRUE)},
				&Attribute{C.CKA_UNWRAP, boolToArr(C.CK_FALSE)},
				&Attribute{C.CKA_WRAP_WITH_TRUSTED, boolToArr(C.CK_TRUE)},
				&Attribute{C.CKA_EC_POINT, []byte(key.Key.GetData())},
			)
		}
		token.AddObject(&object)
	}
	objects = token._objects
	return
}

func (token *Token) GetInfo(pInfo C.CK_TOKEN_INFO_PTR) error {
	if pInfo == nil {
		return NewError("token.GetInfo", "got NULL pointer", C.CKR_ARGUMENTS_BAD)
	}
	info := (*C.CK_TOKEN_INFO)(unsafe.Pointer(pInfo))
	C.memset(unsafe.Pointer(&info.label[0]), ' ', 32)

	cLabel := C.CBytes([]byte(token.Label))
	defer C.free(unsafe.Pointer(cLabel))
	C.memcpy(unsafe.Pointer(&info.label[0]), cLabel, C.CK_ULONG(len(token.Label)))

	if token.slot == nil {
		return NewError("token.GetInfo", "cannot get info: token is not bound to a slot", C.CKR_ARGUMENTS_BAD)
	}

	apiInfo, r, err := App.Service.InfoGet(token.slot.ctx).Execute()
	if err != nil {
		return NewAPIError("token.GetInfo", "InfoGet", r, err)
	}

	apiSystemInfo, r, err := App.Service.SystemInfoGet(token.slot.ctx).Execute()
	if err != nil {
		return NewAPIError("token.GetInfo", "SystemInfoGet", r, err)
	}

	str2Buf(apiInfo.Vendor, &info.manufacturerID)
	str2Buf(apiInfo.Product, &info.model)
	serialNumber := "12345"
	str2Buf(serialNumber, &info.serialNumber)

	var hwVerMaj, hwVerMin, fwVerMaj, fwVerMin C.uchar
	s := apiSystemInfo.HardwareVersion
	fmt.Sscanf(s, "%d.%d", &hwVerMaj, &hwVerMin)
	s = apiSystemInfo.FirmwareVersion
	fmt.Sscanf(s, "%d.%d", &fwVerMaj, &fwVerMin)

	info.flags = C.CK_ULONG(token.tokenFlags)
	info.ulMaxSessionCount = C.CK_ULONG(App.Config.Cryptoki.MaxSessionCount)
	info.ulSessionCount = C.CK_UNAVAILABLE_INFORMATION
	info.ulMaxRwSessionCount = C.CK_ULONG(App.Config.Cryptoki.MaxSessionCount)
	info.ulRwSessionCount = C.CK_UNAVAILABLE_INFORMATION
	info.ulMaxPinLen = C.CK_ULONG(App.Config.Cryptoki.MaxPinLength)
	info.ulMinPinLen = C.CK_ULONG(App.Config.Cryptoki.MinPinLength)
	info.ulTotalPublicMemory = C.CK_UNAVAILABLE_INFORMATION
	info.ulFreePublicMemory = C.CK_UNAVAILABLE_INFORMATION
	info.ulTotalPrivateMemory = C.CK_UNAVAILABLE_INFORMATION
	info.ulFreePrivateMemory = C.CK_UNAVAILABLE_INFORMATION
	info.hardwareVersion.major = hwVerMaj
	info.hardwareVersion.minor = hwVerMin
	info.firmwareVersion.major = fwVerMaj
	info.firmwareVersion.minor = fwVerMin

	now := time.Now()
	cTimeStr := C.CString(now.Format("20060102150405") + "00")
	defer C.free(unsafe.Pointer(cTimeStr))
	C.memcpy(unsafe.Pointer(&info.utcTime[0]), unsafe.Pointer(cTimeStr), 16)

	return nil
}

// Sets the user pin to a new pin.
func (token *Token) SetUserPin(pin string) {
	token.Pin = pin
}

// It always returns true
func (token *Token) IsInited() bool {
	return true
}

// Gets security level set for the token at Login
func (token *Token) GetSecurityLevel() SecurityLevel {
	return token.securityLevel
}

// Checks if the pin provided is the user pin
func (token *Token) CheckUserPin(pin string) (SecurityLevel, error) {
	if token.Pin == pin {
		return User, nil
	} else {
		return Error, NewError("token.GetUserPin", "incorrect pin", C.CKR_PIN_INCORRECT)
	}
}

// Checks if the pin provided is the SO pin.
func (token *Token) CheckSecurityOfficerPin(pin string) (SecurityLevel, error) {
	if token.SoPin == pin {
		return User, nil
	} else {
		return Error, NewError("token.GetUserPin", "incorrect pin", C.CKR_PIN_INCORRECT)
	}
}

// Logs into the token, or returns an error if something goes wrong.
func (token *Token) Login(userType C.CK_USER_TYPE, pin string) error {
	if token.loggedIn &&
		(userType == C.CKU_USER && token.securityLevel == SecurityOfficer) ||
		(userType == C.CKU_SO && token.securityLevel == User) {
		return NewError("token.Login", "another user already logged in", C.CKR_USER_ALREADY_LOGGED_IN)
	}

	switch userType {
	case C.CKU_SO:
		securityLevel, err := token.CheckSecurityOfficerPin(pin)
		if err != nil {
			return err
		}
		token.securityLevel = securityLevel
	case C.CKU_USER:
		securityLevel, err := token.CheckUserPin(pin)
		if err != nil {
			return err
		}
		token.securityLevel = securityLevel
	case C.CKU_CONTEXT_SPECIFIC:
		switch token.securityLevel {
		case Public:
			return NewError("token.Login", "Bad userType", C.CKR_OPERATION_NOT_INITIALIZED)
		case User:
			securityLevel, err := token.CheckUserPin(pin)
			if err != nil {
				return err
			}
			token.securityLevel = securityLevel
		case SecurityOfficer:
			securityLevel, err := token.CheckSecurityOfficerPin(pin)
			if err != nil {
				return err
			}
			token.securityLevel = securityLevel

		}
	default:
		return NewError("token.Login", "Bad userType", C.CKR_USER_TYPE_INVALID)
	}
	token.loggedIn = true
	return nil
}

// Logs out from the token.
func (token *Token) Logout() {
	token.securityLevel = Public
	token.loggedIn = false
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
	return nil, NewError("Token.GetObject", fmt.Sprintf("object not found with id %v", handle), C.CKR_OBJECT_HANDLE_INVALID)
}

// Deletes an object from its list, but doesn't save it.
func (token *Token) DeleteObject(handle C.CK_OBJECT_HANDLE) error {
	token.Lock()
	defer token.Unlock()
	objPos := -1
	for i, object := range token._objects {
		if object.Handle == handle {
			objPos = i
			break
		}
	}
	if objPos == -1 {
		return NewError("Token.DeleteObject", fmt.Sprintf("object not found with id %v", handle), C.CKR_OBJECT_HANDLE_INVALID)
	}
	token._objects = append(token._objects[:objPos], token._objects[objPos+1:]...)
	return nil
}

// Copies the state of a token
func (token *Token) CopyState(token2 *Token) {
	token.Pin = token2.Pin
	token.securityLevel = token2.securityLevel
	token.loggedIn = token2.loggedIn
	token.SoPin = token2.SoPin
}
