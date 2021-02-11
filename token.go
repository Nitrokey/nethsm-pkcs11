package main

/*
#include <stdlib.h>
#include <string.h>
#include "pkcs11go.h"
*/
import "C"
import (
	"fmt"
	"strings"
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

// A token of the PKCS11 device.
type Token struct {
	sync.Mutex
	Label         string
	Pin           string
	SoPin         string
	Objects       CryptoObjects
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
		token.Objects.Equals(token2.Objects)
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

	manufacturerID := token.slot.Application.Config.Criptoki.ManufacturerID
	if len(manufacturerID) > 32 {
		manufacturerID = manufacturerID[:32]
	}

	manufacturerID += strings.Repeat(" ", 32-len(manufacturerID))
	cManufacturerID := C.CBytes([]byte(manufacturerID))
	defer C.free(unsafe.Pointer(cManufacturerID))
	C.memcpy(unsafe.Pointer(&info.manufacturerID[0]), cManufacturerID, 32)

	model := token.slot.Application.Config.Criptoki.Model
	if len(model) > 16 {
		model = model[:16]
	}
	model += strings.Repeat(" ", 16-len(model))
	cModel := C.CBytes([]byte(model))
	defer C.free(unsafe.Pointer(cModel))
	C.memcpy(unsafe.Pointer(&info.model[0]), cModel, 16)

	serialNumber := token.slot.Application.Config.Criptoki.SerialNumber
	if len(serialNumber) > 16 {
		serialNumber = serialNumber[:16]
	}

	serialNumber += strings.Repeat(" ", 16-len(serialNumber))
	cSerial := C.CBytes([]byte(model))
	defer C.free(unsafe.Pointer(cSerial))
	C.memcpy(unsafe.Pointer(&info.serialNumber[0]), cSerial, 16)

	info.flags = C.CK_ULONG(token.tokenFlags)
	info.ulMaxSessionCount = C.CK_ULONG(token.slot.Application.Config.Criptoki.MaxSessionCount)
	info.ulSessionCount = C.CK_UNAVAILABLE_INFORMATION
	info.ulMaxRwSessionCount = C.CK_ULONG(token.slot.Application.Config.Criptoki.MaxSessionCount)
	info.ulRwSessionCount = C.CK_UNAVAILABLE_INFORMATION
	info.ulMaxPinLen = C.CK_ULONG(token.slot.Application.Config.Criptoki.MaxPinLength)
	info.ulMinPinLen = C.CK_ULONG(token.slot.Application.Config.Criptoki.MinPinLength)
	info.ulTotalPublicMemory = C.CK_UNAVAILABLE_INFORMATION
	info.ulFreePublicMemory = C.CK_UNAVAILABLE_INFORMATION
	info.ulTotalPrivateMemory = C.CK_UNAVAILABLE_INFORMATION
	info.ulFreePrivateMemory = C.CK_UNAVAILABLE_INFORMATION
	info.hardwareVersion.major = 2
	info.hardwareVersion.minor = 40
	info.firmwareVersion.major = 2
	info.firmwareVersion.minor = 40

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
	token.Objects = append(token.Objects, object)
}

// Returns the label of the token (should remove. Label is a public property!
func (token *Token) GetLabel() string {
	return token.Label
}

// Returns an object that uses the handle provided.
func (token *Token) GetObject(handle C.CK_OBJECT_HANDLE) (*CryptoObject, error) {
	token.Lock()
	defer token.Unlock()
	for _, object := range token.Objects {
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
	for i, object := range token.Objects {
		if object.Handle == handle {
			objPos = i
			break
		}
	}
	if objPos == -1 {
		return NewError("Token.DeleteObject", fmt.Sprintf("object not found with id %v", handle), C.CKR_OBJECT_HANDLE_INVALID)
	}
	token.Objects = append(token.Objects[:objPos], token.Objects[objPos+1:]...)
	return nil
}

// Copies the state of a token
func (token *Token) CopyState(token2 *Token) {
	token.Pin = token2.Pin
	token.securityLevel = token2.securityLevel
	token.loggedIn = token2.loggedIn
	token.SoPin = token2.SoPin
}
