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
	"unsafe"
)

// Slot represents a HSM slot. It has an ID and it can have a connected Token.
type Slot struct {
	ID          C.CK_SLOT_ID // ID of slot
	flags       uint64       // Flags related to the slot
	token       *Token       // Token connected to slot. It could be nil
	Sessions    Sessions     // Sessions accessing to the slot
	Application *Application // Application that created the slot.
	sync.Mutex
}

// IsTokenPresent returns true if there is a token connected to the slot
func (slot *Slot) IsTokenPresent() bool {
	return slot.token != nil
}

// OpenSession opens a new session with given flags.
func (slot *Slot) OpenSession(flags C.CK_FLAGS) (C.CK_SESSION_HANDLE, error) {
	if !slot.IsTokenPresent() {
		return 0, NewError("Slot.OpenSession", "token not present", C.CKR_TOKEN_NOT_PRESENT)
	}
	session := NewSession(flags, slot)
	handle := session.Handle
	slot.Lock()
	defer slot.Unlock()
	slot.Sessions[handle] = session
	return handle, nil
}

// CloseSession closes the session identified by the given handle.
func (slot *Slot) CloseSession(handle C.CK_SESSION_HANDLE) error {
	if !slot.IsTokenPresent() {
		return NewError("Slot.CloseSession", "token not present", C.CKR_TOKEN_NOT_PRESENT)
	}
	if _, err := slot.GetSession(handle); err != nil {
		return err
	}
	slot.Lock()
	defer slot.Unlock()
	delete(slot.Sessions, handle)
	return nil
}

func (slot *Slot) CloseAllSessions() {
	slot.Lock()
	defer slot.Unlock()
	slot.Sessions = make(Sessions, 0)
}

// GetSession returns an active session with the given handle.
func (slot *Slot) GetSession(handle C.CK_SESSION_HANDLE) (*Session, error) {
	if !slot.IsTokenPresent() {
		return nil, NewError("Slot.GetSession", "token not present", C.CKR_TOKEN_NOT_PRESENT)
	}
	slot.Lock()
	defer slot.Unlock()
	if session, ok := slot.Sessions[handle]; !ok {
		return nil, NewError("Slot.CloseSession", fmt.Sprintf("session handle '%v' doesn't exist in this slot", handle), C.CKR_SESSION_HANDLE_INVALID)
	} else {
		return session, nil
	}
}

// HasSession returns true if the session with the handle as ID exists.
func (slot *Slot) HasSession(handle C.CK_SESSION_HANDLE) bool {
	slot.Lock()
	defer slot.Unlock()
	_, ok := slot.Sessions[handle]
	return ok
}

// GetInfo returns the slot info.
func (slot *Slot) GetInfo(pInfo C.CK_SLOT_INFO_PTR) error {
	if pInfo == nil {
		return NewError("Slot.GetInfo", "got NULL pointer", C.CKR_ARGUMENTS_BAD)
	}
	info := (*C.CK_SLOT_INFO)(unsafe.Pointer(pInfo))

	description := slot.Application.Config.Criptoki.Description
	if len(description) > 64 {
		description = description[:64]
	}
	description += strings.Repeat(" ", 64-len(description)) // spaces
	cDescription := C.CBytes([]byte(description))
	defer C.free(unsafe.Pointer(cDescription))
	C.memcpy(unsafe.Pointer(&info.slotDescription[0]), cDescription, 64)

	manufacturerID := slot.Application.Config.Criptoki.ManufacturerID
	if len(manufacturerID) > 64 {
		manufacturerID = manufacturerID[:64]
	}
	manufacturerID += strings.Repeat(" ", 32-len(manufacturerID))
	cManufacturerID := C.CBytes([]byte(manufacturerID))
	defer C.free(unsafe.Pointer(cManufacturerID))
	C.memcpy(unsafe.Pointer(&info.manufacturerID[0]), cManufacturerID, 32)

	pInfo.flags = C.CK_ULONG(slot.flags)
	pInfo.hardwareVersion.major = 2
	pInfo.hardwareVersion.minor = 40
	pInfo.firmwareVersion.major = 2
	pInfo.firmwareVersion.minor = 40
	return nil
}

// GetToken returns the token inserted into the slot.
func (slot *Slot) GetToken() (*Token, error) {
	if slot.IsTokenPresent() {
		return slot.token, nil
	} else {
		return nil, NewError("Slot.GetToken", "token not present", C.CKR_TOKEN_NOT_PRESENT)
	}
}

// InsertToken inserts a token into the slot.
func (slot *Slot) InsertToken(token *Token) {
	slot.token = token
	token.slot = slot
}
