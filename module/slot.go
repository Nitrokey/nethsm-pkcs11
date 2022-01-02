package module

import (
	"context"
	"fmt"
	"p11nethsm/api"
	"p11nethsm/config"
	"sync"
)

// Slot represents a HSM slot. It has an ID and it can have a connected Token.
type Slot struct {
	ID          CK_SLOT_ID // ID of slot
	Description string
	Flags       uint64   // Flags related to the slot
	Token       *Token   // Token connected to slot. It could be nil
	Sessions    Sessions // Sessions accessing to the slot
	Api         *api.DefaultApiService
	ctx         context.Context
	ctxCancel   context.CancelFunc
	Conf        *config.SlotsConfig
	sync.RWMutex
}

// IsTokenPresent returns true if there is a token connected to the slot
func (slot *Slot) IsTokenPresent() bool {
	return slot.Token != nil
}

// GetToken returns the token inserted into the slot.
func (slot *Slot) GetToken() (*Token, error) {
	if slot.IsTokenPresent() {
		return slot.Token, nil
	} else {
		return nil, NewError("Slot.GetToken", "token not present", CKR_TOKEN_NOT_PRESENT)
	}
}

// InsertToken inserts a token into the slot.
func (slot *Slot) InsertToken(token *Token) {
	slot.Token = token
	token.Slot = slot
}

// OpenSession opens a new session with given flags.
func (slot *Slot) OpenSession(flags CK_FLAGS) (CK_SESSION_HANDLE, error) {
	if !slot.IsTokenPresent() {
		return 0, NewError("Slot.OpenSession", "token not present", CKR_TOKEN_NOT_PRESENT)
	}
	session := NewSession(flags, slot)
	handle := session.Handle
	slot.Lock()
	defer slot.Unlock()
	slot.Sessions[handle] = session
	return handle, nil
}

// CloseSession closes the session identified by the given handle.
func (slot *Slot) CloseSession(handle CK_SESSION_HANDLE) error {
	if !slot.IsTokenPresent() {
		return NewError("Slot.CloseSession", "token not present", CKR_TOKEN_NOT_PRESENT)
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
	slot.Sessions = make(Sessions)
}

// GetSession returns an active session with the given handle.
func (slot *Slot) GetSession(handle CK_SESSION_HANDLE) (*Session, error) {
	if !slot.IsTokenPresent() {
		return nil, NewError("Slot.GetSession", "token not present", CKR_TOKEN_NOT_PRESENT)
	}
	slot.RLock()
	defer slot.RUnlock()
	if session, ok := slot.Sessions[handle]; !ok {
		return nil, NewError("Slot.CloseSession", fmt.Sprintf("session handle '%v' doesn't exist in this slot", handle), CKR_SESSION_HANDLE_INVALID)
	} else {
		return session, nil
	}
}

// HasSession returns true if the session with the handle as ID exists.
func (slot *Slot) HasSession(handle CK_SESSION_HANDLE) bool {
	slot.RLock()
	defer slot.RUnlock()
	_, ok := slot.Sessions[handle]
	return ok
}
