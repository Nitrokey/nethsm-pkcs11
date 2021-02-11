package main

/*
#include "pkcs11go.h"
*/
import "C"
import (
	"github.com/niclabs/dtc/v3/config"
)

// Application contains the essential parts of the HSM
type Application struct {
	Storage Storage        // Storage saves the HSM objects.
	DTC     *DTC           // DTC is in charge of communication with the nodes.
	Slots   []*Slot        // Represents the slots of the HSM
	Config  *config.Config // has the complete configuration of the HSM
}

// NewApplication returns a new application, using the configuration defined in the config file.
func NewApplication() (app *Application, err error) {
	conf, err := config.GetConfig()
	if err != nil {
		return
	}
	db, err := NewDatabase(conf.Criptoki.DatabaseType)
	if err != nil {
		err = NewError("NewApplication", err.Error(), C.CKR_DEVICE_ERROR)
		return
	}
	if err = db.Init(conf.Criptoki.Slots); err != nil {
		err = NewError("NewApplication", err.Error(), C.CKR_DEVICE_ERROR)
		return
	}
	slots := make([]*Slot, len(conf.Criptoki.Slots))
	dtc, err := NewDTC(conf.DTC)
	if err != nil {
		return
	}

	app = &Application{
		Storage: db,
		Slots:   slots,
		Config:  conf,
		DTC:     dtc,
	}
	for i, slotConf := range conf.Criptoki.Slots {
		slot := &Slot{
			ID:          C.CK_SLOT_ID(i),
			Application: app,
			Sessions:    make(Sessions, 0),
		}
		var token *Token
		token, err = db.GetToken(slotConf.Label)
		if err != nil {
			err = NewError("NewApplication", err.Error(), C.CKR_DEVICE_ERROR)
			return
		}
		slot.InsertToken(token)
		slots[i] = slot
	}
	return
}

// GetSessionSlot returns the slot object related to a given session handle.
func (app *Application) GetSessionSlot(handle C.CK_SESSION_HANDLE) (*Slot, error) {
	for _, slot := range app.Slots {
		if slot.HasSession(handle) {
			return slot, nil
		}
	}
	return nil, NewError("Application.GetSessionSlot", "session not found", C.CKR_SESSION_HANDLE_INVALID)
}

// GetSession returns the session object related to a given handle.
func (app *Application) GetSession(handle C.CK_SESSION_HANDLE) (*Session, error) {
	slot, err := app.GetSessionSlot(handle)
	if err != nil {
		return nil, err
	}
	session, err := slot.GetSession(handle)
	if err != nil {
		return nil, err
	}
	return session, nil
}

// GetSlot returns the slot with the given ID.
func (app *Application) GetSlot(id C.CK_SLOT_ID) (*Slot, error) {
	if int(id) >= len(app.Slots) {
		return nil, NewError("Application.GetSlot", "index out of bounds", C.CKR_SLOT_ID_INVALID)
	}
	return app.Slots[int(id)], nil
}
