package core

/*
#include "pkcs11go.h"
*/
import "C"
import (
	"context"
	"os"
	"p11nethsm/config"
	"p11nethsm/openapi"
	"strings"
)

// Application contains the essential parts of the HSM
type Application struct {
	// Storage Storage        // Storage saves the HSM objects.
	Slots   []*Slot        // Represents the slots of the HSM
	Config  *config.Config // has the complete configuration of the HSM
	Service *openapi.DefaultApiService
}

// NewApplication returns a new application, using the configuration defined in the config file.
func NewApplication() (App *Application, err error) {
	conf := config.Get()
	// db, err := NewDatabase(conf.Cryptoki.DatabaseType)
	// if err != nil {
	// 	err = NewError("NewApplication", err.Error(), C.CKR_DEVICE_ERROR)
	// 	return
	// }
	// if err = db.Init(conf.Cryptoki.Slots); err != nil {
	// 	err = NewError("NewApplication", err.Error(), C.CKR_DEVICE_ERROR)
	// 	return
	// }
	slots := make([]*Slot, len(conf.Slots))

	apiConf := openapi.NewConfiguration()
	apiConf.Servers[0].Variables = map[string]openapi.ServerVariable{"URL": {}}
	apiConf.Servers[0].URL = "{URL}"
	service := openapi.NewAPIClient(apiConf).DefaultApi

	App = &Application{
		// Storage: db,
		Slots:   slots,
		Config:  conf,
		Service: service,
	}
	for i, slotConf := range conf.Slots {
		password := slotConf.Password
		if prefix := "env:"; strings.HasPrefix(password, prefix) {
			password = os.Getenv(strings.TrimPrefix(password, prefix))
		}
		basicAuth := openapi.BasicAuth{
			UserName: slotConf.User,
			Password: password,
		}
		ctx, ctxCancel := context.WithCancel(context.Background())
		ctx = context.WithValue(ctx, openapi.ContextServerVariables, map[string]string{
			"URL": slotConf.URL,
		})
		ctx = context.WithValue(ctx, openapi.ContextBasicAuth, basicAuth)

		slot := &Slot{
			ID:          C.CK_SLOT_ID(i),
			description: slotConf.Description,
			Application: App,
			Sessions:    make(Sessions),
			ctx:         ctx,
			ctxCancel:   ctxCancel,
		}
		slots[i] = slot

		r, e := App.Service.HealthReadyGet(slot.ctx).Execute()
		if e == nil && r.StatusCode < 300 {
			var token *Token
			token, err = NewToken(slotConf.Label, "1234", "1234")
			if err != nil {
				err = NewError("NewApplication", err.Error(), C.CKR_DEVICE_ERROR)
				return
			}
			slot.InsertToken(token)
		}
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
