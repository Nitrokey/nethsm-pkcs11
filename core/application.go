package core

/*
#include "pkcs11go.h"
*/
import "C"
import (
	"context"
	"os"
	"p11nethsm/api"
	"p11nethsm/config"
	"strings"
)

// Application contains the essential parts of the HSM
type Application struct {
	Slots  []*Slot        // Represents the slots of the HSM
	Config *config.Config // has the complete configuration of the HSM
	Api    *api.DefaultApiService
}

// NewApplication returns a new application, using the configuration defined in the config file.
func NewApplication() (*Application, error) {
	conf := config.Get()
	slots := make([]*Slot, len(conf.Slots))

	apiConf := api.NewConfiguration()
	apiConf.Servers[0].Variables = map[string]api.ServerVariable{"URL": {}}
	apiConf.Servers[0].URL = "{URL}"
	client := api.NewAPIClient(apiConf)

	app := &Application{
		Slots:  slots,
		Config: conf,
		Api:    client.DefaultApi,
	}
	for i, slotConf := range conf.Slots {
		password := slotConf.Password
		if prefix := "env:"; strings.HasPrefix(password, prefix) {
			password = os.Getenv(strings.TrimPrefix(password, prefix))
		}
		ctx, ctxCancel := context.WithCancel(context.Background())
		ctx = context.WithValue(ctx, api.ContextServerVariables, map[string]string{
			"URL": slotConf.URL,
		})
		if password != "" {
			ctx = addBasicAuth(ctx, slotConf.User, password)
		}
		slot := &Slot{
			ID:          C.CK_SLOT_ID(i),
			description: slotConf.Description,
			Sessions:    make(Sessions),
			conf:        slotConf,
			ctx:         ctx,
			ctxCancel:   ctxCancel,
		}
		slots[i] = slot

		r, e := app.Api.HealthReadyGet(slot.ctx).Execute()
		if e == nil && r.StatusCode < 300 {
			token, err := NewToken(slotConf.Label)
			if err != nil {
				err = NewError("NewApplication", err.Error(), C.CKR_DEVICE_ERROR)
				return nil, err
			}
			if password == "" {
				token.tokenFlags |= C.CKF_LOGIN_REQUIRED
			}
			slot.InsertToken(token)
		}
	}
	return app, nil
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

// GetSlot returns the slot with the given ID.
func (app *Application) Finalize() error {
	for _, slot := range app.Slots {
		slot.ctxCancel()
		slot = nil
	}
	return nil
}

func addBasicAuth(ctx context.Context, user, password string) context.Context {
	basicAuth := api.BasicAuth{
		UserName: user,
		Password: password,
	}
	return context.WithValue(ctx, api.ContextBasicAuth, basicAuth)
}
