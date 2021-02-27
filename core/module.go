package core

import (
	"context"
	"os"
	"p11nethsm/api"
	"p11nethsm/config"
	"strings"
)

// Module contains the essential parts of the HSM
type Module struct {
	Slots  []*Slot        // Represents the slots of the HSM
	Config *config.Config // has the complete configuration of the HSM
	Api    *api.DefaultApiService
}

var Instance *Module

// Initialize returns a new application, using the configuration defined in the config file.
func Initialize() error {
	conf := config.Get()
	slots := make([]*Slot, len(conf.Slots))

	apiConf := api.NewConfiguration()
	apiConf.Servers[0].Variables = map[string]api.ServerVariable{"URL": {}}
	apiConf.Servers[0].URL = "{URL}"
	apiConf.Debug = conf.Debug
	client := api.NewAPIClient(apiConf)

	app := &Module{
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
			ID:          CK_SLOT_ID(i),
			Description: slotConf.Description,
			Sessions:    make(Sessions),
			Conf:        slotConf,
			ctx:         ctx,
			ctxCancel:   ctxCancel,
		}
		slots[i] = slot

		token, err := NewToken(slotConf.Label)
		if err != nil {
			err = NewError("NewApplication", err.Error(), CKR_DEVICE_ERROR)
			return err
		}
		if password == "" {
			token.Flags |= CKF_LOGIN_REQUIRED
		}
		if slotConf.Sparse {
			slot.InsertToken(token)
		} else {
			r, e := app.Api.HealthReadyGet(ctx).Execute()
			if e == nil && r.StatusCode < 300 {
				slot.InsertToken(token)
			}
		}
	}
	Instance = app
	return nil
}

// GetSessionSlot returns the slot object related to a given session handle.
func (app *Module) GetSessionSlot(handle CK_SESSION_HANDLE) (*Slot, error) {
	for _, slot := range app.Slots {
		if slot.HasSession(handle) {
			return slot, nil
		}
	}
	return nil, NewError("Application.GetSessionSlot", "session not found", CKR_SESSION_HANDLE_INVALID)
}

// GetSession returns the session object related to a given handle.
func (app *Module) GetSession(handle CK_SESSION_HANDLE) (*Session, error) {
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
func (app *Module) GetSlot(id CK_SLOT_ID) (*Slot, error) {
	if int(id) >= len(app.Slots) {
		return nil, NewError("Application.GetSlot", "index out of bounds", CKR_SLOT_ID_INVALID)
	}
	return app.Slots[int(id)], nil
}

// GetSlot returns the slot with the given ID.
func (app *Module) Finalize() error {
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
