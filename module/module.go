package module

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"net/http"
	"os"
	"p11nethsm/api"
	"p11nethsm/config"
	"regexp"
	"strings"
)

var (
	Slots       []*Slot        // Represents the slots of the HSM
	Config      *config.Config // has the complete configuration of the HSM
	Initialized bool
)

var hexFilter = regexp.MustCompile(`[^a-fA-F0-9]`)

func pinnedClient(hashes []string) (*http.Client, error) {
	pins := make([][32]byte, len(hashes))
	for i := range hashes {
		filtered := []byte(hexFilter.ReplaceAllString(hashes[i], ""))
		if len(filtered) != 64 {
			return nil, fmt.Errorf("Fingerprint (%s) has wrong length.", hashes[i])
		}
		_, err := hex.Decode(pins[i][:], filtered)
		if err != nil {
			return nil, fmt.Errorf("Fingerprint (%s) malformed: %w", hashes[i], err)
		}
	}
	checkPinnedCert := func(c tls.ConnectionState) error {
		sum := sha256.Sum256(c.PeerCertificates[0].Raw)
		for i := range pins {
			if pins[i] == sum {
				return nil
			}
		}
		return fmt.Errorf("Certificate does not match any pinned fingerprint: %s",
			hex.EncodeToString(sum[:]))
	}
	customTransport := http.DefaultTransport.(*http.Transport).Clone()
	customTransport.TLSClientConfig = &tls.Config{
		VerifyConnection:   checkPinnedCert,
		InsecureSkipVerify: true,
	}
	return &http.Client{Transport: customTransport}, nil
}

func parsePassword(pw string) string {
	prefix := "env:"
	if strings.HasPrefix(pw, prefix) {
		return os.Getenv(strings.TrimPrefix(pw, prefix))
	}
	return pw
}

// Initialize returns a new application, using the configuration defined in the config file.
func Initialize() error {
	conf := config.Get()
	slots := make([]*Slot, len(conf.Slots))

	for i, slotConf := range conf.Slots {
		apiConf := api.NewConfiguration()
		apiConf.Debug = conf.Debug
		apiConf.Servers = api.ServerConfigurations{
			{
				URL:         slotConf.URL,
				Description: slotConf.Description,
			},
		}
		if len(slotConf.CertSHA256) != 0 {
			client, err := pinnedClient(slotConf.CertSHA256)
			if err != nil {
				desc := fmt.Sprintf("Slot %d (%s): %v", i, slotConf.Label, err)
				return NewError("Initialize", desc, CKR_DEVICE_ERROR)
			}
			apiConf.HTTPClient = client
		}
		service := api.NewAPIClient(apiConf).DefaultApi

		ctx, ctxCancel := context.WithCancel(context.Background())

		password := parsePassword(slotConf.Password)
		if password != "" {
			ctx = addBasicAuth(ctx, slotConf.User, password)
		}

		slot := &Slot{
			ID:          CK_SLOT_ID(i),
			Description: slotConf.Description,
			Sessions:    make(Sessions),
			Conf:        slotConf,
			Api:         service,
			ctx:         ctx,
			ctxCancel:   ctxCancel,
		}
		slots[i] = slot

		token, err := NewToken(slotConf.Label)
		if err != nil {
			return NewError("Initialize", err.Error(), CKR_DEVICE_ERROR)
		}
		if password == "" {
			token.Flags |= CKF_LOGIN_REQUIRED
		}
		if slotConf.Sparse {
			slot.InsertToken(token)
		} else {
			r, e := service.HealthReadyGet(ctx).Execute()
			if e != nil || r.StatusCode >= 300 {
				desc := fmt.Sprintf("Couldn't reach NetHSM of slot %d (%s): %v", i, slotConf.Label, e)
				return NewError("Initialize", desc, CKR_DEVICE_ERROR)
			}
			slot.InsertToken(token)
		}
	}
	Slots = slots
	Config = conf
	Initialized = true
	return nil
}

// GetSessionSlot returns the slot object related to a given session handle.
func GetSessionSlot(handle CK_SESSION_HANDLE) (*Slot, error) {
	for _, slot := range Slots {
		if slot.HasSession(handle) {
			return slot, nil
		}
	}
	return nil, NewError("Application.GetSessionSlot", "session not found", CKR_SESSION_HANDLE_INVALID)
}

// GetSession returns the session object related to a given handle.
func GetSession(handle CK_SESSION_HANDLE) (*Session, error) {
	slot, err := GetSessionSlot(handle)
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
func GetSlot(id CK_SLOT_ID) (*Slot, error) {
	if int(id) >= len(Slots) {
		return nil, NewError("Application.GetSlot", "index out of bounds", CKR_SLOT_ID_INVALID)
	}
	return Slots[int(id)], nil
}

// GetSlot returns the slot with the given ID.
func Finalize() error {
	for _, slot := range Slots {
		slot.ctxCancel()
		slot = nil
	}
	Initialized = false
	return nil
}

func addBasicAuth(ctx context.Context, user, password string) context.Context {
	basicAuth := api.BasicAuth{
		UserName: user,
		Password: password,
	}
	return context.WithValue(ctx, api.ContextBasicAuth, basicAuth)
}
