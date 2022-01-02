package module

import (
	"context"
	"encoding/base64"
	"fmt"
	"p11nethsm/api"
	"sync"
)

var nextObjectHandle = func() func() CK_OBJECT_HANDLE {
	var (
		lastObjectHandle CK_OBJECT_HANDLE
		m                sync.Mutex
	)
	return func() CK_OBJECT_HANDLE {
		m.Lock()
		defer m.Unlock()
		lastObjectHandle++
		return lastObjectHandle
	}
}()

type loginData struct {
	userType CK_USER_TYPE
	pin      string
}

// A token of the PKCS11 device.
type Token struct {
	Label      string
	keyIDs     []string
	objects    CryptoObjects
	fetchedAll bool
	Flags      uint64
	loginData  *loginData
	Slot       *Slot
	Info       *api.InfoData
	sync.RWMutex
}

// Creates a new token, but doesn't store it.
func NewToken(label string) (*Token, error) {
	if len(label) > 32 {
		return nil, NewError("objects.NewToken", "Label with more than 32 chars", CKR_ARGUMENTS_BAD)
	}
	newToken := &Token{
		Label: label,
		Flags: CKF_RNG |
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
	ctx := token.Slot.ctx
	if token.loginData != nil {
		ctx = addBasicAuth(ctx, token.Slot.Conf.User, token.loginData.pin)
	}
	return ctx
}

func (token *Token) FetchObjectsByID(keyID string) (CryptoObjects, error) {
	if objects := token.GetObjectsByID(keyID); objects != nil {
		return objects, nil
	}
	key, r, err := token.Slot.Api.KeysKeyIDGet(token.ApiCtx(), keyID).Execute()
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
		&Attribute{CKA_CLASS, ulongToArr(CKO_PRIVATE_KEY)},
		&Attribute{CKA_ID, []byte(keyID)},
		&Attribute{CKA_SUBJECT, nil},
		&Attribute{CKA_KEY_GEN_MECHANISM, ulongToArr(CK_UNAVAILABLE_INFORMATION)},
		&Attribute{CKA_LOCAL, FalseAttr},
		&Attribute{CKA_PRIVATE, TrueAttr},
		&Attribute{CKA_MODIFIABLE, FalseAttr},
		&Attribute{CKA_TOKEN, TrueAttr},
		&Attribute{CKA_ALWAYS_AUTHENTICATE, FalseAttr},
		&Attribute{CKA_SENSITIVE, TrueAttr},
		&Attribute{CKA_ALWAYS_SENSITIVE, TrueAttr},
		&Attribute{CKA_EXTRACTABLE, FalseAttr},
		&Attribute{CKA_NEVER_EXTRACTABLE, TrueAttr},
	)
	switch key.Type {
	case api.KEYTYPE_RSA:
		data, ok := key.GetKeyOk()
		if !ok {
			return nil, NewError("token.GetObjects", "Can't parse key data", CKR_DEVICE_ERROR)
		}
		modulusB64, ok := data.GetModulusOk()
		if !ok {
			return nil, NewError("token.GetObjects", "Can't parse key modulus", CKR_DEVICE_ERROR)
		}
		pubExpB64, ok := data.GetPublicExponentOk()
		if !ok {
			return nil, NewError("token.GetObjects", "Can't parse public key exponent", CKR_DEVICE_ERROR)
		}
		modulus, err := base64.StdEncoding.DecodeString(*modulusB64)
		if err != nil {
			return nil, err
		}
		pubExp, err := base64.StdEncoding.DecodeString(*pubExpB64)
		if err != nil {
			return nil, err
		}
		object.Attributes.Set(
			&Attribute{CKA_KEY_TYPE, ulongToArr(CKK_RSA)},
			&Attribute{CKA_DERIVE, FalseAttr},
			&Attribute{CKA_DECRYPT, TrueAttr},
			&Attribute{CKA_SIGN, TrueAttr},
			&Attribute{CKA_SIGN_RECOVER, TrueAttr},
			&Attribute{CKA_UNWRAP, FalseAttr},
			&Attribute{CKA_WRAP_WITH_TRUSTED, TrueAttr},
			&Attribute{CKA_MODULUS, modulus},
			&Attribute{CKA_PUBLIC_EXPONENT, pubExp},
		)
	case api.KEYTYPE_CURVE25519,
		api.KEYTYPE_EC_P224,
		api.KEYTYPE_EC_P256,
		api.KEYTYPE_EC_P384,
		api.KEYTYPE_EC_P521:
		data, err := base64.StdEncoding.DecodeString(key.Key.GetData())
		if err != nil {
			return nil, err
		}
		object.Attributes.Set(
			&Attribute{CKA_KEY_TYPE, ulongToArr(CKK_EC)},
			&Attribute{CKA_DERIVE, TrueAttr},
			&Attribute{CKA_DECRYPT, FalseAttr},
			&Attribute{CKA_SIGN, TrueAttr},
			&Attribute{CKA_SIGN_RECOVER, TrueAttr},
			&Attribute{CKA_UNWRAP, FalseAttr},
			&Attribute{CKA_WRAP_WITH_TRUSTED, TrueAttr},
			&Attribute{CKA_EC_POINT, data},
		)
	default:
		return nil, NewError("token.GetObjects", "Invalid algorithm", CKR_DEVICE_ERROR)
	}
	token.AddObject(object)
	return CryptoObjects{object}, nil
}

func (token *Token) FetchKeyIDs() ([]string, error) {
	token.Lock()
	defer token.Unlock()
	if token.keyIDs == nil {
		keys, r, err := token.Slot.Api.KeysGet(token.ApiCtx()).Execute()
		if err != nil {
			err = NewAPIError("token.FetchKeyIDs", "KeysGet", r, err)
			return nil, err
		}
		ids := make([]string, len(keys))
		for i := range keys {
			ids[i] = keys[i].GetKey()
		}
		token.keyIDs = ids
	}
	return token.keyIDs, nil // no need to copy, because it will not change
}

func (token *Token) FetchObjects(keyID string) (CryptoObjects, error) {
	if keyID != "" {
		return token.FetchObjectsByID(keyID)
	}
	if !token.fetchedAll {
		ids, err := token.FetchKeyIDs()
		if err != nil {
			return nil, err
		}
		for _, id := range ids {
			_, err := token.FetchObjectsByID(id)
			if err != nil {
				return nil, err
			}
		}
		token.fetchedAll = true
	}
	return token.objects, nil // no need to copy, because it will not change
}

func (token *Token) CheckUserPin(pin string) error {
	authCtx := addBasicAuth(token.ApiCtx(), token.Slot.Conf.User, pin)
	_, r, err := token.Slot.Api.KeysGet(authCtx).Execute()
	if err != nil {
		if r.StatusCode == 401 {
			return NewError("Login", "Authorization failed", CKR_PIN_INCORRECT)
		}
		return NewAPIError("Login", "Login failed", r, err)
	}
	return nil
}

// Logs into the token, or returns an error if something goes wrong.
func (token *Token) Login(userType CK_USER_TYPE, pin string) error {
	if userType != CKU_CONTEXT_SPECIFIC && token.loginData != nil &&
		token.loginData.userType == userType {
		return NewError("token.Login", "another user already logged in", CKR_USER_ALREADY_LOGGED_IN)
	}

	switch userType {
	case CKU_USER:
		if !token.Slot.Conf.Sparse {
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
	token.objects = append(token.objects, object)
}

// Returns the label of the token (should remove. Label is a public property!
func (token *Token) GetLabel() string {
	return token.Label
}

// Returns an object that uses the handle provided.
func (token *Token) GetObject(handle CK_OBJECT_HANDLE) (*CryptoObject, error) {
	token.RLock()
	defer token.RUnlock()
	for _, object := range token.objects {
		if object.Handle == handle {
			return object, nil
		}
	}
	return nil, NewError("Token.GetObject", fmt.Sprintf("object not found with handle %v", handle), CKR_OBJECT_HANDLE_INVALID)
}

func (token *Token) GetObjectsByID(keyID string) CryptoObjects {
	token.RLock()
	defer token.RUnlock()
	var objects CryptoObjects
	for _, object := range token.objects {
		if object.ID == keyID {
			objects = append(objects, object)
		}
	}
	return objects
}
