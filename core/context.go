package core

import (
	"unsafe"
)

// OpContext represents a structure which groups parameters that allow to sign
// or decrypt
// a document.
type OpContext interface {
	Init() error
	ResultLength() int
	Update(data []byte) error
	Final() ([]byte, error)
	Initialized() bool
}

func NewSignContext(session *Session, mechanism *Mechanism, hKey CK_OBJECT_HANDLE) (context OpContext, err error) {
	keyObject, err := session.GetObject(hKey)
	if err != nil {
		return nil, err
	}
	keyIDAttr := keyObject.FindAttribute(CKA_ID)
	if keyIDAttr == nil {
		return nil, NewError("NewSignContext", "object does not contain a key ID", CKR_ARGUMENTS_BAD)
	}
	switch mechanism.Type {
	case CKM_RSA_PKCS, CKM_MD5_RSA_PKCS, CKM_SHA1_RSA_PKCS, CKM_SHA256_RSA_PKCS, CKM_SHA384_RSA_PKCS, CKM_SHA512_RSA_PKCS, CKM_RSA_PKCS_PSS, CKM_SHA1_RSA_PKCS_PSS, CKM_SHA256_RSA_PKCS_PSS, CKM_SHA384_RSA_PKCS_PSS, CKM_SHA512_RSA_PKCS_PSS:
		c := &SignContextRSA{OpContextRSA{
			session:   session,
			keyID:     string(keyIDAttr.Value),
			mechanism: mechanism,
			data:      make([]byte, 0),
		}}
		if err := c.Init(); err != nil {
			return nil, err
		}
		context = c
	default:
		err = NewError("NewSignContext", "sign mechanism invalid", CKR_MECHANISM_INVALID)
		return nil, err
	}
	return context, nil
}

func NewDecryptContext(session *Session, mechanism *Mechanism, hKey CK_OBJECT_HANDLE) (context OpContext, err error) {
	keyObject, err := session.GetObject(hKey)
	if err != nil {
		return nil, err
	}
	keyIDAttr := keyObject.FindAttribute(CKA_ID)
	if keyIDAttr == nil {
		return nil, NewError("NewDecryptContext", "object does not contain a key ID", CKR_ARGUMENTS_BAD)
	}
	switch mechanism.Type {
	case CKM_RSA_X_509, CKM_RSA_PKCS, CKM_RSA_PKCS_OAEP:
		c := &DecryptContextRSA{OpContextRSA{
			session:   session,
			keyID:     string(keyIDAttr.Value),
			mechanism: mechanism,
			data:      make([]byte, 0),
		}}
		if err := c.Init(); err != nil {
			return nil, err
		}
		context = c
	default:
		err = NewError("NewDecryptContext", "decrypt mechanism invalid", CKR_MECHANISM_INVALID)
		return nil, err
	}
	return context, nil
}

func ulongToArr(n CK_ULONG) []byte {
	const size = unsafe.Sizeof(n)
	arr := make([]byte, size)
	for i := range arr {
		arr[i] = byte(n)
		n >>= 8
	}
	return arr
}
