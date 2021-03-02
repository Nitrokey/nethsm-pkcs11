package module

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

func NewSignContext(session *Session, mechanism *Mechanism, hKey CK_OBJECT_HANDLE) (OpContext, error) {
	keyObject, err := session.GetObject(hKey)
	if err != nil {
		return nil, err
	}
	keyIDAttr := keyObject.FindAttribute(CKA_ID)
	if keyIDAttr == nil {
		return nil, NewError("NewSignContext", "object does not contain a key ID", CKR_ARGUMENTS_BAD)
	}
	mode, err := mechanism.SignMode()
	if err != nil {
		return nil, err
	}
	var ctx SignContextRSA
	ctx.session = session
	ctx.keyID = string(keyIDAttr.Value)
	ctx.data = make([]byte, 0)
	ctx.mode = mode
	if err := ctx.Init(); err != nil {
		return nil, err
	}
	return &ctx, nil
}

func NewDecryptContext(session *Session, mechanism *Mechanism, hKey CK_OBJECT_HANDLE) (OpContext, error) {
	keyObject, err := session.GetObject(hKey)
	if err != nil {
		return nil, err
	}
	keyIDAttr := keyObject.FindAttribute(CKA_ID)
	if keyIDAttr == nil {
		return nil, NewError("NewDecryptContext", "object does not contain a key ID", CKR_ARGUMENTS_BAD)
	}
	mode, err := mechanism.DecryptMode()
	if err != nil {
		return nil, err
	}
	var ctx DecryptContextRSA
	ctx.session = session
	ctx.keyID = string(keyIDAttr.Value)
	ctx.data = make([]byte, 0)
	ctx.mode = mode
	if err := ctx.Init(); err != nil {
		return nil, err
	}
	return &ctx, nil
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
