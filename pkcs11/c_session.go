package pkcs11

/*
#include "pkcs11go.h"
*/
import "C"
import (
	"p11nethsm/core"
	"unsafe"
)

// GetInfo dumps session information into a C pointer.
func GetSessionInfo(session *core.Session, pInfo C.CK_SESSION_INFO_PTR) error {
	if pInfo != nil {
		state, err := session.GetState()
		if err != nil {
			return err
		}
		info := (*C.CK_SESSION_INFO)(unsafe.Pointer(pInfo))
		info.slotID = C.CK_SLOT_ID(session.Slot.ID)
		info.state = C.CK_STATE(state)
		info.flags = C.CK_FLAGS(session.Flags)
		return nil

	} else {
		return core.NewError("Session.GetSessionInfo", "got NULL pointer", C.CKR_ARGUMENTS_BAD)
	}
}
