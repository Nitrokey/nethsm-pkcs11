package pkcs11

/*
#include <stdlib.h>
#include <string.h>
#include "pkcs11go.h"
*/
import "C"
import (
	"p11nethsm/core"
	"unsafe"
)

// GetInfo returns the slot info.
func GetSlotInfo(slot *core.Slot, pInfo C.CK_SLOT_INFO_PTR) error {
	if pInfo == nil {
		return core.NewError("Slot.GetInfo", "got NULL pointer", C.CKR_ARGUMENTS_BAD)
	}
	info := (*C.CK_SLOT_INFO)(unsafe.Pointer(pInfo))

	description := slot.Description
	if description == "" {
		description = "Nitrokey NetHSM"
	}
	str2Buf(description, info.slotDescription[:])
	str2Buf(libManufacturerID, info.manufacturerID[:])

	slot.Flags = C.CKF_REMOVABLE_DEVICE
	if slot.Token != nil {
		slot.Flags |= C.CKF_TOKEN_PRESENT
	}

	pInfo.flags = C.CK_ULONG(slot.Flags)
	pInfo.hardwareVersion.major = 0
	pInfo.hardwareVersion.minor = 0
	pInfo.firmwareVersion.major = 0
	pInfo.firmwareVersion.minor = 0
	return nil
}
