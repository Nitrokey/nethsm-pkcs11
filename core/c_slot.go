package core

/*
#include <stdlib.h>
#include <string.h>
#include "pkcs11go.h"
*/
import "C"
import (
	"unsafe"
)

// GetInfo returns the slot info.
func (slot *Slot) GetInfo(pInfo C.CK_SLOT_INFO_PTR) error {
	if pInfo == nil {
		return NewError("Slot.GetInfo", "got NULL pointer", CKR_ARGUMENTS_BAD)
	}
	info := (*C.CK_SLOT_INFO)(unsafe.Pointer(pInfo))

	description := slot.description
	if slot.description == "" {
		description = "Nitrokey NetHSM"
	}
	str2Buf(description, info.slotDescription[:])
	str2Buf(libManufacturerID, info.manufacturerID[:])

	slot.flags = CKF_REMOVABLE_DEVICE
	if slot.token != nil {
		slot.flags |= CKF_TOKEN_PRESENT
	}

	pInfo.flags = C.CK_ULONG(slot.flags)
	pInfo.hardwareVersion.major = 0
	pInfo.hardwareVersion.minor = 0
	pInfo.firmwareVersion.major = 0
	pInfo.firmwareVersion.minor = 0
	return nil
}
