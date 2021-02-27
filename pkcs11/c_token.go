package pkcs11

/*
#include <stdlib.h>
#include <string.h>
#include "pkcs11go.h"
*/
import "C"

import (
	"p11nethsm/api"
	"p11nethsm/core"
	"time"
	"unsafe"
)

func GetTokenInfo(token *core.Token, pInfo C.CK_TOKEN_INFO_PTR) error {
	if pInfo == nil {
		return core.NewError("token.GetInfo", "got NULL pointer", C.CKR_ARGUMENTS_BAD)
	}
	info := (*C.CK_TOKEN_INFO)(unsafe.Pointer(pInfo))

	str2Buf(token.Label, info.label[:])

	if token.Slot == nil {
		return core.NewError("token.GetInfo", "cannot get info: token is not bound to a slot", C.CKR_ARGUMENTS_BAD)
	}

	if token.Info == nil {
		if token.Slot.Conf.Sparse {
			var info api.InfoData
			info.Product = "NetHSM"
			info.Vendor = libManufacturerID
			token.Info = &info
		} else {
			info, r, err := core.Instance.Api.InfoGet(token.ApiCtx()).Execute()
			if err != nil {
				return core.NewAPIError("token.GetInfo", "InfoGet", r, err)
			}
			token.Info = &info
		}
	}

	str2Buf(token.Info.Vendor, info.manufacturerID[:])
	str2Buf(token.Info.Product, info.model[:])
	str2Buf(serialNumber, info.serialNumber[:])

	info.flags = C.CK_ULONG(token.Flags)
	info.ulMaxSessionCount = C.CK_ULONG(core.Instance.Config.MaxSessionCount)
	info.ulSessionCount = C.CK_UNAVAILABLE_INFORMATION
	info.ulMaxRwSessionCount = 0
	info.ulRwSessionCount = C.CK_UNAVAILABLE_INFORMATION
	info.ulMaxPinLen = C.CK_ULONG(maxPinLength)
	info.ulMinPinLen = C.CK_ULONG(minPinLength)
	info.ulTotalPublicMemory = C.CK_UNAVAILABLE_INFORMATION
	info.ulFreePublicMemory = C.CK_UNAVAILABLE_INFORMATION
	info.ulTotalPrivateMemory = C.CK_UNAVAILABLE_INFORMATION
	info.ulFreePrivateMemory = C.CK_UNAVAILABLE_INFORMATION
	info.hardwareVersion.major = 0
	info.hardwareVersion.minor = 1
	info.firmwareVersion.major = 0
	info.firmwareVersion.minor = 1

	now := time.Now()
	timeStr := []byte(now.Format("20060102150405") + "00")
	C.memcpy(unsafe.Pointer(&info.utcTime[0]), unsafe.Pointer(&timeStr[0]), 16)

	return nil
}
