package core

/*
#include <stdlib.h>
#include <string.h>
#include "pkcs11go.h"
*/
import "C"

import (
	"p11nethsm/api"
	"time"
	"unsafe"
)

func (token *Token) GetInfo(pInfo C.CK_TOKEN_INFO_PTR) error {
	if pInfo == nil {
		return NewError("token.GetInfo", "got NULL pointer", CKR_ARGUMENTS_BAD)
	}
	info := (*C.CK_TOKEN_INFO)(unsafe.Pointer(pInfo))

	str2Buf(token.Label, info.label[:])

	if token.slot == nil {
		return NewError("token.GetInfo", "cannot get info: token is not bound to a slot", CKR_ARGUMENTS_BAD)
	}

	if token.info == nil {
		if token.slot.conf.Sparse {
			var info api.InfoData
			info.Product = "NetHSM"
			info.Vendor = libManufacturerID
			token.info = &info
		} else {
			info, r, err := App.Api.InfoGet(token.ApiCtx()).Execute()
			if err != nil {
				return NewAPIError("token.GetInfo", "InfoGet", r, err)
			}
			token.info = &info
		}
	}

	str2Buf(token.info.Vendor, info.manufacturerID[:])
	str2Buf(token.info.Product, info.model[:])
	str2Buf(serialNumber, info.serialNumber[:])

	info.flags = C.CK_ULONG(token.tokenFlags)
	info.ulMaxSessionCount = C.CK_ULONG(App.Config.MaxSessionCount)
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
