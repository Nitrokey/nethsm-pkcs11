package pkcs11

/*
#include <stdlib.h>
#include <string.h>
#include "pkcs11go.h"
*/
import "C"

import (
	"fmt"
	"math"
	"p11nethsm/api"
	"p11nethsm/log"
	"p11nethsm/module"
	"time"
	"unsafe"
)

const (
	libManufacturerID = "Nitrokey GmbH"
	libDescription    = "NetHSM PKCS#11 module"
	libVersionMajor   = 0
	libVersionMinor   = 1
	minPinLength      = 3
	maxPinLength      = 256
	serialNumber      = "0"
)

// assert that go module.CK_ULONG has correct size
const _ = byte(C.sizeof_CK_ULONG-unsafe.Sizeof(module.CK_ULONG(0))) << 8

// Extracts the Return Value from an error, and logs it.
func errorToRV(err error) C.CK_RV {
	if err == nil {
		return C.CKR_OK
	}
	// log.Debugf("%+v\n", err)
	switch err := err.(type) {
	case module.P11Error:
		log.Errorf("[%s] %s [Code %d]\n", err.Who, err.Description, int(err.Code))
		return C.CK_RV(err.Code)
	default:
		log.Errorf("[General error] %+v\n", err)
		return C.CKR_GENERAL_ERROR
	}
}

func (v C.CK_ATTRIBUTE) String() string {
	val := (*[math.MaxInt32]byte)(unsafe.Pointer(v.pValue))[:int(v.ulValueLen):int(v.ulValueLen)]
	return fmt.Sprintf("%v: %v/\"%v\"", module.CKAString(module.CK_ATTRIBUTE_TYPE((v._type))), val, string(val))
}

// CToAttributes transform a C pointer of attributes into a Golang Attributes structure.
func cToAttributes(pAttributes C.CK_ATTRIBUTE_PTR, ulCount C.CK_ULONG) (module.Attributes, error) {
	if ulCount <= 0 {
		return nil, module.NewError("CToAttributes", "cannot transform: ulcount is not greater than 0", C.CKR_BUFFER_TOO_SMALL)
	}

	cAttrSlice := (*[math.MaxInt32]C.CK_ATTRIBUTE)(unsafe.Pointer(pAttributes))[:ulCount:ulCount]

	attributes := make(module.Attributes, ulCount)
	for _, cAttr := range cAttrSlice {
		attr := cToAttribute(cAttr)
		attributes[attr.Type] = attr
	}
	return attributes, nil
}

// CToAttribute transforms a single C attribute struct into an Attribute Golang struct.
func cToAttribute(cAttr C.CK_ATTRIBUTE) *module.Attribute {
	attrVal := C.GoBytes(unsafe.Pointer(cAttr.pValue), C.int(cAttr.ulValueLen))
	return &module.Attribute{
		Type:  module.CK_ATTRIBUTE_TYPE(cAttr._type),
		Value: attrVal,
	}
}

// ToC copies an attribute into a C pointer of attribute struct.
func attributeToC(attribute *module.Attribute, cDst C.CK_ATTRIBUTE_PTR) error {
	if cDst.pValue == nil {
		cDst.ulValueLen = C.CK_ULONG(len(attribute.Value))
		return nil
	}
	if cDst.ulValueLen >= C.CK_ULONG(len(attribute.Value)) {
		valueLen := C.CK_ULONG(len(attribute.Value))
		cDst._type = C.CK_ATTRIBUTE_TYPE(attribute.Type)
		cDst.ulValueLen = valueLen
		if attribute.Value != nil {
			C.memcpy(unsafe.Pointer(cDst.pValue), unsafe.Pointer(&attribute.Value[0]), valueLen)
		}
	} else {
		return module.NewError("AttributeToC", fmt.Sprintf("Buffer too small: %d, need %d", cDst.ulValueLen, len(attribute.Value)), C.CKR_BUFFER_TOO_SMALL)
	}
	return nil
}

// Copies the attributes of an object to a C pointer.
func copyAttributes(object *module.CryptoObject, pTemplate C.CK_ATTRIBUTE_PTR, ulCount C.CK_ULONG) error {
	if pTemplate == nil {
		return module.NewError("CryptoObject.CopyAttributes", "got NULL pointer", C.CKR_ARGUMENTS_BAD)
	}
	templateSlice := (*[math.MaxInt32]C.CK_ATTRIBUTE)(unsafe.Pointer(pTemplate))[:ulCount:ulCount]

	// log.Debugf("template:%v", templateSlice)

	missingAttr := false

	for i := 0; i < len(templateSlice); i++ {
		src := object.FindAttribute(module.CK_ATTRIBUTE_TYPE(templateSlice[i]._type))
		if src != nil {
			log.Debugf("Attr: %v", src)
			err := attributeToC(src, &templateSlice[i])
			if err != nil {
				return err
			}
		} else {
			missingAttr = true
			log.Debugf("CopyAttributes: Attribute number %d does not exist: %v", i, module.CKAString(module.CK_ATTRIBUTE_TYPE(templateSlice[i]._type)))
			templateSlice[i].ulValueLen = C.CK_UNAVAILABLE_INFORMATION
		}
	}
	if missingAttr {
		return module.NewError("CopyAttributes", "Some attributes were missing", C.CKR_ATTRIBUTE_TYPE_INVALID)
	}
	return nil
}

// CToMechanism transforms a C mechanism into a Mechanism Golang structure.
func cToMechanism(pMechanism C.CK_MECHANISM_PTR) *module.Mechanism {
	cMechanism := (*C.CK_MECHANISM)(unsafe.Pointer(pMechanism))
	mechanismType := cMechanism.mechanism
	mechanismVal := C.GoBytes(unsafe.Pointer(cMechanism.pParameter), C.int(cMechanism.ulParameterLen))
	return &module.Mechanism{
		Type:      module.CK_MECHANISM_TYPE(mechanismType),
		Parameter: mechanismVal,
	}
}

// ToC transforms a Mechanism Golang Structure into a C structure.
// func mechanismToC(mechanism *module.Mechanism, cDst C.CK_MECHANISM_PTR) error {
// 	cMechanism := (*C.CK_MECHANISM)(unsafe.Pointer(cDst))
// 	paramLen := C.CK_ULONG(len(mechanism.Parameter))
// 	if cMechanism.ulParameterLen >= paramLen {
// 		cMechanism.mechanism = C.CK_MECHANISM_TYPE(mechanism.Type)
// 		cMechanism.ulParameterLen = paramLen
// 		C.memcpy(unsafe.Pointer(cMechanism.pParameter), unsafe.Pointer(&mechanism.Parameter[0]), paramLen)
// 	} else {
// 		return module.NewError("Mechanism.ToC", "Buffer too small", C.CKR_BUFFER_TOO_SMALL)
// 	}
// 	return nil
// }

// GetInfo dumps session information into a C pointer.
func getSessionInfo(session *module.Session, pInfo C.CK_SESSION_INFO_PTR) error {
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
		return module.NewError("Session.GetSessionInfo", "got NULL pointer", C.CKR_ARGUMENTS_BAD)
	}
}

// GetInfo returns the slot info.
func getSlotInfo(slot *module.Slot, pInfo C.CK_SLOT_INFO_PTR) error {
	if pInfo == nil {
		return module.NewError("Slot.GetInfo", "got NULL pointer", C.CKR_ARGUMENTS_BAD)
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

func getTokenInfo(token *module.Token, pInfo C.CK_TOKEN_INFO_PTR) error {
	if pInfo == nil {
		return module.NewError("token.GetInfo", "got NULL pointer", C.CKR_ARGUMENTS_BAD)
	}
	info := (*C.CK_TOKEN_INFO)(unsafe.Pointer(pInfo))

	str2Buf(token.Label, info.label[:])

	if token.Slot == nil {
		return module.NewError("token.GetInfo", "cannot get info: token is not bound to a slot", C.CKR_ARGUMENTS_BAD)
	}

	if token.Info == nil {
		if token.Slot.Conf.Sparse {
			var info api.InfoData
			info.Product = "NetHSM"
			info.Vendor = libManufacturerID
			token.Info = &info
		} else {
			info, r, err := token.Slot.Api.InfoGet(token.ApiCtx()).Execute()
			if err != nil {
				return module.NewAPIError("token.GetInfo", "InfoGet", r, err)
			}
			token.Info = &info
		}
	}

	str2Buf(token.Info.Vendor, info.manufacturerID[:])
	str2Buf(token.Info.Product, info.model[:])
	str2Buf(serialNumber, info.serialNumber[:])

	info.flags = C.CK_ULONG(token.Flags)
	info.ulMaxSessionCount = C.CK_ULONG(module.Config.MaxSessionCount)
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
