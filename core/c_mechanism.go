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

// CToMechanism transforms a C mechanism into a Mechanism Golang structure.
func CToMechanism(pMechanism C.CK_MECHANISM_PTR) *Mechanism {
	cMechanism := (*C.CK_MECHANISM)(unsafe.Pointer(pMechanism))
	mechanismType := cMechanism.mechanism
	mechanismVal := C.GoBytes(unsafe.Pointer(cMechanism.pParameter), C.int(cMechanism.ulParameterLen))
	return &Mechanism{
		Type:      CK_MECHANISM_TYPE(mechanismType),
		Parameter: mechanismVal,
	}

}

// ToC transforms a Mechanism Golang Structure into a C structure.
func (mechanism *Mechanism) ToC(cDst C.CK_MECHANISM_PTR) error {
	cMechanism := (*C.CK_MECHANISM)(unsafe.Pointer(cDst))
	paramLen := C.CK_ULONG(len(mechanism.Parameter))
	if cMechanism.ulParameterLen >= paramLen {
		cMechanism.mechanism = C.CK_MECHANISM_TYPE(mechanism.Type)
		cMechanism.ulParameterLen = paramLen
		C.memcpy(unsafe.Pointer(cMechanism.pParameter), unsafe.Pointer(&mechanism.Parameter[0]), paramLen)
	} else {
		return NewError("Mechanism.ToC", "Buffer too small", CKR_BUFFER_TOO_SMALL)
	}
	return nil
}
