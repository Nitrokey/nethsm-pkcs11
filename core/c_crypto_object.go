package core

/*
#include "pkcs11go.h"
*/
import "C"

import (
	"math"
	"p11nethsm/log"
	"unsafe"
)

// Copies the attributes of an object to a C pointer.
func (object *CryptoObject) CopyAttributes(pTemplate C.CK_ATTRIBUTE_PTR, ulCount C.CK_ULONG) error {
	if pTemplate == nil {
		return NewError("CryptoObject.CopyAttributes", "got NULL pointer", CKR_ARGUMENTS_BAD)
	}
	templateSlice := (*[math.MaxInt32]C.CK_ATTRIBUTE)(unsafe.Pointer(pTemplate))[:ulCount:ulCount]

	//log.Debugf("template:%v", templateSlice)

	missingAttr := false

	for i := 0; i < len(templateSlice); i++ {
		src := object.FindAttribute(CK_ATTRIBUTE_TYPE(templateSlice[i]._type))
		if src != nil {
			log.Debugf("Attr: %v", src)
			err := src.ToC(&templateSlice[i])
			if err != nil {
				return err
			}
		} else {
			missingAttr = true
			log.Debugf("CopyAttributes: Attribute number %d does not exist: %v", i, CKAString(CK_ATTRIBUTE_TYPE(templateSlice[i]._type)))
			templateSlice[i].ulValueLen = C.CK_UNAVAILABLE_INFORMATION
		}
	}
	if missingAttr {
		return NewError("CopyAttributes", "Some attributes were missing", CKR_ATTRIBUTE_TYPE_INVALID)
	}
	return nil
}
