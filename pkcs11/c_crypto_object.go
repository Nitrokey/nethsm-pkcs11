package pkcs11

/*
#include "pkcs11go.h"
*/
import "C"

import (
	"math"
	"p11nethsm/core"
	"p11nethsm/log"
	"unsafe"
)

// Copies the attributes of an object to a C pointer.
func CopyAttributes(object *core.CryptoObject, pTemplate C.CK_ATTRIBUTE_PTR, ulCount C.CK_ULONG) error {
	if pTemplate == nil {
		return core.NewError("CryptoObject.CopyAttributes", "got NULL pointer", C.CKR_ARGUMENTS_BAD)
	}
	templateSlice := (*[math.MaxInt32]C.CK_ATTRIBUTE)(unsafe.Pointer(pTemplate))[:ulCount:ulCount]

	//log.Debugf("template:%v", templateSlice)

	missingAttr := false

	for i := 0; i < len(templateSlice); i++ {
		src := object.FindAttribute(core.CK_ATTRIBUTE_TYPE(templateSlice[i]._type))
		if src != nil {
			log.Debugf("Attr: %v", src)
			err := AttributeToC(src, &templateSlice[i])
			if err != nil {
				return err
			}
		} else {
			missingAttr = true
			log.Debugf("CopyAttributes: Attribute number %d does not exist: %v", i, core.CKAString(core.CK_ATTRIBUTE_TYPE(templateSlice[i]._type)))
			templateSlice[i].ulValueLen = C.CK_UNAVAILABLE_INFORMATION
		}
	}
	if missingAttr {
		return core.NewError("CopyAttributes", "Some attributes were missing", C.CKR_ATTRIBUTE_TYPE_INVALID)
	}
	return nil
}
