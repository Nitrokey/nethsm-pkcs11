package core

/*
#include <stdlib.h>
#include <string.h>
#include "pkcs11go.h"
*/
import "C"
import (
	"fmt"
	"math"
	"unsafe"
)

func (v C.CK_ATTRIBUTE) String() string {
	val := (*[math.MaxInt32]byte)(unsafe.Pointer(v.pValue))[:int(v.ulValueLen):int(v.ulValueLen)]
	return fmt.Sprintf("%v: %v/\"%v\"", CKAString(CK_ATTRIBUTE_TYPE((v._type))), val, string(val))
}

// CToAttributes transform a C pointer of attributes into a Golang Attributes structure.
func CToAttributes(pAttributes C.CK_ATTRIBUTE_PTR, ulCount C.CK_ULONG) (Attributes, error) {
	if ulCount <= 0 {
		return nil, NewError("CToAttributes", "cannot transform: ulcount is not greater than 0", CKR_BUFFER_TOO_SMALL)
	}

	cAttrSlice := (*[math.MaxInt32]C.CK_ATTRIBUTE)(unsafe.Pointer(pAttributes))[:ulCount:ulCount]

	attributes := make(Attributes, ulCount)
	for _, cAttr := range cAttrSlice {
		attr := CToAttribute(cAttr)
		attributes[attr.Type] = attr
	}
	return attributes, nil
}

// CToAttribute transforms a single C attribute struct into an Attribute Golang struct.
func CToAttribute(cAttr C.CK_ATTRIBUTE) *Attribute {
	attrType := cAttr._type
	attrVal := C.GoBytes(unsafe.Pointer(cAttr.pValue), C.int(cAttr.ulValueLen))
	return &Attribute{
		Type:  CK_ATTRIBUTE_TYPE((attrType)),
		Value: attrVal,
	}
}

// ToC copies an attribute into a C pointer of attribute struct.
func (attribute *Attribute) ToC(cDst C.CK_ATTRIBUTE_PTR) error {
	if cDst.pValue == nil {
		cDst.ulValueLen = C.CK_ULONG(len(attribute.Value))
		return nil
	}
	if cDst.ulValueLen >= C.CK_ULONG(len(attribute.Value)) {
		valueLen := C.CK_ULONG(len(attribute.Value))
		cDst._type = C.CK_ATTRIBUTE_TYPE(attribute.Type)
		cDst.ulValueLen = valueLen
		C.memcpy(unsafe.Pointer(cDst.pValue), unsafe.Pointer(&attribute.Value[0]), valueLen)
	} else {
		return NewError("Attribute.ToC", fmt.Sprintf("Buffer too small: %d, need %d", cDst.ulValueLen, len(attribute.Value)), CKR_BUFFER_TOO_SMALL)
	}
	return nil
}
