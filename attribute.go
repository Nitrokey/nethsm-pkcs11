package main

/*
#include <stdlib.h>
#include <string.h>
#include "pkcs11go.h"
*/
import "C"
import (
	"bytes"
	"unsafe"
)

// An attribute related to a crypto object.
type Attribute struct {
	Type  uint32 // Type of attribute
	Value []byte // Value of attribute
}

// A map of attributes
type Attributes map[uint32]*Attribute

// CToAttributes transform a C pointer of attributes into a Golang Attributes structure.
func CToAttributes(pAttributes C.CK_ATTRIBUTE_PTR, ulCount C.CK_ULONG) (Attributes, error) {
	if ulCount <= 0 {
		return nil, NewError("CToAttributes", "cannot transform: ulcount is not greater than 0", C.CKR_BUFFER_TOO_SMALL)
	}

	cAttrSlice := (*[1 << 30]C.CK_ATTRIBUTE)(unsafe.Pointer(pAttributes))[:ulCount:ulCount]

	attributes := make(Attributes, ulCount)
	for _, cAttr := range cAttrSlice {
		attr := CToAttribute(cAttr)
		attributes[attr.Type] = attr
	}
	return attributes, nil
}

// Equals returns true if the maps of attributes are equal.
func (attributes Attributes) Equals(attributes2 Attributes) bool {
	if len(attributes) != len(attributes2) {
		return false
	}
	for attrType, attribute := range attributes {
		attribute2, ok := attributes2[attrType]
		if !ok {
			return false
		}
		if !attribute.Equals(attribute2) {
			return false
		}
	}
	return true
}

// SetIfUndefined adds an attribute only if it doesn't exist
func (attributes Attributes) SetIfUndefined(attrs ...*Attribute) {
	for _, attr := range attrs {
		if _, ok := attributes[attr.Type]; !ok {
			attributes[attr.Type] = attr
		}
	}
}

// Set adds an attribute or modifies it if it already exists
func (attributes Attributes) Set(attrs ...*Attribute) {
	for _, attr := range attrs {
		attributes[attr.Type] = attr
	}
}

// CToAttribute transforms a single C attribute struct into an Attribute Golang struct.
func CToAttribute(cAttr C.CK_ATTRIBUTE) *Attribute {
	attrType := cAttr._type
	attrVal := C.GoBytes(unsafe.Pointer(cAttr.pValue), C.int(cAttr.ulValueLen))
	return &Attribute{
		Type:  uint32(attrType),
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
		cValue := C.CBytes(attribute.Value)
		cValueLen := C.CK_ULONG(len(attribute.Value))
		cDst._type = C.CK_ATTRIBUTE_TYPE(attribute.Type)
		cDst.ulValueLen = cValueLen
		C.memcpy(unsafe.Pointer(cDst.pValue), unsafe.Pointer(cValue), cValueLen)
		C.free(unsafe.Pointer(cValue))
	} else {
		return NewError("Attribute.ToC", "Buffer too small", C.CKR_BUFFER_TOO_SMALL)
	}
	return nil
}

// Equals returns true if the attributes are equal.
func (attribute *Attribute) Equals(attribute2 *Attribute) bool {
	return attribute.Type == attribute2.Type &&
		bytes.Compare(attribute.Value, attribute2.Value) == 0
}

// GetAttributeByType returns an attribute of the attributes list with the type specified in the arguments.
func (attributes Attributes) GetAttributeByType(cAttr C.CK_ATTRIBUTE_TYPE) (*Attribute, error) {
	attr, ok := attributes[uint32(cAttr)]
	if ok {
		return attr, nil
	}
	return nil, NewError("Attributes.GetAttributeByType", "attribute doesn't exist", C.CKR_ATTRIBUTE_VALUE_INVALID)
}
