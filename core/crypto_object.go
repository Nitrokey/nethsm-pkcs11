package core

/*
#include "pkcs11go.h"
*/
import "C"
import (
	"bytes"
	"math"
	"unsafe"
)

// CryptoObjectType represents a type of cryptoObject.
type CryptoObjectType int

const (
	SessionObject CryptoObjectType = iota
	TokenObject
)

// A cryptoObject related to a token.
type CryptoObject struct {
	Handle     C.CK_OBJECT_HANDLE // Object's handle
	Type       CryptoObjectType   // Object type
	Attributes Attributes         // List of attributes of the object.
}

// A map of cryptoobjects
type CryptoObjects []*CryptoObject

// Transforms a C version of a cryptoobject in a CryptoObject Golang struct.
func CToCryptoObject(pAttributes C.CK_ATTRIBUTE_PTR, ulCount C.CK_ULONG) (*CryptoObject, error) {
	attrMap, err := CToAttributes(pAttributes, ulCount)
	if err != nil {
		return nil, err
	}
	var coType CryptoObjectType
	tokenAttr, ok := attrMap[C.CKA_TOKEN]
	if !ok {
		return nil, NewError("CToCryptoObject", "Token attribute not found", C.CKR_ATTRIBUTE_VALUE_INVALID)
	}
	isToken := C.CK_BBOOL(tokenAttr.Value[0])
	if isToken == C.CK_FALSE {
		coType = SessionObject
	} else {
		coType = TokenObject
	}
	object := &CryptoObject{
		Type:       coType,
		Attributes: attrMap,
	}
	return object, nil
}

// Equals returns true if the maps of crypto objects are equal.
func (objects CryptoObjects) Equals(objects2 CryptoObjects) bool {
	if len(objects) != len(objects2) {
		return false
	}
	for _, object := range objects {
		ok := false
		var object2 *CryptoObject
		for _, object2 = range objects2 {
			if object2.Handle == object.Handle {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
		if !object.Equals(object2) {
			return false
		}
	}
	return true
}

// Equals returns true if the crypto_objects are equal.
func (object *CryptoObject) Equals(object2 *CryptoObject) bool {
	return object.Handle == object2.Handle &&
		object.Attributes.Equals(object2.Attributes)
}

// https://stackoverflow.com/questions/28925179/cgo-how-to-pass-struct-array-from-c-to-go#28933938
func (object *CryptoObject) Match(attrs Attributes) bool {
	for _, theirAttr := range attrs {
		ourAttr, ok := object.Attributes[uint32(theirAttr.Type)]
		if !ok {
			return false
		} else if !bytes.Equal(ourAttr.Value, theirAttr.Value) {
			return false
		}
	}
	dbg.Printf("Matching object: %v", object)
	return true
}

// Returns an attribute with the type specified by the argument, or nil if the object does not have it.
func (object *CryptoObject) FindAttribute(attrType C.CK_ATTRIBUTE_TYPE) *Attribute {
	if attr, ok := object.Attributes[uint32(attrType)]; ok {
		return attr
	}
	return nil
}

// Copies the attributes of an object to a C pointer.
func (object *CryptoObject) CopyAttributes(pTemplate C.CK_ATTRIBUTE_PTR, ulCount C.CK_ULONG) error {
	if pTemplate == nil {
		return NewError("CryptoObject.CopyAttributes", "got NULL pointer", C.CKR_ARGUMENTS_BAD)
	}
	templateSlice := (*[math.MaxUint32]C.CK_ATTRIBUTE)(unsafe.Pointer(pTemplate))[:ulCount:ulCount]

	// dbg.Printf("templateSlice:%+v", templateSlice)

	missingAttr := false

	for i := 0; i < len(templateSlice); i++ {
		src := object.FindAttribute(templateSlice[i]._type)
		if src != nil {
			err := src.ToC(&templateSlice[i])
			if err != nil {
				return err
			}
		} else {
			missingAttr = true
			dbg.Printf("CopyAttributes: Attribute number %d does not exist: %d", i, templateSlice[i]._type)
			templateSlice[i].ulValueLen = C.CK_UNAVAILABLE_INFORMATION
		}
	}
	if missingAttr {
		return NewError("CopyAttributes", "Some attributes were missing", C.CKR_ATTRIBUTE_TYPE_INVALID)
	}
	return nil
}

// Copies the attributes of an object to a C pointer.
// func (object *CryptoObject) EditAttributes(pTemplate C.CK_ATTRIBUTE_PTR, ulCount C.CK_ULONG, session *Session) error {
// 	if pTemplate == nil {
// 		return NewError("CryptoObject.CopyAttributes", "got NULL pointer", C.CKR_ARGUMENTS_BAD)
// 	}
// 	templateSlice := (*[1 << 30]C.CK_ATTRIBUTE)(unsafe.Pointer(pTemplate))[:ulCount:ulCount]

// 	for i := 0; i < len(templateSlice); i++ {
// 		newAttr := CToAttribute(templateSlice[i])
// 		src := object.FindAttribute(templateSlice[i]._type)
// 		if src != nil {
// 			src.Value = newAttr.Value
// 		} else {
// 			object.Attributes[uint32(templateSlice[i]._type)] = newAttr
// 		}
// 	}
// 	err := session.SaveObject(object)
// 	return err
// }
