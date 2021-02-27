package module

import (
	"bytes"
	"p11nethsm/log"
)

// A cryptoObject related to a token.
type CryptoObject struct {
	Handle     CK_OBJECT_HANDLE // Object's handle
	ID         string
	Attributes Attributes // List of attributes of the object.
}

// A map of cryptoobjects
type CryptoObjects []*CryptoObject

// Transforms a C version of a cryptoobject in a CryptoObject Golang struct.
// func CToCryptoObject(pAttributes C.CK_ATTRIBUTE_PTR, ulCount C.CK_ULONG) (*CryptoObject, error) {
// 	attrMap, err := CToAttributes(pAttributes, ulCount)
// 	if err != nil {
// 		return nil, err
// 	}
// 	var coType CryptoObjectType
// 	tokenAttr, ok := attrMap[CKA_TOKEN]
// 	if !ok {
// 		return nil, NewError("CToCryptoObject", "Token attribute not found", CKR_ATTRIBUTE_VALUE_INVALID)
// 	}
// 	isToken := C.CK_BBOOL(tokenAttr.Value[0])
// 	if isToken == CK_FALSE {
// 		coType = SessionObject
// 	} else {
// 		coType = TokenObject
// 	}
// 	object := &CryptoObject{
// 		Type:       coType,
// 		Attributes: attrMap,
// 	}
// 	return object, nil
// }

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
		ourAttr, ok := object.Attributes[theirAttr.Type]
		if !ok {
			return false
		} else if !bytes.Equal(ourAttr.Value, theirAttr.Value) {
			return false
		}
	}
	log.Debugf("Matching object: %v", object)
	return true
}

// Returns an attribute with the type specified by the argument, or nil if the object does not have it.
func (object *CryptoObject) FindAttribute(attrType CK_ATTRIBUTE_TYPE) *Attribute {
	if attr, ok := object.Attributes[attrType]; ok {
		return attr
	}
	return nil
}
