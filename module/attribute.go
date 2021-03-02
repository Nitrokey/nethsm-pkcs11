package module

import (
	"bytes"
	"fmt"
)

// An attribute related to a crypto object.
type Attribute struct {
	Type  CK_ATTRIBUTE_TYPE // Type of attribute
	Value []byte            // Value of attribute
}

func (v Attribute) String() string {
	return fmt.Sprintf("%v: %+q", CKAString(v.Type), string(v.Value))
}

// A map of attributes
type Attributes map[CK_ATTRIBUTE_TYPE]*Attribute

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

// Equals returns true if the attributes are equal.
func (attribute *Attribute) Equals(attribute2 *Attribute) bool {
	return attribute.Type == attribute2.Type &&
		bytes.Equal(attribute.Value, attribute2.Value)
}

// GetAttributeByType returns an attribute of the attributes list with the type specified in the arguments.
func (attributes Attributes) GetAttributeByType(aType CK_ATTRIBUTE_TYPE) (*Attribute, error) {
	attr, ok := attributes[aType]
	if ok {
		return attr, nil
	}
	return nil, NewError("Attributes.GetAttributeByType", "attribute doesn't exist", CKR_ATTRIBUTE_VALUE_INVALID)
}
