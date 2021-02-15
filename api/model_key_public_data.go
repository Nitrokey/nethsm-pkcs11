/*
 * NetHSM
 *
 * All endpoints expect exactly the specified JSON. Additional properties will cause a Bad Request Error (400). All HTTP errors contain a JSON structure with an explanation of type string. All <a href=\"https://tools.ietf.org/html/rfc4648#section-4\">base64</a> encoded values are Big Endian.
 *
 * API version: v1
 */

// Code generated by OpenAPI Generator (https://openapi-generator.tech); DO NOT EDIT.

package api

import (
	"encoding/json"
)

// KeyPublicData struct for KeyPublicData
type KeyPublicData struct {
	Modulus *string `json:"modulus,omitempty"`
	PublicExponent *string `json:"publicExponent,omitempty"`
	Data *string `json:"data,omitempty"`
	AdditionalProperties map[string]interface{}
}

type _KeyPublicData KeyPublicData

// NewKeyPublicData instantiates a new KeyPublicData object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewKeyPublicData() *KeyPublicData {
	this := KeyPublicData{}
	return &this
}

// NewKeyPublicDataWithDefaults instantiates a new KeyPublicData object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewKeyPublicDataWithDefaults() *KeyPublicData {
	this := KeyPublicData{}
	return &this
}

// GetModulus returns the Modulus field value if set, zero value otherwise.
func (o *KeyPublicData) GetModulus() string {
	if o == nil || o.Modulus == nil {
		var ret string
		return ret
	}
	return *o.Modulus
}

// GetModulusOk returns a tuple with the Modulus field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *KeyPublicData) GetModulusOk() (*string, bool) {
	if o == nil || o.Modulus == nil {
		return nil, false
	}
	return o.Modulus, true
}

// HasModulus returns a boolean if a field has been set.
func (o *KeyPublicData) HasModulus() bool {
	if o != nil && o.Modulus != nil {
		return true
	}

	return false
}

// SetModulus gets a reference to the given string and assigns it to the Modulus field.
func (o *KeyPublicData) SetModulus(v string) {
	o.Modulus = &v
}

// GetPublicExponent returns the PublicExponent field value if set, zero value otherwise.
func (o *KeyPublicData) GetPublicExponent() string {
	if o == nil || o.PublicExponent == nil {
		var ret string
		return ret
	}
	return *o.PublicExponent
}

// GetPublicExponentOk returns a tuple with the PublicExponent field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *KeyPublicData) GetPublicExponentOk() (*string, bool) {
	if o == nil || o.PublicExponent == nil {
		return nil, false
	}
	return o.PublicExponent, true
}

// HasPublicExponent returns a boolean if a field has been set.
func (o *KeyPublicData) HasPublicExponent() bool {
	if o != nil && o.PublicExponent != nil {
		return true
	}

	return false
}

// SetPublicExponent gets a reference to the given string and assigns it to the PublicExponent field.
func (o *KeyPublicData) SetPublicExponent(v string) {
	o.PublicExponent = &v
}

// GetData returns the Data field value if set, zero value otherwise.
func (o *KeyPublicData) GetData() string {
	if o == nil || o.Data == nil {
		var ret string
		return ret
	}
	return *o.Data
}

// GetDataOk returns a tuple with the Data field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *KeyPublicData) GetDataOk() (*string, bool) {
	if o == nil || o.Data == nil {
		return nil, false
	}
	return o.Data, true
}

// HasData returns a boolean if a field has been set.
func (o *KeyPublicData) HasData() bool {
	if o != nil && o.Data != nil {
		return true
	}

	return false
}

// SetData gets a reference to the given string and assigns it to the Data field.
func (o *KeyPublicData) SetData(v string) {
	o.Data = &v
}

func (o KeyPublicData) MarshalJSON() ([]byte, error) {
	toSerialize := map[string]interface{}{}
	if o.Modulus != nil {
		toSerialize["modulus"] = o.Modulus
	}
	if o.PublicExponent != nil {
		toSerialize["publicExponent"] = o.PublicExponent
	}
	if o.Data != nil {
		toSerialize["data"] = o.Data
	}

	for key, value := range o.AdditionalProperties {
		toSerialize[key] = value
	}

	return json.Marshal(toSerialize)
}

func (o *KeyPublicData) UnmarshalJSON(bytes []byte) (err error) {
	varKeyPublicData := _KeyPublicData{}

	if err = json.Unmarshal(bytes, &varKeyPublicData); err == nil {
		*o = KeyPublicData(varKeyPublicData)
	}

	additionalProperties := make(map[string]interface{})

	if err = json.Unmarshal(bytes, &additionalProperties); err == nil {
		delete(additionalProperties, "modulus")
		delete(additionalProperties, "publicExponent")
		delete(additionalProperties, "data")
		o.AdditionalProperties = additionalProperties
	}

	return err
}

type NullableKeyPublicData struct {
	value *KeyPublicData
	isSet bool
}

func (v NullableKeyPublicData) Get() *KeyPublicData {
	return v.value
}

func (v *NullableKeyPublicData) Set(val *KeyPublicData) {
	v.value = val
	v.isSet = true
}

func (v NullableKeyPublicData) IsSet() bool {
	return v.isSet
}

func (v *NullableKeyPublicData) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableKeyPublicData(val *KeyPublicData) *NullableKeyPublicData {
	return &NullableKeyPublicData{value: val, isSet: true}
}

func (v NullableKeyPublicData) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableKeyPublicData) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}

