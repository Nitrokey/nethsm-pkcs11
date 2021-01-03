# PrivateKey

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Purpose** | [**KeyPurpose**](KeyPurpose.md) |  | 
**Algorithm** | [**KeyAlgorithm**](KeyAlgorithm.md) |  | 
**Key** | [**PrivateKeyKey**](PrivateKey_key.md) |  | 

## Methods

### NewPrivateKey

`func NewPrivateKey(purpose KeyPurpose, algorithm KeyAlgorithm, key PrivateKeyKey, ) *PrivateKey`

NewPrivateKey instantiates a new PrivateKey object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewPrivateKeyWithDefaults

`func NewPrivateKeyWithDefaults() *PrivateKey`

NewPrivateKeyWithDefaults instantiates a new PrivateKey object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetPurpose

`func (o *PrivateKey) GetPurpose() KeyPurpose`

GetPurpose returns the Purpose field if non-nil, zero value otherwise.

### GetPurposeOk

`func (o *PrivateKey) GetPurposeOk() (*KeyPurpose, bool)`

GetPurposeOk returns a tuple with the Purpose field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetPurpose

`func (o *PrivateKey) SetPurpose(v KeyPurpose)`

SetPurpose sets Purpose field to given value.


### GetAlgorithm

`func (o *PrivateKey) GetAlgorithm() KeyAlgorithm`

GetAlgorithm returns the Algorithm field if non-nil, zero value otherwise.

### GetAlgorithmOk

`func (o *PrivateKey) GetAlgorithmOk() (*KeyAlgorithm, bool)`

GetAlgorithmOk returns a tuple with the Algorithm field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetAlgorithm

`func (o *PrivateKey) SetAlgorithm(v KeyAlgorithm)`

SetAlgorithm sets Algorithm field to given value.


### GetKey

`func (o *PrivateKey) GetKey() PrivateKeyKey`

GetKey returns the Key field if non-nil, zero value otherwise.

### GetKeyOk

`func (o *PrivateKey) GetKeyOk() (*PrivateKeyKey, bool)`

GetKeyOk returns a tuple with the Key field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetKey

`func (o *PrivateKey) SetKey(v PrivateKeyKey)`

SetKey sets Key field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


