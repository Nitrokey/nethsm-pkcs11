# PrivateKey

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Mechanisms** | [**[]KeyMechanism**](KeyMechanism.md) |  | 
**Algorithm** | [**KeyAlgorithm**](KeyAlgorithm.md) |  | 
**Key** | [**KeyPrivateData**](KeyPrivateData.md) |  | 

## Methods

### NewPrivateKey

`func NewPrivateKey(mechanisms []KeyMechanism, algorithm KeyAlgorithm, key KeyPrivateData, ) *PrivateKey`

NewPrivateKey instantiates a new PrivateKey object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewPrivateKeyWithDefaults

`func NewPrivateKeyWithDefaults() *PrivateKey`

NewPrivateKeyWithDefaults instantiates a new PrivateKey object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetMechanisms

`func (o *PrivateKey) GetMechanisms() []KeyMechanism`

GetMechanisms returns the Mechanisms field if non-nil, zero value otherwise.

### GetMechanismsOk

`func (o *PrivateKey) GetMechanismsOk() (*[]KeyMechanism, bool)`

GetMechanismsOk returns a tuple with the Mechanisms field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetMechanisms

`func (o *PrivateKey) SetMechanisms(v []KeyMechanism)`

SetMechanisms sets Mechanisms field to given value.


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

`func (o *PrivateKey) GetKey() KeyPrivateData`

GetKey returns the Key field if non-nil, zero value otherwise.

### GetKeyOk

`func (o *PrivateKey) GetKeyOk() (*KeyPrivateData, bool)`

GetKeyOk returns a tuple with the Key field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetKey

`func (o *PrivateKey) SetKey(v KeyPrivateData)`

SetKey sets Key field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


