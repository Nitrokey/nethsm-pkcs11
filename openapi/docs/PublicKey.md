# PublicKey

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Mechanisms** | [**[]KeyMechanism**](KeyMechanism.md) |  | 
**Algorithm** | [**KeyAlgorithm**](KeyAlgorithm.md) |  | 
**Key** | [**KeyPublicData**](KeyPublicData.md) |  | 
**Operations** | **int32** |  | 

## Methods

### NewPublicKey

`func NewPublicKey(mechanisms []KeyMechanism, algorithm KeyAlgorithm, key KeyPublicData, operations int32, ) *PublicKey`

NewPublicKey instantiates a new PublicKey object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewPublicKeyWithDefaults

`func NewPublicKeyWithDefaults() *PublicKey`

NewPublicKeyWithDefaults instantiates a new PublicKey object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetMechanisms

`func (o *PublicKey) GetMechanisms() []KeyMechanism`

GetMechanisms returns the Mechanisms field if non-nil, zero value otherwise.

### GetMechanismsOk

`func (o *PublicKey) GetMechanismsOk() (*[]KeyMechanism, bool)`

GetMechanismsOk returns a tuple with the Mechanisms field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetMechanisms

`func (o *PublicKey) SetMechanisms(v []KeyMechanism)`

SetMechanisms sets Mechanisms field to given value.


### GetAlgorithm

`func (o *PublicKey) GetAlgorithm() KeyAlgorithm`

GetAlgorithm returns the Algorithm field if non-nil, zero value otherwise.

### GetAlgorithmOk

`func (o *PublicKey) GetAlgorithmOk() (*KeyAlgorithm, bool)`

GetAlgorithmOk returns a tuple with the Algorithm field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetAlgorithm

`func (o *PublicKey) SetAlgorithm(v KeyAlgorithm)`

SetAlgorithm sets Algorithm field to given value.


### GetKey

`func (o *PublicKey) GetKey() KeyPublicData`

GetKey returns the Key field if non-nil, zero value otherwise.

### GetKeyOk

`func (o *PublicKey) GetKeyOk() (*KeyPublicData, bool)`

GetKeyOk returns a tuple with the Key field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetKey

`func (o *PublicKey) SetKey(v KeyPublicData)`

SetKey sets Key field to given value.


### GetOperations

`func (o *PublicKey) GetOperations() int32`

GetOperations returns the Operations field if non-nil, zero value otherwise.

### GetOperationsOk

`func (o *PublicKey) GetOperationsOk() (*int32, bool)`

GetOperationsOk returns a tuple with the Operations field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetOperations

`func (o *PublicKey) SetOperations(v int32)`

SetOperations sets Operations field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


