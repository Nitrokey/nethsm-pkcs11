# KeyGenerateRequestData

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Mechanisms** | [**[]KeyMechanism**](KeyMechanism.md) |  | 
**Type** | [**KeyType**](KeyType.md) |  | 
**Length** | Pointer to **int32** |  | [optional] 
**Id** | Pointer to **string** |  | [optional] 

## Methods

### NewKeyGenerateRequestData

`func NewKeyGenerateRequestData(mechanisms []KeyMechanism, type_ KeyType, ) *KeyGenerateRequestData`

NewKeyGenerateRequestData instantiates a new KeyGenerateRequestData object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewKeyGenerateRequestDataWithDefaults

`func NewKeyGenerateRequestDataWithDefaults() *KeyGenerateRequestData`

NewKeyGenerateRequestDataWithDefaults instantiates a new KeyGenerateRequestData object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetMechanisms

`func (o *KeyGenerateRequestData) GetMechanisms() []KeyMechanism`

GetMechanisms returns the Mechanisms field if non-nil, zero value otherwise.

### GetMechanismsOk

`func (o *KeyGenerateRequestData) GetMechanismsOk() (*[]KeyMechanism, bool)`

GetMechanismsOk returns a tuple with the Mechanisms field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetMechanisms

`func (o *KeyGenerateRequestData) SetMechanisms(v []KeyMechanism)`

SetMechanisms sets Mechanisms field to given value.


### GetType

`func (o *KeyGenerateRequestData) GetType() KeyType`

GetType returns the Type field if non-nil, zero value otherwise.

### GetTypeOk

`func (o *KeyGenerateRequestData) GetTypeOk() (*KeyType, bool)`

GetTypeOk returns a tuple with the Type field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetType

`func (o *KeyGenerateRequestData) SetType(v KeyType)`

SetType sets Type field to given value.


### GetLength

`func (o *KeyGenerateRequestData) GetLength() int32`

GetLength returns the Length field if non-nil, zero value otherwise.

### GetLengthOk

`func (o *KeyGenerateRequestData) GetLengthOk() (*int32, bool)`

GetLengthOk returns a tuple with the Length field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLength

`func (o *KeyGenerateRequestData) SetLength(v int32)`

SetLength sets Length field to given value.

### HasLength

`func (o *KeyGenerateRequestData) HasLength() bool`

HasLength returns a boolean if a field has been set.

### GetId

`func (o *KeyGenerateRequestData) GetId() string`

GetId returns the Id field if non-nil, zero value otherwise.

### GetIdOk

`func (o *KeyGenerateRequestData) GetIdOk() (*string, bool)`

GetIdOk returns a tuple with the Id field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetId

`func (o *KeyGenerateRequestData) SetId(v string)`

SetId sets Id field to given value.

### HasId

`func (o *KeyGenerateRequestData) HasId() bool`

HasId returns a boolean if a field has been set.


[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


