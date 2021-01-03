# InlineObject3

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Purpose** | [**KeyPurpose**](KeyPurpose.md) |  | 
**Algorithm** | [**KeyAlgorithm**](KeyAlgorithm.md) |  | 
**Length** | Pointer to **string** |  | [optional] 
**Id** | Pointer to **string** |  | [optional] 

## Methods

### NewInlineObject3

`func NewInlineObject3(purpose KeyPurpose, algorithm KeyAlgorithm, ) *InlineObject3`

NewInlineObject3 instantiates a new InlineObject3 object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewInlineObject3WithDefaults

`func NewInlineObject3WithDefaults() *InlineObject3`

NewInlineObject3WithDefaults instantiates a new InlineObject3 object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetPurpose

`func (o *InlineObject3) GetPurpose() KeyPurpose`

GetPurpose returns the Purpose field if non-nil, zero value otherwise.

### GetPurposeOk

`func (o *InlineObject3) GetPurposeOk() (*KeyPurpose, bool)`

GetPurposeOk returns a tuple with the Purpose field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetPurpose

`func (o *InlineObject3) SetPurpose(v KeyPurpose)`

SetPurpose sets Purpose field to given value.


### GetAlgorithm

`func (o *InlineObject3) GetAlgorithm() KeyAlgorithm`

GetAlgorithm returns the Algorithm field if non-nil, zero value otherwise.

### GetAlgorithmOk

`func (o *InlineObject3) GetAlgorithmOk() (*KeyAlgorithm, bool)`

GetAlgorithmOk returns a tuple with the Algorithm field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetAlgorithm

`func (o *InlineObject3) SetAlgorithm(v KeyAlgorithm)`

SetAlgorithm sets Algorithm field to given value.


### GetLength

`func (o *InlineObject3) GetLength() string`

GetLength returns the Length field if non-nil, zero value otherwise.

### GetLengthOk

`func (o *InlineObject3) GetLengthOk() (*string, bool)`

GetLengthOk returns a tuple with the Length field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLength

`func (o *InlineObject3) SetLength(v string)`

SetLength sets Length field to given value.

### HasLength

`func (o *InlineObject3) HasLength() bool`

HasLength returns a boolean if a field has been set.

### GetId

`func (o *InlineObject3) GetId() string`

GetId returns the Id field if non-nil, zero value otherwise.

### GetIdOk

`func (o *InlineObject3) GetIdOk() (*string, bool)`

GetIdOk returns a tuple with the Id field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetId

`func (o *InlineObject3) SetId(v string)`

SetId sets Id field to given value.

### HasId

`func (o *InlineObject3) HasId() bool`

HasId returns a boolean if a field has been set.


[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


