# SignRequestData

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Mode** | [**SignMode**](SignMode.md) |  | 
**Message** | **string** |  | 

## Methods

### NewSignRequestData

`func NewSignRequestData(mode SignMode, message string, ) *SignRequestData`

NewSignRequestData instantiates a new SignRequestData object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewSignRequestDataWithDefaults

`func NewSignRequestDataWithDefaults() *SignRequestData`

NewSignRequestDataWithDefaults instantiates a new SignRequestData object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetMode

`func (o *SignRequestData) GetMode() SignMode`

GetMode returns the Mode field if non-nil, zero value otherwise.

### GetModeOk

`func (o *SignRequestData) GetModeOk() (*SignMode, bool)`

GetModeOk returns a tuple with the Mode field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetMode

`func (o *SignRequestData) SetMode(v SignMode)`

SetMode sets Mode field to given value.


### GetMessage

`func (o *SignRequestData) GetMessage() string`

GetMessage returns the Message field if non-nil, zero value otherwise.

### GetMessageOk

`func (o *SignRequestData) GetMessageOk() (*string, bool)`

GetMessageOk returns a tuple with the Message field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetMessage

`func (o *SignRequestData) SetMessage(v string)`

SetMessage sets Message field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


