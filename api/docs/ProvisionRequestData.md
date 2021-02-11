# ProvisionRequestData

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**UnlockPassphrase** | **string** |  | 
**AdminPassphrase** | **string** |  | 
**SystemTime** | **time.Time** |  | 

## Methods

### NewProvisionRequestData

`func NewProvisionRequestData(unlockPassphrase string, adminPassphrase string, systemTime time.Time, ) *ProvisionRequestData`

NewProvisionRequestData instantiates a new ProvisionRequestData object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewProvisionRequestDataWithDefaults

`func NewProvisionRequestDataWithDefaults() *ProvisionRequestData`

NewProvisionRequestDataWithDefaults instantiates a new ProvisionRequestData object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetUnlockPassphrase

`func (o *ProvisionRequestData) GetUnlockPassphrase() string`

GetUnlockPassphrase returns the UnlockPassphrase field if non-nil, zero value otherwise.

### GetUnlockPassphraseOk

`func (o *ProvisionRequestData) GetUnlockPassphraseOk() (*string, bool)`

GetUnlockPassphraseOk returns a tuple with the UnlockPassphrase field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetUnlockPassphrase

`func (o *ProvisionRequestData) SetUnlockPassphrase(v string)`

SetUnlockPassphrase sets UnlockPassphrase field to given value.


### GetAdminPassphrase

`func (o *ProvisionRequestData) GetAdminPassphrase() string`

GetAdminPassphrase returns the AdminPassphrase field if non-nil, zero value otherwise.

### GetAdminPassphraseOk

`func (o *ProvisionRequestData) GetAdminPassphraseOk() (*string, bool)`

GetAdminPassphraseOk returns a tuple with the AdminPassphrase field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetAdminPassphrase

`func (o *ProvisionRequestData) SetAdminPassphrase(v string)`

SetAdminPassphrase sets AdminPassphrase field to given value.


### GetSystemTime

`func (o *ProvisionRequestData) GetSystemTime() time.Time`

GetSystemTime returns the SystemTime field if non-nil, zero value otherwise.

### GetSystemTimeOk

`func (o *ProvisionRequestData) GetSystemTimeOk() (*time.Time, bool)`

GetSystemTimeOk returns a tuple with the SystemTime field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetSystemTime

`func (o *ProvisionRequestData) SetSystemTime(v time.Time)`

SetSystemTime sets SystemTime field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


