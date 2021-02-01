# UserPostData

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**RealName** | **string** |  | 
**Role** | [**UserRole**](UserRole.md) |  | 
**Passphrase** | **string** |  | 

## Methods

### NewUserPostData

`func NewUserPostData(realName string, role UserRole, passphrase string, ) *UserPostData`

NewUserPostData instantiates a new UserPostData object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewUserPostDataWithDefaults

`func NewUserPostDataWithDefaults() *UserPostData`

NewUserPostDataWithDefaults instantiates a new UserPostData object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetRealName

`func (o *UserPostData) GetRealName() string`

GetRealName returns the RealName field if non-nil, zero value otherwise.

### GetRealNameOk

`func (o *UserPostData) GetRealNameOk() (*string, bool)`

GetRealNameOk returns a tuple with the RealName field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetRealName

`func (o *UserPostData) SetRealName(v string)`

SetRealName sets RealName field to given value.


### GetRole

`func (o *UserPostData) GetRole() UserRole`

GetRole returns the Role field if non-nil, zero value otherwise.

### GetRoleOk

`func (o *UserPostData) GetRoleOk() (*UserRole, bool)`

GetRoleOk returns a tuple with the Role field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetRole

`func (o *UserPostData) SetRole(v UserRole)`

SetRole sets Role field to given value.


### GetPassphrase

`func (o *UserPostData) GetPassphrase() string`

GetPassphrase returns the Passphrase field if non-nil, zero value otherwise.

### GetPassphraseOk

`func (o *UserPostData) GetPassphraseOk() (*string, bool)`

GetPassphraseOk returns a tuple with the Passphrase field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetPassphrase

`func (o *UserPostData) SetPassphrase(v string)`

SetPassphrase sets Passphrase field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


