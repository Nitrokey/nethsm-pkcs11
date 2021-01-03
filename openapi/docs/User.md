# User

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Realname** | **string** |  | 
**Role** | [**UserRole**](UserRole.md) |  | 
**Passphrase** | **string** |  | 

## Methods

### NewUser

`func NewUser(realname string, role UserRole, passphrase string, ) *User`

NewUser instantiates a new User object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewUserWithDefaults

`func NewUserWithDefaults() *User`

NewUserWithDefaults instantiates a new User object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetRealname

`func (o *User) GetRealname() string`

GetRealname returns the Realname field if non-nil, zero value otherwise.

### GetRealnameOk

`func (o *User) GetRealnameOk() (*string, bool)`

GetRealnameOk returns a tuple with the Realname field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetRealname

`func (o *User) SetRealname(v string)`

SetRealname sets Realname field to given value.


### GetRole

`func (o *User) GetRole() UserRole`

GetRole returns the Role field if non-nil, zero value otherwise.

### GetRoleOk

`func (o *User) GetRoleOk() (*UserRole, bool)`

GetRoleOk returns a tuple with the Role field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetRole

`func (o *User) SetRole(v UserRole)`

SetRole sets Role field to given value.


### GetPassphrase

`func (o *User) GetPassphrase() string`

GetPassphrase returns the Passphrase field if non-nil, zero value otherwise.

### GetPassphraseOk

`func (o *User) GetPassphraseOk() (*string, bool)`

GetPassphraseOk returns a tuple with the Passphrase field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetPassphrase

`func (o *User) SetPassphrase(v string)`

SetPassphrase sets Passphrase field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


