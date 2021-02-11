# LoggingConfig

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**IpAddress** | **string** |  | 
**Port** | **int32** |  | 
**LogLevel** | [**LogLevel**](LogLevel.md) |  | 

## Methods

### NewLoggingConfig

`func NewLoggingConfig(ipAddress string, port int32, logLevel LogLevel, ) *LoggingConfig`

NewLoggingConfig instantiates a new LoggingConfig object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewLoggingConfigWithDefaults

`func NewLoggingConfigWithDefaults() *LoggingConfig`

NewLoggingConfigWithDefaults instantiates a new LoggingConfig object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetIpAddress

`func (o *LoggingConfig) GetIpAddress() string`

GetIpAddress returns the IpAddress field if non-nil, zero value otherwise.

### GetIpAddressOk

`func (o *LoggingConfig) GetIpAddressOk() (*string, bool)`

GetIpAddressOk returns a tuple with the IpAddress field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetIpAddress

`func (o *LoggingConfig) SetIpAddress(v string)`

SetIpAddress sets IpAddress field to given value.


### GetPort

`func (o *LoggingConfig) GetPort() int32`

GetPort returns the Port field if non-nil, zero value otherwise.

### GetPortOk

`func (o *LoggingConfig) GetPortOk() (*int32, bool)`

GetPortOk returns a tuple with the Port field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetPort

`func (o *LoggingConfig) SetPort(v int32)`

SetPort sets Port field to given value.


### GetLogLevel

`func (o *LoggingConfig) GetLogLevel() LogLevel`

GetLogLevel returns the LogLevel field if non-nil, zero value otherwise.

### GetLogLevelOk

`func (o *LoggingConfig) GetLogLevelOk() (*LogLevel, bool)`

GetLogLevelOk returns a tuple with the LogLevel field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetLogLevel

`func (o *LoggingConfig) SetLogLevel(v LogLevel)`

SetLogLevel sets LogLevel field to given value.



[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


