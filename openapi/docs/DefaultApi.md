# \DefaultApi

All URIs are relative to *https://nethsmdemo.nitrokey.com/api/v1*

Method | HTTP request | Description
------------- | ------------- | -------------
[**config_backup_passphrase_put**](DefaultApi.md#config_backup_passphrase_put) | **PUT** /config/backup-passphrase | 
[**config_logging_get**](DefaultApi.md#config_logging_get) | **GET** /config/logging | 
[**config_logging_put**](DefaultApi.md#config_logging_put) | **PUT** /config/logging | 
[**config_network_get**](DefaultApi.md#config_network_get) | **GET** /config/network | 
[**config_network_put**](DefaultApi.md#config_network_put) | **PUT** /config/network | 
[**config_time_get**](DefaultApi.md#config_time_get) | **GET** /config/time | 
[**config_time_put**](DefaultApi.md#config_time_put) | **PUT** /config/time | 
[**config_tls_cert_pem_get**](DefaultApi.md#config_tls_cert_pem_get) | **GET** /config/tls/cert.pem | 
[**config_tls_cert_pem_put**](DefaultApi.md#config_tls_cert_pem_put) | **PUT** /config/tls/cert.pem | 
[**config_tls_csr_pem_post**](DefaultApi.md#config_tls_csr_pem_post) | **POST** /config/tls/csr.pem | 
[**config_tls_generate_post**](DefaultApi.md#config_tls_generate_post) | **POST** /config/tls/generate | 
[**config_tls_public_pem_get**](DefaultApi.md#config_tls_public_pem_get) | **GET** /config/tls/public.pem | 
[**config_unattended_boot_get**](DefaultApi.md#config_unattended_boot_get) | **GET** /config/unattended-boot | 
[**config_unattended_boot_put**](DefaultApi.md#config_unattended_boot_put) | **PUT** /config/unattended-boot | 
[**config_unlock_passphrase_put**](DefaultApi.md#config_unlock_passphrase_put) | **PUT** /config/unlock-passphrase | 
[**health_alive_get**](DefaultApi.md#health_alive_get) | **GET** /health/alive | 
[**health_ready_get**](DefaultApi.md#health_ready_get) | **GET** /health/ready | 
[**health_state_get**](DefaultApi.md#health_state_get) | **GET** /health/state | 
[**info_get**](DefaultApi.md#info_get) | **GET** /info | 
[**keys_generate_post**](DefaultApi.md#keys_generate_post) | **POST** /keys/generate | 
[**keys_get**](DefaultApi.md#keys_get) | **GET** /keys | 
[**keys_key_id_cert_delete**](DefaultApi.md#keys_key_id_cert_delete) | **DELETE** /keys/{KeyID}/cert | 
[**keys_key_id_cert_get**](DefaultApi.md#keys_key_id_cert_get) | **GET** /keys/{KeyID}/cert | 
[**keys_key_id_cert_put**](DefaultApi.md#keys_key_id_cert_put) | **PUT** /keys/{KeyID}/cert | 
[**keys_key_id_csr_pem_post**](DefaultApi.md#keys_key_id_csr_pem_post) | **POST** /keys/{KeyID}/csr.pem | 
[**keys_key_id_decrypt_post**](DefaultApi.md#keys_key_id_decrypt_post) | **POST** /keys/{KeyID}/decrypt | 
[**keys_key_id_delete**](DefaultApi.md#keys_key_id_delete) | **DELETE** /keys/{KeyID} | 
[**keys_key_id_encrypt_post**](DefaultApi.md#keys_key_id_encrypt_post) | **POST** /keys/{KeyID}/encrypt | 
[**keys_key_id_get**](DefaultApi.md#keys_key_id_get) | **GET** /keys/{KeyID} | 
[**keys_key_id_public_pem_get**](DefaultApi.md#keys_key_id_public_pem_get) | **GET** /keys/{KeyID}/public.pem | 
[**keys_key_id_put**](DefaultApi.md#keys_key_id_put) | **PUT** /keys/{KeyID} | 
[**keys_key_id_restrictions_tags_tag_delete**](DefaultApi.md#keys_key_id_restrictions_tags_tag_delete) | **DELETE** /keys/{KeyID}/restrictions/tags/{Tag} | 
[**keys_key_id_restrictions_tags_tag_put**](DefaultApi.md#keys_key_id_restrictions_tags_tag_put) | **PUT** /keys/{KeyID}/restrictions/tags/{Tag} | 
[**keys_key_id_sign_post**](DefaultApi.md#keys_key_id_sign_post) | **POST** /keys/{KeyID}/sign | 
[**keys_post**](DefaultApi.md#keys_post) | **POST** /keys | 
[**lock_post**](DefaultApi.md#lock_post) | **POST** /lock | 
[**metrics_get**](DefaultApi.md#metrics_get) | **GET** /metrics | 
[**provision_post**](DefaultApi.md#provision_post) | **POST** /provision | 
[**random_post**](DefaultApi.md#random_post) | **POST** /random | 
[**system_backup_post**](DefaultApi.md#system_backup_post) | **POST** /system/backup | 
[**system_cancel_update_post**](DefaultApi.md#system_cancel_update_post) | **POST** /system/cancel-update | 
[**system_commit_update_post**](DefaultApi.md#system_commit_update_post) | **POST** /system/commit-update | 
[**system_factory_reset_post**](DefaultApi.md#system_factory_reset_post) | **POST** /system/factory-reset | 
[**system_info_get**](DefaultApi.md#system_info_get) | **GET** /system/info | 
[**system_reboot_post**](DefaultApi.md#system_reboot_post) | **POST** /system/reboot | 
[**system_restore_post**](DefaultApi.md#system_restore_post) | **POST** /system/restore | 
[**system_shutdown_post**](DefaultApi.md#system_shutdown_post) | **POST** /system/shutdown | 
[**system_update_post**](DefaultApi.md#system_update_post) | **POST** /system/update | 
[**unlock_post**](DefaultApi.md#unlock_post) | **POST** /unlock | 
[**users_get**](DefaultApi.md#users_get) | **GET** /users | 
[**users_post**](DefaultApi.md#users_post) | **POST** /users | 
[**users_user_id_delete**](DefaultApi.md#users_user_id_delete) | **DELETE** /users/{UserID} | 
[**users_user_id_get**](DefaultApi.md#users_user_id_get) | **GET** /users/{UserID} | 
[**users_user_id_passphrase_post**](DefaultApi.md#users_user_id_passphrase_post) | **POST** /users/{UserID}/passphrase | 
[**users_user_id_put**](DefaultApi.md#users_user_id_put) | **PUT** /users/{UserID} | 
[**users_user_id_tags_get**](DefaultApi.md#users_user_id_tags_get) | **GET** /users/{UserID}/tags | 
[**users_user_id_tags_tag_delete**](DefaultApi.md#users_user_id_tags_tag_delete) | **DELETE** /users/{UserID}/tags/{Tag} | 
[**users_user_id_tags_tag_put**](DefaultApi.md#users_user_id_tags_tag_put) | **PUT** /users/{UserID}/tags/{Tag} | 



## config_backup_passphrase_put

> config_backup_passphrase_put(backup_passphrase_config)


Update the backup passphrase.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**backup_passphrase_config** | [**BackupPassphraseConfig**](BackupPassphraseConfig.md) |  | [required] |

### Return type

 (empty response body)

### Authorization

[basic](../README.md#basic)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: Not defined

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## config_logging_get

> crate::models::LoggingConfig config_logging_get()


Get logging configuration. Protocol is always syslog over UDP. Configurable are IP adress and port, log level. 

### Parameters

This endpoint does not need any parameter.

### Return type

[**crate::models::LoggingConfig**](LoggingConfig.md)

### Authorization

[basic](../README.md#basic)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## config_logging_put

> config_logging_put(logging_config)


Configure log level and destination.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**logging_config** | [**LoggingConfig**](LoggingConfig.md) |  | [required] |

### Return type

 (empty response body)

### Authorization

[basic](../README.md#basic)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: Not defined

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## config_network_get

> crate::models::NetworkConfig config_network_get()


Get network configuration. IP address, netmask, router.

### Parameters

This endpoint does not need any parameter.

### Return type

[**crate::models::NetworkConfig**](NetworkConfig.md)

### Authorization

[basic](../README.md#basic)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## config_network_put

> config_network_put(network_config)


Configure network.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**network_config** | [**NetworkConfig**](NetworkConfig.md) |  | [required] |

### Return type

 (empty response body)

### Authorization

[basic](../README.md#basic)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: Not defined

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## config_time_get

> crate::models::TimeConfig config_time_get()


Get system time.

### Parameters

This endpoint does not need any parameter.

### Return type

[**crate::models::TimeConfig**](TimeConfig.md)

### Authorization

[basic](../README.md#basic)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## config_time_put

> config_time_put(time_config)


Configure system time.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**time_config** | [**TimeConfig**](TimeConfig.md) |  | [required] |

### Return type

 (empty response body)

### Authorization

[basic](../README.md#basic)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: Not defined

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## config_tls_cert_pem_get

> String config_tls_cert_pem_get()


Get certificate for NetHSMs https API.

### Parameters

This endpoint does not need any parameter.

### Return type

**String**

### Authorization

[basic](../README.md#basic)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/x-pem-file

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## config_tls_cert_pem_put

> config_tls_cert_pem_put(body)


Set certificate for NetHSMs https API e.g. to replace self-signed intital certificate.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**body** | **String** |  | [required] |

### Return type

 (empty response body)

### Authorization

[basic](../README.md#basic)

### HTTP request headers

- **Content-Type**: application/x-pem-file
- **Accept**: Not defined

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## config_tls_csr_pem_post

> String config_tls_csr_pem_post(distinguished_name)


Get NetHSM certificate signing request e.g. to replace self-signed intital certificate.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**distinguished_name** | [**DistinguishedName**](DistinguishedName.md) |  | [required] |

### Return type

**String**

### Authorization

[basic](../README.md#basic)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/x-pem-file

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## config_tls_generate_post

> config_tls_generate_post(tls_key_generate_request_data)


Generate a new pair of public and private key for NetHSM's https API.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**tls_key_generate_request_data** | [**TlsKeyGenerateRequestData**](TlsKeyGenerateRequestData.md) |  | [required] |

### Return type

 (empty response body)

### Authorization

[basic](../README.md#basic)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: Not defined

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## config_tls_public_pem_get

> String config_tls_public_pem_get()


Get public key for NetHSMs https API.

### Parameters

This endpoint does not need any parameter.

### Return type

**String**

### Authorization

[basic](../README.md#basic)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/x-pem-file

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## config_unattended_boot_get

> crate::models::UnattendedBootConfig config_unattended_boot_get()


Read unattended boot configuration: is it on or off?

### Parameters

This endpoint does not need any parameter.

### Return type

[**crate::models::UnattendedBootConfig**](UnattendedBootConfig.md)

### Authorization

[basic](../README.md#basic)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## config_unattended_boot_put

> config_unattended_boot_put(unattended_boot_config)


Configure unattended boot: switch it on or off (flip the switch).

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**unattended_boot_config** | [**UnattendedBootConfig**](UnattendedBootConfig.md) |  | [required] |

### Return type

 (empty response body)

### Authorization

[basic](../README.md#basic)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: Not defined

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## config_unlock_passphrase_put

> config_unlock_passphrase_put(unlock_passphrase_config)


Update the unlock passphrase.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**unlock_passphrase_config** | [**UnlockPassphraseConfig**](UnlockPassphraseConfig.md) |  | [required] |

### Return type

 (empty response body)

### Authorization

[basic](../README.md#basic)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: Not defined

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## health_alive_get

> health_alive_get()


Retrieve wether NetHSM is alive (powered up). This corresponds to the state *Locked* or *Unprovisioned*. 

### Parameters

This endpoint does not need any parameter.

### Return type

 (empty response body)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: Not defined

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## health_ready_get

> health_ready_get()


Retrieve wether NetHSM is alive and ready to take traffic. This corresponds to the state *Operational*. 

### Parameters

This endpoint does not need any parameter.

### Return type

 (empty response body)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: Not defined

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## health_state_get

> crate::models::HealthStateData health_state_get()


Retrieve the state of NetHSM.

### Parameters

This endpoint does not need any parameter.

### Return type

[**crate::models::HealthStateData**](HealthStateData.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## info_get

> crate::models::InfoData info_get()


Information about the vendor and product.

### Parameters

This endpoint does not need any parameter.

### Return type

[**crate::models::InfoData**](InfoData.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## keys_generate_post

> keys_generate_post(key_generate_request_data)


Generate a pair of public and private key and store it in NetHSM. KeyID is optional as a parameter and will be generated by NetHSM if not present. 

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**key_generate_request_data** | [**KeyGenerateRequestData**](KeyGenerateRequestData.md) |  | [required] |

### Return type

 (empty response body)

### Authorization

[basic](../README.md#basic)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: Not defined

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## keys_get

> Vec<crate::models::KeyItem> keys_get(filter)


Get a list of the identifiers of all keys that are currently stored in NetHSM. Separate requests need to be made to request the individual key data. 

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**filter** | Option<**String**> | Only return keys that are can be used by the requester, according to restrictions. |  |

### Return type

[**Vec<crate::models::KeyItem>**](KeyItem.md)

### Authorization

[basic](../README.md#basic)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## keys_key_id_cert_delete

> keys_key_id_cert_delete(key_id)


Delete the certificate.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**key_id** | **String** |  | [required] |

### Return type

 (empty response body)

### Authorization

[basic](../README.md#basic)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: Not defined

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## keys_key_id_cert_get

> String keys_key_id_cert_get(key_id)


Retrieve stored certificate. The content-type header will display the media type of the stored data. 

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**key_id** | **String** |  | [required] |

### Return type

**String**

### Authorization

[basic](../README.md#basic)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/x-pem-file, application/x-x509-ca-cert, application/pgp-keys

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## keys_key_id_cert_put

> keys_key_id_cert_put(key_id, body)


Store a certificate. Maximum size 1MB. The content-type header provides the media type. Only application/json, application/x-pem-file, application/x-x509-ca-cert, application/octet-stream, text/plain and application/pgp-keys is allowed. 

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**key_id** | **String** |  | [required] |
**body** | **String** |  | [required] |

### Return type

 (empty response body)

### Authorization

[basic](../README.md#basic)

### HTTP request headers

- **Content-Type**: application/x-pem-file, application/x-x509-ca-cert, application/pgp-keys
- **Accept**: Not defined

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## keys_key_id_csr_pem_post

> String keys_key_id_csr_pem_post(key_id, distinguished_name)


Retrieve a certificate signing request in PEM format.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**key_id** | **String** |  | [required] |
**distinguished_name** | [**DistinguishedName**](DistinguishedName.md) |  | [required] |

### Return type

**String**

### Authorization

[basic](../README.md#basic)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/x-pem-file

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## keys_key_id_decrypt_post

> crate::models::DecryptData keys_key_id_decrypt_post(key_id, decrypt_request_data)


Decrypt an encrypted message with the secret key.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**key_id** | **String** |  | [required] |
**decrypt_request_data** | [**DecryptRequestData**](DecryptRequestData.md) | For request body with content type `application/json`: * Mode `RAW` expects raw binary data. * Mode `PKCS1` expects PKCS1-encoded and padded binary data. * Mode `OAEP_*` expects EME-OAEP-encoded and padded binary data.  | [required] |

### Return type

[**crate::models::DecryptData**](DecryptData.md)

### Authorization

[basic](../README.md#basic)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## keys_key_id_delete

> keys_key_id_delete(key_id)


Delete a pair of public and private key.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**key_id** | **String** |  | [required] |

### Return type

 (empty response body)

### Authorization

[basic](../README.md#basic)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: Not defined

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## keys_key_id_encrypt_post

> crate::models::EncryptData keys_key_id_encrypt_post(key_id, encrypt_request_data)


Encrypt a message with the secret key.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**key_id** | **String** |  | [required] |
**encrypt_request_data** | [**EncryptRequestData**](EncryptRequestData.md) |  | [required] |

### Return type

[**crate::models::EncryptData**](EncryptData.md)

### Authorization

[basic](../README.md#basic)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## keys_key_id_get

> crate::models::PublicKey keys_key_id_get(key_id)


Retrieve the public key.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**key_id** | **String** |  | [required] |

### Return type

[**crate::models::PublicKey**](PublicKey.md)

### Authorization

[basic](../README.md#basic)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## keys_key_id_public_pem_get

> String keys_key_id_public_pem_get(key_id)


Retrieve public key in PEM format.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**key_id** | **String** |  | [required] |

### Return type

**String**

### Authorization

[basic](../README.md#basic)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/x-pem-file

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## keys_key_id_put

> keys_key_id_put(key_id, private_key, mechanisms, tags)


Import a private key into NetHSM and store it under the *KeyID* path. The public key will be automatically derived. The parameters of the key can be passed as a PEM file or a JSON object. 

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**key_id** | **String** |  | [required] |
**private_key** | [**PrivateKey**](PrivateKey.md) | For request body with content type `application/json`: * *RSA* includes `primeP`, `primeQ`, and `publicExponent` properties.   The remaining properties `privateExponent`, `modulus`, ..) are computed. * *EC_P224*, *EC_P256*, *EC_P384*, *EC_P521* uses the `data` property.   Keys are the raw (big endian) scalar. * *Curve25519* uses the `data` property.   Keys are the raw (little endian) key.  | [required] |
**mechanisms** | Option<[**Vec<crate::models::KeyMechanism>**](crate::models::KeyMechanism.md)> |  |  |
**tags** | Option<[**Vec<String>**](String.md)> |  |  |

### Return type

 (empty response body)

### Authorization

[basic](../README.md#basic)

### HTTP request headers

- **Content-Type**: application/json, application/x-pem-file
- **Accept**: Not defined

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## keys_key_id_restrictions_tags_tag_delete

> keys_key_id_restrictions_tags_tag_delete(tag, key_id)


Delete a tag from the authorized set

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**tag** | **String** |  | [required] |
**key_id** | **String** |  | [required] |

### Return type

 (empty response body)

### Authorization

[basic](../README.md#basic)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: Not defined

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## keys_key_id_restrictions_tags_tag_put

> keys_key_id_restrictions_tags_tag_put(tag, key_id)


Add a tag to the authorized set

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**tag** | **String** |  | [required] |
**key_id** | **String** |  | [required] |

### Return type

 (empty response body)

### Authorization

[basic](../README.md#basic)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: Not defined

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## keys_key_id_sign_post

> crate::models::SignData keys_key_id_sign_post(key_id, sign_request_data)


Sign a message with the secret key.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**key_id** | **String** |  | [required] |
**sign_request_data** | [**SignRequestData**](SignRequestData.md) | For request body with content type `application/json`: * Mode `PKCS1` expects the already hashed data. * Mode `PSS_*` expects the already hashed data. * Mode `EdDSA` expects the raw message   (ED25519 applies the SHA512 hash internally,   also to derive the nonce). * Mode `ECDSA` expects the hashed data   (using SHA224 for P224, SHA256 for P256,   SHA384 for P384 and SHA512 for P521).  | [required] |

### Return type

[**crate::models::SignData**](SignData.md)

### Authorization

[basic](../README.md#basic)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## keys_post

> keys_post(private_key, mechanisms, tags)


Import a private key into NetHSM and let NetHSM generate a KeyID. The public key will be automatically derived. The parameters of the key can be passed as a PEM file or a JSON object. 

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**private_key** | [**PrivateKey**](PrivateKey.md) |  | [required] |
**mechanisms** | Option<[**Vec<crate::models::KeyMechanism>**](crate::models::KeyMechanism.md)> |  |  |
**tags** | Option<[**Vec<String>**](String.md)> |  |  |

### Return type

 (empty response body)

### Authorization

[basic](../README.md#basic)

### HTTP request headers

- **Content-Type**: application/json, application/x-pem-file
- **Accept**: Not defined

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## lock_post

> lock_post()


Brings an *Operational* NetHSM into *Locked* state.

### Parameters

This endpoint does not need any parameter.

### Return type

 (empty response body)

### Authorization

[basic](../README.md#basic)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: Not defined

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## metrics_get

> serde_json::Value metrics_get()


Get metrics. Precondition: NetHSM is *Operational* and a **R-Metrics** can be authenticated. 

### Parameters

This endpoint does not need any parameter.

### Return type

[**serde_json::Value**](serde_json::Value.md)

### Authorization

[basic](../README.md#basic)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## provision_post

> provision_post(provision_request_data)


Initial provisioning, only available in *Unprovisioned* state.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**provision_request_data** | [**ProvisionRequestData**](ProvisionRequestData.md) |  | [required] |

### Return type

 (empty response body)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: Not defined

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## random_post

> crate::models::RandomData random_post(random_request_data)


Retrieve cryptographically strong random bytes from NetHSM. Precondition: NetHSM is *Operational* and a **R-Operator** can be authenticated. 

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**random_request_data** | [**RandomRequestData**](RandomRequestData.md) |  | [required] |

### Return type

[**crate::models::RandomData**](RandomData.md)

### Authorization

[basic](../README.md#basic)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## system_backup_post

> system_backup_post()


Back up the key store to a backup file.

### Parameters

This endpoint does not need any parameter.

### Return type

 (empty response body)

### Authorization

[basic](../README.md#basic)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: Not defined

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## system_cancel_update_post

> system_cancel_update_post()


Cancel update of NetHSM software.

### Parameters

This endpoint does not need any parameter.

### Return type

 (empty response body)

### Authorization

[basic](../README.md#basic)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: Not defined

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## system_commit_update_post

> system_commit_update_post()


Commit update of NetHSM software.

### Parameters

This endpoint does not need any parameter.

### Return type

 (empty response body)

### Authorization

[basic](../README.md#basic)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: Not defined

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## system_factory_reset_post

> system_factory_reset_post()


Reset NetHSM to factory settings.

### Parameters

This endpoint does not need any parameter.

### Return type

 (empty response body)

### Authorization

[basic](../README.md#basic)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: Not defined

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## system_info_get

> crate::models::SystemInfo system_info_get()


Get detailed system information, including firmware, system, and hardware version. 

### Parameters

This endpoint does not need any parameter.

### Return type

[**crate::models::SystemInfo**](SystemInfo.md)

### Authorization

[basic](../README.md#basic)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## system_reboot_post

> system_reboot_post()


Reboot NetHSM.

### Parameters

This endpoint does not need any parameter.

### Return type

 (empty response body)

### Authorization

[basic](../README.md#basic)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: Not defined

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## system_restore_post

> system_restore_post(backup_passphrase, body, system_time)


Restore the key store and user store from a backup file. If NetHSM is *Unprovisioned*, then the configuration is restored. 

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**backup_passphrase** | **String** |  | [required] |
**body** | **String** |  | [required] |
**system_time** | Option<**String**> |  |  |

### Return type

 (empty response body)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: application/octet-stream
- **Accept**: Not defined

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## system_shutdown_post

> system_shutdown_post()


Shut down NetHSM.

### Parameters

This endpoint does not need any parameter.

### Return type

 (empty response body)

### Authorization

[basic](../README.md#basic)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: Not defined

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## system_update_post

> crate::models::SystemUpdateData system_update_post(body)


Update NetHSM software.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**body** | **String** |  | [required] |

### Return type

[**crate::models::SystemUpdateData**](SystemUpdateData.md)

### Authorization

[basic](../README.md#basic)

### HTTP request headers

- **Content-Type**: application/octet-stream
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## unlock_post

> unlock_post(unlock_request_data)


Brings a *Locked* NetHSM into *Operational* state.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**unlock_request_data** | [**UnlockRequestData**](UnlockRequestData.md) |  | [required] |

### Return type

 (empty response body)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: Not defined

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## users_get

> Vec<crate::models::UserItem> users_get()


Get a list of all user ids that have accounts on NetHSM.

### Parameters

This endpoint does not need any parameter.

### Return type

[**Vec<crate::models::UserItem>**](UserItem.md)

### Authorization

[basic](../README.md#basic)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## users_post

> users_post(user_post_data)


Create a new user on NetHSM. The user-ID is generated by NetHSM.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**user_post_data** | [**UserPostData**](UserPostData.md) |  | [required] |

### Return type

 (empty response body)

### Authorization

[basic](../README.md#basic)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: Not defined

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## users_user_id_delete

> users_user_id_delete(user_id)


Delete a user from keyfender.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**user_id** | **String** |  | [required] |

### Return type

 (empty response body)

### Authorization

[basic](../README.md#basic)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: Not defined

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## users_user_id_get

> crate::models::UserData users_user_id_get(user_id)


Get user info: name and role.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**user_id** | **String** |  | [required] |

### Return type

[**crate::models::UserData**](UserData.md)

### Authorization

[basic](../README.md#basic)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## users_user_id_passphrase_post

> users_user_id_passphrase_post(user_id, user_passphrase_post_data)


Update the passphrase.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**user_id** | **String** |  | [required] |
**user_passphrase_post_data** | [**UserPassphrasePostData**](UserPassphrasePostData.md) |  | [required] |

### Return type

 (empty response body)

### Authorization

[basic](../README.md#basic)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: Not defined

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## users_user_id_put

> users_user_id_put(user_id, user_post_data)


Create a user on keyfender.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**user_id** | **String** |  | [required] |
**user_post_data** | [**UserPostData**](UserPostData.md) |  | [required] |

### Return type

 (empty response body)

### Authorization

[basic](../README.md#basic)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: Not defined

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## users_user_id_tags_get

> Vec<String> users_user_id_tags_get(user_id)


Get the list of tags set to an Operator user.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**user_id** | **String** |  | [required] |

### Return type

**Vec<String>**

### Authorization

[basic](../README.md#basic)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## users_user_id_tags_tag_delete

> users_user_id_tags_tag_delete(user_id, tag)


Delete a tag from the Operator user

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**user_id** | **String** |  | [required] |
**tag** | **String** |  | [required] |

### Return type

 (empty response body)

### Authorization

[basic](../README.md#basic)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: Not defined

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## users_user_id_tags_tag_put

> users_user_id_tags_tag_put(user_id, tag)


Add a tag to the Operator user.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**user_id** | **String** |  | [required] |
**tag** | **String** |  | [required] |

### Return type

 (empty response body)

### Authorization

[basic](../README.md#basic)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: Not defined

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

