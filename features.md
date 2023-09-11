# Features

- :white_check_mark: : Fully functionnal
- :warning: : Some behaviors may not be implemented
- 🗓️ : Planned
- :x: : Not in the current scope of the project

## Concurrency

As of current version concurrency is not yet implemented.

## Base features

| Feature           | Status             | Notes                            |
| ----------------- | ------------------ | -------------------------------- |
| C_GetFunctionList | :white_check_mark: |                                  |
| C_Initialize      | :white_check_mark: | Custom mutexes are not supported |
| C_Finalize        | :white_check_mark: |                                  |
| C_GetInfo         | :white_check_mark: |                                  |

## Session

| Feature             | Status             | Notes                             |
| ------------------- | ------------------ | --------------------------------- |
| C_OpenSession       | :white_check_mark: | Notify not supported              |
| C_CloseSession      | :white_check_mark: |                                   |
| C_CloseAllSessions  | :white_check_mark: |                                   |
| C_GetSessionInfo    | :white_check_mark: |                                   |
| C_GetOperationState | :x:                | No demand                         |
| C_SetOperationState | :x:                | No demand                         |
| C_GetFunctionStatus | :white_check_mark: | Returns CKR_FUNCTION_NOT_PARALLEL |
| C_CancelFunction    | :white_check_mark: | Returns CKR_FUNCTION_NOT_PARALLEL |

## Token

| Feature            | Status             | Notes                                                                                                                           |
| ------------------ | ------------------ | ------------------------------------------------------------------------------------------------------------------------------- |
| C_GetSlotList      | :white_check_mark: |                                                                                                                                 |
| C_GetSlotInfo      | :white_check_mark: |                                                                                                                                 |
| C_GetTokenInfo     | :white_check_mark: |                                                                                                                                 |
| C_InitToken        | :x:                |                                                                                                                                 |
| C_GetMechanismList | :white_check_mark: |                                                                                                                                 |
| C_GetMechanismInfo | :white_check_mark: |                                                                                                                                 |
| C_Login            | :white_check_mark: | The PIN is used as the password, login as SO means logging in with an Administrator account ("admin" username set by default)   |
| C_Logout           | :white_check_mark: |                                                                                                                                 |
| C_WaitForSlotEvent | :white_check_mark: | CKF_DONT_BLOCK set: checks if a slot has changed state since last check. CKF_DONT_BLOCK clear: waits for a slot to change state |

## Decrypt

Mechanisms:

- AES-CBC
- RSA-X-509 (Raw RSA)
- RSA-PKCS
- RSA-PKCS-OAEP: data hashed with MD5/SHA1/SHA224/SHA256/SHA384/SHA512

| Feature               | Status             | Notes                                                                                                            |
| --------------------- | ------------------ | ---------------------------------------------------------------------------------------------------------------- |
| C_DecryptInit         | :white_check_mark: |                                                                                                                  |
| C_Decrypt             | :white_check_mark: |                                                                                                                  |
| C_DecryptUpdate       | :white_check_mark: | The length of the output buffer will always be 0. The decrypted data will be all sent in the C_DecryptFinal call |
| C_DecryptFinal        | :white_check_mark: |                                                                                                                  |
| C_DecryptVerifyUpdate | :x:                | Verify is not supported by NetHSM                                                                                |

## Encrypt

Mechanisms:

- AES-CBC

| Feature         | Status             | Notes                                                 |
| --------------- | ------------------ | ----------------------------------------------------- |
| C_EncryptInit   | :white_check_mark: |                                                       |
| C_Encrypt       | :white_check_mark: |                                                       |
| C_EncryptUpdate | :white_check_mark: |                                                       |
| C_EncryptFinal  | :white_check_mark: | AES-CBC expects messages with a length multiple of 16 |

## Sign

Mechanisms:

- RSA-PKCS
- RSA-PKCS-PSS: expects hashed value with MD5/SHA1/SHA224/SHA256/SHA384/SHA512 (set the correct one in CK_RSA_PKCS_PSS_PARAMS)
- EDDSA
- ECDSA
- ECDSA-SHA1 (Hash is computed by the PKCS#11 module)
- ECDSA-SHA224 (Hash is computed by the PKCS#11 module)
- ECDSA-SHA256 (Hash is computed by the PKCS#11 module)
- ECDSA-SHA384 (Hash is computed by the PKCS#11 module)
- ECDSA-SHA512 (Hash is computed by the PKCS#11 module)

| Feature             | Status             | Notes                   |
| ------------------- | ------------------ | ----------------------- |
| C_SignInit          | :white_check_mark: |                         |
| C_Sign              | :white_check_mark: |                         |
| C_SignUpdate        | :white_check_mark: |                         |
| C_SignFinal         | :white_check_mark: |                         |
| C_SignRecoverInit   | :x:                | Not supported by NetHSM |
| C_SignRecover       | :x:                | Not supported by NetHSM |
| C_SignEncryptUpdate | :x:                | Not supported by NetHSM |

## Digest :x:

Digest is not supported by NetHSM

## Verify :x:

Verify is not supported by NetHSM

## Generation

| Feature           | Status             | Notes                                    |
| ----------------- | ------------------ | ---------------------------------------- |
| C_GenerateKey     | :white_check_mark: | Needs Administrator                      |
| C_GenerateKeyPair | :white_check_mark: | Needs Administrator                      |
| C_GenerateRandom  | :white_check_mark: |                                          |
| C_SeedRandom      | :warning:          | Returns OK but the arguments are ignored |
| C_WrapKey         | :x:                | Not supported by NetHSM                  |
| C_UnwrapKey       | :x:                | Not supported by NetHSM                  |
| C_DeriveKey       | :x:                | Not supported by NetHSM                  |

## Objects

| Feature             | Status             | Notes                                                                                                                       |
| ------------------- | ------------------ | --------------------------------------------------------------------------------------------------------------------------- |
| C_FindObjectsInit   | :warning:          | Only lists the available keys                                                                                               |
| C_FindObjects       | :warning:          | Only lists the available keys                                                                                               |
| C_FindObjectsFinal  | :white_check_mark: |                                                                                                                             |
| C_GetAttributeValue | :white_check_mark: |                                                                                                                             |
| C_GetObjectSize     | :white_check_mark: |                                                                                                                             |
| C_CreateObject      | :warning:          | Needs to be logged as Administrator (SO). Only private keys can be added.                                                   |
| C_CopyObject        | :white_check_mark: | Always returns CKR_ACTION_PROHIBITED                                                                                        |
| C_DestroyObject     | :warning:          | Needs to be logged as Administrator (SO). Only private keys can be deleted.                                                 |
| C_SetAttributeValue | :white_check_mark: | Returns CKR_ACTION_PROHIBITED. A compatibility option is available for Java Sun PKCS11 / EJBCA : enable_set_attribute_value |

## Pin management

| Feature   | Status             | Notes                            |
| --------- | ------------------ | -------------------------------- |
| C_InitPIN | :x:                |                                  |
| C_SetPIN  | :white_check_mark: | Changes the password of the user |
