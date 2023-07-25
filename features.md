# Status of the pkcs11 module implementation

- :heavy_check_mark: : Fully functionnal
- :warning: : Some behaviors may not be implemented
- 🗓️ : Planned
- :x: : Not in the current scope of the project

## Concurrency

As of current version concurrency is not yet implemented.

## Base features

| Feature           | Status             | Notes                         |
| ----------------- | ------------------ | ----------------------------- |
| C_GetFunctionList | :heavy_check_mark: |                               |
| C_Initialize      | :warning:          | Concurrency not yet supported |
| C_Finalize        | :heavy_check_mark: |                               |
| C_GetInfo         | :heavy_check_mark: |                               |

## Session

| Feature             | Status             | Notes                             |
| ------------------- | ------------------ | --------------------------------- |
| C_OpenSession       | :warning:          | Notify not supported              |
| C_CloseSession      | :heavy_check_mark: |                                   |
| C_CloseAllSessions  | :heavy_check_mark: |                                   |
| C_GetSessionInfo    | :heavy_check_mark: |                                   |
| C_GetOperationState | :x:                | May be implemented later          |
| C_SetOperationState | :x:                | May be implemented later          |
| C_GetFunctionStatus | :heavy_check_mark: | Returns CKR_FUNCTION_NOT_PARALLEL |
| C_CancelFunction    | :heavy_check_mark: | Returns CKR_FUNCTION_NOT_PARALLEL |

## Token

| Feature            | Status             | Notes                                                                                                                       |
| ------------------ | ------------------ | --------------------------------------------------------------------------------------------------------------------------- |
| C_GetSlotList      | :heavy_check_mark: |                                                                                                                             |
| C_GetSlotInfo      | :heavy_check_mark: |                                                                                                                             |
| C_GetTokenInfo     | :heavy_check_mark: |                                                                                                                             |
| C_InitToken        | :x:                |                                                                                                                             |
| C_GetMechanismList | :heavy_check_mark: |                                                                                                                             |
| C_GetMechanismInfo | :heavy_check_mark: |                                                                                                                             |
| C_Login            | :heavy_check_mark: | The pin is used as the password, login in as an SO means logging in with an admin account ("admin" username set by default) |
| C_Logout           | :heavy_check_mark: |                                                                                                                             |
| C_WaitForSlotEvent | :x:                | May be used to poll for the status of the server, requires a lot of work                                                    |

## Decrypt

| Feature               | Status             | Notes                                                                                                            |
| --------------------- | ------------------ | ---------------------------------------------------------------------------------------------------------------- |
| C_DecryptInit         | :heavy_check_mark: |                                                                                                                  |
| C_Decrypt             | :heavy_check_mark: |                                                                                                                  |
| C_DecryptUpdate       | :heavy_check_mark: | The length of the output buffer will always be 0, the decrypted data will be all sent in the C_DecryptFinal call |
| C_DecryptFinal        | :heavy_check_mark: |                                                                                                                  |
| C_DecryptVerifyUpdate | :x:                | Verify is not supported by NetHSM                                                                                |

## Encrypt

| Feature         | Status             | Notes                                                 |
| --------------- | ------------------ | ----------------------------------------------------- |
| C_EncryptInit   | :heavy_check_mark: |                                                       |
| C_Encrypt       | :heavy_check_mark: |                                                       |
| C_EncryptUpdate | :heavy_check_mark: |                                                       |
| C_EncryptFinal  | :heavy_check_mark: | AES-CBC expects messages with a length multiple of 16 |

## Sign

| Feature             | Status             | Notes                    |
| ------------------- | ------------------ | ------------------------ |
| C_SignInit          | :heavy_check_mark: |                          |
| C_Sign              | :heavy_check_mark: |                          |
| C_SignUpdate        | :heavy_check_mark: |                          |
| C_SignFinal         | :heavy_check_mark: |                          |
| C_SignRecoverInit   | :x:                | May be implemented later |
| C_SignRecover       | :x:                | May be implemented later |
| C_SignEncryptUpdate | :x:                | Not supported by NetHSM  |

## Digest :x:

Digest is not supported by NetHSM

## Verify :x:

Verify is not supported by NetHSM

## Generation

| Feature           | Status             | Notes                                    |
| ----------------- | ------------------ | ---------------------------------------- |
| C_GenerateKey     | :heavy_check_mark: | Needs admin                              |
| C_GenerateKeyPair | :heavy_check_mark: | Needs admin                              |
| C_GenerateRandom  | :heavy_check_mark: |                                          |
| C_SeedRandom      | :warning:          | Returns OK but the arguments are ignored |
| C_WrapKey         | :x:                | Not supported by NetHSM                  |
| C_UnwrapKey       | :x:                | Not supported by NetHSM                  |
| C_DeriveKey       | :x:                | Not supported by NetHSM                  |

## Objects

| Feature             | Status             | Notes                                                               |
| ------------------- | ------------------ | ------------------------------------------------------------------- |
| C_FindObjectsInit   | :warning:          | Only lists the available keys                                       |
| C_FindObjects       | :warning:          | Only lists the available keys                                       |
| C_FindObjectsFinal  | :heavy_check_mark: |                                                                     |
| C_GetAttributeValue | :heavy_check_mark: |                                                                     |
| C_GetObjectSize     | :heavy_check_mark: |                                                                     |
| C_CreateObject      | :warning:          | Needs to be logged as admin (SO). Only private keys can be added.   |
| C_CopyObject        | :warning:          | Always returns CKR_ACTION_PROHIBITED                                |
| C_DestroyObject     | :warning:          | Needs to be logged as admin (SO). Only private keys can be deleted. |
| C_SetAttributeValue | :warning:          | Always returns CKR_ACTION_PROHIBITED                                |

## Pin management

| Feature   | Status             | Notes                            |
| --------- | ------------------ | -------------------------------- |
| C_InitPIN | :x:                |                                  |
| C_SetPIN  | :heavy_check_mark: | Changes the password of the user |
