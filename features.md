# Status of the pkcs11 module implementation

- ✔️ : Fully functionnal
- ⚠️ : Some behaviors may not be implemented
- 🗓️ : Planned
- ❌ : Not in the current scope of the project

## Concurrency

As of current version concurrency is not yet implemented.

## Base features

| Feature           | Status | Notes                         |
| ----------------- | ------ | ----------------------------- |
| C_GetFunctionList | ✔️      |                               |
| C_Initialize      | ⚠️      | Concurrency not yet supported |
| C_Finalize        | ✔️      |                               |
| C_GetInfo         | ✔️      |                               |

## Session

| Feature             | Status | Notes                             |
| ------------------- | ------ | --------------------------------- |
| C_OpenSession       | ⚠️      | Notify not supported              |
| C_CloseSession      | ✔️      |                                   |
| C_CloseAllSessions  | ✔️      |                                   |
| C_GetSessionInfo    | ✔️      |                                   |
| C_GetOperationState | ❌      | May be implemented later          |
| C_SetOperationState | ❌      | May be implemented later          |
| C_GetFunctionStatus | ✔️      | Returns CKR_FUNCTION_NOT_PARALLEL |
| C_CancelFunction    | ✔️      | Returns CKR_FUNCTION_NOT_PARALLEL |

## Token

| Feature            | Status | Notes                                                                                                                       |
| ------------------ | ------ | --------------------------------------------------------------------------------------------------------------------------- |
| C_GetSlotList      | ✔️      |                                                                                                                             |
| C_GetSlotInfo      | ✔️      |                                                                                                                             |
| C_GetTokenInfo     | ✔️      |                                                                                                                             |
| C_InitToken        | ❌      |                                                                                                                             |
| C_GetMechanismList | ✔️      |                                                                                                                             |
| C_GetMechanismInfo | ✔️      |                                                                                                                             |
| C_Login            | ✔️      | The pin is used as the password, login in as an SO means logging in with an admin account ("admin" username set by default) |
| C_Logout           | ✔️      |                                                                                                                             |
| C_WaitForSlotEvent | ❌      | May be used to poll for the status of the server, requires a lot of work                                                    |

## Decrypt

| Feature               | Status | Notes                                                                                                            |
| --------------------- | ------ | ---------------------------------------------------------------------------------------------------------------- |
| C_DecryptInit         | ✔️      |                                                                                                                  |
| C_Decrypt             | ✔️      |                                                                                                                  |
| C_DecryptUpdate       | ✔️      | The length of the output buffer will always be 0, the decrypted data will be all sent in the C_DecryptFinal call |
| C_DecryptFinal        | ✔️      |                                                                                                                  |
| C_DecryptVerifyUpdate | ❌      | Verify is not supported by NetHSM                                                                                |

## Encrypt

| Feature         | Status | Notes                                                 |
| --------------- | ------ | ----------------------------------------------------- |
| C_EncryptInit   | ✔️      |                                                       |
| C_Encrypt       | ✔️      |                                                       |
| C_EncryptUpdate | ✔️      |                                                       |
| C_EncryptFinal  | ✔️      | AES-CBC expects messages with a length multiple of 16 |

## Sign

| Feature             | Status | Notes                    |
| ------------------- | ------ | ------------------------ |
| C_SignInit          | ✔️      |                          |
| C_Sign              | ✔️      |                          |
| C_SignUpdate        | ✔️      |                          |
| C_SignFinal         | ✔️      |                          |
| C_SignRecoverInit   | ❌      | May be implemented later |
| C_SignRecover       | ❌      | May be implemented later |
| C_SignEncryptUpdate | ❌      | Not supported by NetHSM  |

## Digest ❌

Digest is not supported by NetHSM

## Verify ❌

Verify is not supported by NetHSM

## Generation

| Feature           | Status | Notes                                    |
| ----------------- | ------ | ---------------------------------------- |
| C_GenerateKey     | ✔️      | Needs admin                              |
| C_GenerateKeyPair | ✔️      | Needs admin                              |
| C_GenerateRandom  | ✔️      |                                          |
| C_SeedRandom      | ⚠️      | Returns OK but the arguments are ignored |
| C_WrapKey         | ❌      | Not supported by NetHSM                  |
| C_UnwrapKey       | ❌      | Not supported by NetHSM                  |
| C_DeriveKey       | ❌      | Not supported by NetHSM                  |

## Objects

| Feature             | Status | Notes                                                               |
| ------------------- | ------ | ------------------------------------------------------------------- |
| C_FindObjectsInit   | ⚠️      | Only lists the available keys                                       |
| C_FindObjects       | ⚠️      | Only lists the available keys                                       |
| C_FindObjectsFinal  | ✔️      |                                                                     |
| C_GetAttributeValue | ✔️      |                                                                     |
| C_GetObjectSize     | ✔️      |                                                                     |
| C_CreateObject      | ⚠️      | Needs to be logged as admin (SO). Only private keys can be added.   |
| C_CopyObject        | ✔️      | Always returns CKR_ACTION_PROHIBITED                                |
| C_DestroyObject     | ⚠️      | Needs to be logged as admin (SO). Only private keys can be deleted. |
| C_SetAttributeValue | ✔️      | Always returns CKR_ACTION_PROHIBITED                                |

## Pin management

| Feature   | Status | Notes                            |
| --------- | ------ | -------------------------------- |
| C_InitPIN | ❌      |                                  |
| C_SetPIN  | ✔️      | Changes the password of the user |
