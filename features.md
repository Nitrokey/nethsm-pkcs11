# Status of the pkcs implementation

- ✔️ : Fully functionnal
- ⚠️ : Some behaviors may not be implemented
- 🗓️ : Planned
- ❌ : Not in the current scope of the project

## Base features

| Feature           | Status |
| ----------------- | ------ |
| C_GetFunctionList | ✔️      |
| C_Initialize      | ✔️      |
| C_Finalize        | ✔️      |
| C_GetInfo         | ✔️      |

## Session

| Feature             | Status | Notes                             |
| ------------------- | ------ | --------------------------------- |
| C_OpenSession       | ⚠️      | Notify not supported              |
| C_CloseSession      | ✔️      |                                   |
| C_CloseAllSessions  | ✔️      |                                   |
| C_GetSessionInfo    | ✔️      |                                   |
| C_GetOperationState | ❌      |                                   |
| C_SetOperationState | ❌      |                                   |
| C_GetFunctionStatus | ✔️      | Returns CKR_FUNCTION_NOT_PARALLEL |
| C_CancelFunction    | ✔️      | Returns CKR_FUNCTION_NOT_PARALLEL |

## Token

| Feature            | Status | Notes                                     |
| ------------------ | ------ | ----------------------------------------- |
| C_GetSlotList      | ✔️      |                                           |
| C_GetSlotInfo      | ✔️      |                                           |
| C_GetTokenInfo     | ✔️      |                                           |
| C_InitToken        | ❌      |                                           |
| C_GetMechanismList | ✔️      |                                           |
| C_GetMechanismInfo | ✔️      | Length of the RSA public keys is set to 0 |
| C_Login            | ✔️      | The pin is used as the password           |
| C_Logout           | ✔️      |                                           |
| C_WaitForSlotEvent | ❌      |                                           |

## Decrypt

| Feature               | Status | Notes                                                        |
| --------------------- | ------ | ------------------------------------------------------------ |
| C_DecryptInit         | ✔️      |                                                              |
| C_Decrypt             | ⚠️      | Getting the size by setting pData to null is not implemented |
| C_DecryptUpdate       | 🗓️      |                                                              |
| C_DecryptFinal        | 🗓️      |                                                              |
| C_DecryptVerifyUpdate | ❌      | Verify is not supported by NetHSM                            |

## Encrypt

| Feature         | Status | Notes                                                         |
| --------------- | ------ | ------------------------------------------------------------- |
| C_EncryptInit   | ✔️      |                                                               |
| C_Encrypt       | ⚠️      | Getting the size by setting pData to null is not implemented. |
| C_EncryptUpdate | 🗓️      |                                                               |
| C_EncryptFinal  | 🗓️      |                                                               |

## Sign

| Feature             | Status | Notes                                                        |
| ------------------- | ------ | ------------------------------------------------------------ |
| C_SignInit          | ✔️      |                                                              |
| C_Sign              | ⚠️      | Getting the size by setting pData to null is not implemented |
| C_SignUpdate        | ✔️      |                                                              |
| C_SignFinal         | ⚠️      | Getting the size by setting pData to null is not implemented |
| C_SignRecoverInit   | ❌      | Maybe ?                                                      |
| C_SignRecover       | ❌      | Maybe ?                                                      |
| C_SignEncryptUpdate | ❌      |                                                              |

## Digest ❌

Digest is not supported by NetHSM

## Verify ❌

Verify is not supported by NetHSM

## Generation

| Feature           | Status | Notes                                    |
| ----------------- | ------ | ---------------------------------------- |
| C_GenerateKey     | 🗓️      |                                          |
| C_GenerateKeyPair | 🗓️      |                                          |
| C_GenerateRandom  | 🗓️      |                                          |
| C_SeedRandom      | ⚠️      | Returns OK but the arguments are ignored |
| C_WrapKey         | ❌      |                                          |
| C_UnwrapKey       | ❌      |                                          |
| C_DeriveKey       | ❌      |                                          |

## Objects

| Feature             | Status | Notes                                |
| ------------------- | ------ | ------------------------------------ |
| C_FindObjectsInit   | ⚠️      | Only lists the available keys        |
| C_FindObjects       | ⚠️      | Only lists the available keys        |
| C_FindObjectsFinal  | ✔️      |                                      |
| C_GetAttributeValue | ✔️      |                                      |
| C_GetObjectSize     | 🗓️      |                                      |
| C_CreateObject      | 🗓️      | maybe ? need to be admin ?           |
| C_CopyObject        | ✔️      | Always returns CKR_ACTION_PROHIBITED |
| C_DestroyObject     | 🗓️      | maybe ?                              |
| C_SetAttributeValue | ✔️      | Always returns CKR_ACTION_PROHIBITED |

## Pin management ❌

| Feature   | Status | Notes         |
| --------- | ------ | ------------- |
| C_InitPIN | ❌      | Not supported |
| C_SetPIN  | ❌      |               |
