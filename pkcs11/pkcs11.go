package pkcs11

/*
#include <stdlib.h>
#include <string.h>
#include "pkcs11go.h"
extern CK_FUNCTION_LIST functionList;
*/
import "C"
import (
	"math"
	"p11nethsm/log"
	"p11nethsm/module"
	"strings"
	"unsafe"
)

func str2Buf(s string, b []C.uchar) {
	sLen := len(s)
	bLen := len(b)
	if sLen < bLen {
		s += strings.Repeat(" ", bLen-sLen)
	}
	dst := []byte(s)
	C.memcpy(unsafe.Pointer(&b[0]), unsafe.Pointer(&dst[0]), (C.size_t)(bLen))
}

//export C_Initialize
func C_Initialize(pInitArgs C.CK_VOID_PTR) C.CK_RV {
	log.Debugf("Called: C_Initialize")
	if module.Initialized {
		return C.CKR_CRYPTOKI_ALREADY_INITIALIZED
	}
	if pInitArgs != nil {
		cInitArgs := (*C.CK_C_INITIALIZE_ARGS)(unsafe.Pointer(pInitArgs))
		if (cInitArgs.CreateMutex == nil && (cInitArgs.DestroyMutex != nil ||
			cInitArgs.LockMutex != nil || cInitArgs.UnlockMutex != nil)) ||
			(cInitArgs.CreateMutex != nil && (cInitArgs.DestroyMutex == nil ||
				cInitArgs.LockMutex == nil || cInitArgs.UnlockMutex == nil)) {
			log.Errorf("CKR_ARGUMENTS_BAD, cInitArgs: %v", cInitArgs)
			return C.CKR_ARGUMENTS_BAD
		}
		if (cInitArgs.flags & C.CKF_LIBRARY_CANT_CREATE_OS_THREADS) != 0 {
			log.Errorf("CKR_NEED_TO_CREATE_THREADS, InitArgs: %v", cInitArgs)
			return C.CKR_NEED_TO_CREATE_THREADS
		}
		if (cInitArgs.flags&C.CKF_OS_LOCKING_OK) == 0 &&
			cInitArgs.CreateMutex != nil {
			log.Errorf("CKR_CANT_LOCK, InitArgs: %v", cInitArgs)
			return C.CKR_CANT_LOCK
		}
	}
	log.Infof("Initializing p11nethsm module")
	err := module.Initialize()
	//log.Debugf("Created new app with %d slots.", len(module.App.Slots))
	return errorToRV(err)
}

//export C_Finalize
func C_Finalize(pReserved C.CK_VOID_PTR) C.CK_RV {
	log.Debugf("Called: C_Finalize\n")
	if !module.Initialized {
		return C.CKR_CRYPTOKI_NOT_INITIALIZED
	}
	if pReserved != nil {
		return C.CKR_ARGUMENTS_BAD
	}
	err := module.Finalize()
	return errorToRV(err)
}

//export C_InitToken
func C_InitToken(slotID C.CK_SLOT_ID, pPin C.CK_UTF8CHAR_PTR, ulPinLen C.CK_ULONG, pLabel C.CK_UTF8CHAR_PTR) C.CK_RV {
	log.Debugf("Called: C_InitToken\n")
	return C.CKR_FUNCTION_NOT_SUPPORTED
}

//export C_InitPIN
func C_InitPIN(hSession C.CK_SESSION_HANDLE, pPin C.CK_UTF8CHAR_PTR, ulPinLen C.CK_ULONG) C.CK_RV {
	log.Debugf("Called: C_InitPIN\n")
	return C.CKR_FUNCTION_NOT_SUPPORTED
}

//export C_SetPIN
func C_SetPIN(hSession C.CK_SESSION_HANDLE, pOldPin C.CK_UTF8CHAR_PTR, ulOldPinLen C.CK_ULONG, pNewPin C.CK_UTF8CHAR_PTR, ulNewPinLen C.CK_ULONG) C.CK_RV {
	log.Debugf("Called: C_SetPIN\n")
	return C.CKR_FUNCTION_NOT_SUPPORTED
}

//export C_GetInfo
func C_GetInfo(pInfo C.CK_INFO_PTR) C.CK_RV {
	log.Debugf("Called: C_GetInfo\n")
	if !module.Initialized {
		return C.CKR_CRYPTOKI_NOT_INITIALIZED
	}
	if pInfo == nil {
		return C.CKR_ARGUMENTS_BAD
	}
	info := (*C.CK_INFO)(unsafe.Pointer(pInfo))

	// log.Debugf("%v", &info.manufacturerID[0])
	str2Buf(libManufacturerID, info.manufacturerID[:])
	str2Buf(libDescription, info.libraryDescription[:])

	info.flags = 0
	info.cryptokiVersion.major = 2
	info.cryptokiVersion.minor = 40
	info.libraryVersion.major = libVersionMajor
	info.libraryVersion.minor = libVersionMinor
	return C.CKR_OK
}

//export C_GetFunctionList
func C_GetFunctionList(ppFunctionList C.CK_FUNCTION_LIST_PTR_PTR) C.CK_RV {
	log.Debugf("Called: C_GetFunctionList\n")
	if ppFunctionList == nil {
		return C.CKR_ARGUMENTS_BAD
	}
	*ppFunctionList = &C.functionList
	return C.CKR_OK
}

//export C_GetSlotList
func C_GetSlotList(tokenPresent C.CK_BBOOL, pSlotList C.CK_SLOT_ID_PTR, pulCount C.CK_ULONG_PTR) C.CK_RV {
	log.Debugf("Called: C_GetSlotList\n")
	if !module.Initialized {
		return C.CKR_CRYPTOKI_NOT_INITIALIZED
	}
	if pulCount == nil {
		return C.CKR_ARGUMENTS_BAD
	}
	bufSize := 0
	slotList := module.Slots
	if tokenPresent == C.CK_TRUE {
		for _, slot := range slotList {
			if slot.IsTokenPresent() {
				bufSize++
			}
		}
	} else {
		bufSize = len(slotList)
	}
	if pSlotList == nil {
		*pulCount = C.CK_ULONG(bufSize)
		return C.CKR_OK
	}
	if int(*pulCount) < bufSize {
		*pulCount = C.CK_ULONG(bufSize)
		return C.CKR_BUFFER_TOO_SMALL
	}

	cSlotSlice := (*[math.MaxInt32]C.CK_SLOT_ID)(unsafe.Pointer(pSlotList))[:*pulCount:*pulCount]

	i := 0
	for _, slot := range slotList {
		if slot.IsTokenPresent() || tokenPresent == C.CK_FALSE {
			cSlotSlice[i] = C.CK_SLOT_ID(slot.ID)
			i++
		}
	}

	*pulCount = C.CK_ULONG(bufSize)
	// log.Debugf("Slots: %d", *pulCount)
	return C.CKR_OK
}

//export C_GetSlotInfo
func C_GetSlotInfo(slotId C.CK_SLOT_ID, pInfo C.CK_SLOT_INFO_PTR) C.CK_RV {
	log.Debugf("Called: C_GetSlotInfo\n")
	if !module.Initialized {
		return C.CKR_CRYPTOKI_NOT_INITIALIZED
	}
	if pInfo == nil {
		return C.CKR_ARGUMENTS_BAD
	}
	slot, err := module.GetSlot(module.CK_SLOT_ID(slotId))
	if err != nil {
		return errorToRV(err)
	}
	err = getSlotInfo(slot, pInfo)
	if err != nil {
		return errorToRV(err)
	}
	//log.Debugf("pInfo: %v", *pInfo)
	return C.CKR_OK
}

//export C_GetTokenInfo
func C_GetTokenInfo(slotId C.CK_SLOT_ID, pInfo C.CK_TOKEN_INFO_PTR) C.CK_RV {
	log.Debugf("Called: C_GetTokenInfo\n")
	if !module.Initialized {
		return C.CKR_CRYPTOKI_NOT_INITIALIZED
	}
	if pInfo == nil {
		return C.CKR_ARGUMENTS_BAD
	}
	slot, err := module.GetSlot(module.CK_SLOT_ID(slotId))
	if err != nil {
		return errorToRV(err)
	}
	token, err := slot.GetToken()
	if err != nil {
		return errorToRV(err)
	}
	err = getTokenInfo(token, pInfo)
	if err != nil {
		return errorToRV(err)
	}
	//log.Debugf("pInfo: %v", *pInfo)
	return C.CKR_OK
}

//export C_OpenSession
func C_OpenSession(slotId C.CK_SLOT_ID, flags C.CK_FLAGS, pApplication C.CK_VOID_PTR, notify C.CK_NOTIFY, phSession C.CK_SESSION_HANDLE_PTR) C.CK_RV {
	log.Debugf("Called: C_OpenSession\n")
	if !module.Initialized {
		return C.CKR_CRYPTOKI_NOT_INITIALIZED
	}
	if flags == 0 {
		return C.CKR_SESSION_PARALLEL_NOT_SUPPORTED
	}
	if phSession == nil {
		return C.CKR_ARGUMENTS_BAD
	}
	slot, err := module.GetSlot(module.CK_SLOT_ID(slotId))
	if err != nil {
		return errorToRV(err)
	}
	_, err = slot.GetToken()
	if err != nil {
		return errorToRV(err)
	}
	session, err := slot.OpenSession(module.CK_FLAGS(flags))
	if err != nil {
		return errorToRV(err)
	}
	*phSession = C.CK_SESSION_HANDLE(session)
	return C.CKR_OK
}

//export C_CloseSession
func C_CloseSession(hSession C.CK_SESSION_HANDLE) C.CK_RV {
	log.Debugf("Called: C_CloseSession\n")
	if !module.Initialized {
		return C.CKR_CRYPTOKI_NOT_INITIALIZED
	}
	slot, err := module.GetSessionSlot(module.CK_SESSION_HANDLE(hSession))
	if err != nil {
		return errorToRV(err)
	}
	err = slot.CloseSession(module.CK_SESSION_HANDLE(hSession))
	if err != nil {
		return errorToRV(err)
	}
	return C.CKR_OK
}

//export C_CloseAllSessions
func C_CloseAllSessions(slotId C.CK_SLOT_ID) C.CK_RV {
	log.Debugf("Called: C_CloseAllSessions\n")
	if !module.Initialized {
		return C.CKR_CRYPTOKI_NOT_INITIALIZED
	}
	slot, err := module.GetSlot(module.CK_SLOT_ID(slotId))
	if err != nil {
		return errorToRV(err)
	}
	slot.CloseAllSessions()
	return C.CKR_OK
}

//export C_GetSessionInfo
func C_GetSessionInfo(hSession C.CK_SESSION_HANDLE, pInfo C.CK_SESSION_INFO_PTR) C.CK_RV {
	log.Debugf("Called: C_GetSessionInfo\n")
	if !module.Initialized {
		return C.CKR_CRYPTOKI_NOT_INITIALIZED
	}
	session, err := module.GetSession(module.CK_SESSION_HANDLE(hSession))
	if err != nil {
		return errorToRV(err)
	}
	err = getSessionInfo(session, pInfo)
	if err != nil {
		return errorToRV(err)
	}
	return C.CKR_OK
}

//export C_Login
func C_Login(hSession C.CK_SESSION_HANDLE, userType C.CK_USER_TYPE, pPin C.CK_UTF8CHAR_PTR, ulPinLen C.CK_ULONG) C.CK_RV {
	log.Debugf("Called: C_Login\n")
	if !module.Initialized {
		return C.CKR_CRYPTOKI_NOT_INITIALIZED
	}
	if pPin == nil {
		return C.CKR_ARGUMENTS_BAD
	}
	session, err := module.GetSession(module.CK_SESSION_HANDLE(hSession))
	if err != nil {
		return errorToRV(err)
	}
	pin := string(C.GoBytes(unsafe.Pointer(pPin), C.int(ulPinLen)))
	err = session.Login(module.CK_USER_TYPE(userType), pin)
	if err != nil {
		return errorToRV(err)
	}
	return C.CKR_OK
}

//export C_Logout
func C_Logout(hSession C.CK_SESSION_HANDLE) C.CK_RV {
	log.Debugf("Called: C_Logout\n")
	if !module.Initialized {
		return C.CKR_CRYPTOKI_NOT_INITIALIZED
	}
	session, err := module.GetSession(module.CK_SESSION_HANDLE(hSession))
	if err != nil {
		// log.Errorf("error! %v\n", err)
		return errorToRV(err)
	}
	err = session.Logout()
	if err != nil {
		// log.Errorf("error! %v", err)
		return errorToRV(err)
	}
	// log.Debugf("Logged out.")
	return C.CKR_OK
}

//export C_CreateObject
func C_CreateObject(hSession C.CK_SESSION_HANDLE, pTemplate C.CK_ATTRIBUTE_PTR, ulCount C.CK_ULONG, phObject C.CK_OBJECT_HANDLE_PTR) C.CK_RV {
	log.Debugf("Called: C_CreateObject\n")
	return C.CKR_FUNCTION_NOT_SUPPORTED
}

//export C_DestroyObject
func C_DestroyObject(hSession C.CK_SESSION_HANDLE, hObject C.CK_OBJECT_HANDLE) C.CK_RV {
	log.Debugf("Called: C_DestroyObject\n")
	return C.CKR_FUNCTION_NOT_SUPPORTED
}

//export C_FindObjectsInit
func C_FindObjectsInit(hSession C.CK_SESSION_HANDLE, pTemplate C.CK_ATTRIBUTE_PTR, ulCount C.CK_ULONG) C.CK_RV {
	log.Debugf("Called: C_FindObjectsInit\n")
	if !module.Initialized {
		return C.CKR_CRYPTOKI_NOT_INITIALIZED
	}
	// log.Debugf("Template: %v\n", pTemplate)
	if ulCount > 0 && pTemplate == nil {
		return C.CKR_ARGUMENTS_BAD
	}
	session, err := module.GetSession(module.CK_SESSION_HANDLE(hSession))
	if err != nil {
		return errorToRV(err)
	}
	var attrs module.Attributes
	if ulCount > 0 {
		attrs, err = cToAttributes(pTemplate, ulCount)
		if err != nil {
			return errorToRV(err)
		}
	}
	err = session.FindObjectsInit(attrs)
	if err != nil {
		return errorToRV(err)
	}
	return C.CKR_OK
}

//export C_FindObjects
func C_FindObjects(hSession C.CK_SESSION_HANDLE, phObject C.CK_OBJECT_HANDLE_PTR, ulMaxObjectCount C.CK_ULONG, pulObjectCount C.CK_ULONG_PTR) C.CK_RV {
	log.Debugf("Called: C_FindObjects\n")
	if !module.Initialized {
		return C.CKR_CRYPTOKI_NOT_INITIALIZED
	}
	if phObject == nil || pulObjectCount == nil {
		return C.CKR_ARGUMENTS_BAD
	}
	session, err := module.GetSession(module.CK_SESSION_HANDLE(hSession))
	if err != nil {
		return errorToRV(err)
	}

	handles, err := session.FindObjects(int(ulMaxObjectCount))
	if err != nil {
		return errorToRV(err)
	}

	cObjectSlice := (*[math.MaxInt32]C.CK_OBJECT_HANDLE)(unsafe.Pointer(phObject))[:ulMaxObjectCount:ulMaxObjectCount]

	l := len(cObjectSlice)
	if len(handles) < len(cObjectSlice) {
		l = len(handles)
	}
	for i := 0; i < l; i++ {
		cObjectSlice[i] = C.CK_OBJECT_HANDLE(handles[i])

	}
	*pulObjectCount = C.ulong(len(handles))
	return C.CKR_OK
}

//export C_FindObjectsFinal
func C_FindObjectsFinal(hSession C.CK_SESSION_HANDLE) C.CK_RV {
	log.Debugf("Called: C_FindObjectsFinal\n")
	if !module.Initialized {
		return C.CKR_CRYPTOKI_NOT_INITIALIZED
	}
	session, err := module.GetSession(module.CK_SESSION_HANDLE(hSession))
	if err != nil {
		return errorToRV(err)
	}
	err = session.FindObjectsFinal()
	if err != nil {
		return errorToRV(err)
	}
	return C.CKR_OK
}

//export C_SetAttributeValue
func C_SetAttributeValue(hSession C.CK_SESSION_HANDLE, hObject C.CK_OBJECT_HANDLE, pTemplate C.CK_ATTRIBUTE_PTR,
	ulCount C.CK_ULONG) C.CK_RV {
	log.Debugf("Called: C_SetAttributeValue\n")
	return C.CKR_FUNCTION_NOT_SUPPORTED
}

//export C_GetAttributeValue
func C_GetAttributeValue(hSession C.CK_SESSION_HANDLE, hObject C.CK_OBJECT_HANDLE, pTemplate C.CK_ATTRIBUTE_PTR, ulCount C.CK_ULONG) C.CK_RV {
	log.Debugf("Called: C_GetAttributeValue, session:%v, object:%v\n", hSession, hObject)
	if !module.Initialized {
		return C.CKR_CRYPTOKI_NOT_INITIALIZED
	}
	session, err := module.GetSession(module.CK_SESSION_HANDLE(hSession))
	if err != nil {
		return errorToRV(err)
	}
	object, err := session.GetObject(module.CK_OBJECT_HANDLE(hObject))
	if err != nil {
		return errorToRV(err)
	}
	// log.Debugf("Obj Attr: %+v", object.Attributes)
	if err := copyAttributes(object, pTemplate, ulCount); err != nil {
		return errorToRV(err)
	}
	return C.CKR_OK
}

//export C_GenerateKeyPair
func C_GenerateKeyPair(hSession C.CK_SESSION_HANDLE, pMechanism C.CK_MECHANISM_PTR, pPublicKeyTemplate C.CK_ATTRIBUTE_PTR, ulPublicKeyAttributeCount C.CK_ULONG, pPrivateKeyTemplate C.CK_ATTRIBUTE_PTR, ulPrivateKeyAttributeCount C.CK_ULONG, phPublicKey C.CK_OBJECT_HANDLE_PTR, phPrivateKey C.CK_OBJECT_HANDLE_PTR) C.CK_RV {
	log.Debugf("Called: C_GenerateKeyPair\n")
	return C.CKR_FUNCTION_NOT_SUPPORTED
}

//export C_SignInit
func C_SignInit(hSession C.CK_SESSION_HANDLE, pMechanism C.CK_MECHANISM_PTR, hKey C.CK_OBJECT_HANDLE) C.CK_RV {
	log.Debugf("Called: C_SignInit\n")
	if !module.Initialized {
		return C.CKR_CRYPTOKI_NOT_INITIALIZED
	}
	session, err := module.GetSession(module.CK_SESSION_HANDLE(hSession))
	if err != nil {
		return errorToRV(err)
	}
	mechanism := cToMechanism(pMechanism)
	log.Debugf("Object: %v Mechanism: %v", hKey, module.CKMString(mechanism.Type))
	err = session.SignInit(mechanism, module.CK_OBJECT_HANDLE(hKey))
	if err != nil {
		return errorToRV(err)
	}
	return C.CKR_OK
}

//export C_SignUpdate
func C_SignUpdate(hSession C.CK_SESSION_HANDLE, pPart C.CK_BYTE_PTR, ulPartLen C.CK_ULONG) C.CK_RV {
	log.Debugf("Called: C_SignUpdate\n")
	if !module.Initialized {
		return C.CKR_CRYPTOKI_NOT_INITIALIZED
	}
	session, err := module.GetSession(module.CK_SESSION_HANDLE(hSession))
	if err != nil {
		return errorToRV(err)
	}
	data := C.GoBytes(unsafe.Pointer(pPart), C.int(ulPartLen))
	err = session.SignUpdate(data)
	if err != nil {
		return errorToRV(err)
	}
	return C.CKR_OK
}

//export C_SignFinal
func C_SignFinal(hSession C.CK_SESSION_HANDLE, pSignature C.CK_BYTE_PTR, pulSignatureLen C.CK_ULONG_PTR) C.CK_RV {
	log.Debugf("Called: C_SignFinal\n")
	if !module.Initialized {
		return C.CKR_CRYPTOKI_NOT_INITIALIZED
	}
	session, err := module.GetSession(module.CK_SESSION_HANDLE(hSession))
	if err != nil {
		return errorToRV(err)
	}
	if pulSignatureLen == nil {
		session.SignClear()
		return C.CKR_ARGUMENTS_BAD
	}
	signature, err := session.SignFinal()
	// log.Debugf("signFinal done")
	if err != nil {
		session.SignClear()
		return errorToRV(err)
	}
	sigLen := C.CK_ULONG(len(signature))
	if pSignature == nil {
		*pulSignatureLen = sigLen
		return C.CKR_OK
	} else if *pulSignatureLen < sigLen {
		*pulSignatureLen = sigLen
		return C.CKR_BUFFER_TOO_SMALL
	}
	*pulSignatureLen = sigLen
	C.memcpy(unsafe.Pointer(pSignature), unsafe.Pointer(&signature[0]), *pulSignatureLen)
	session.SignClear()
	return C.CKR_OK
}

//export C_Sign
func C_Sign(hSession C.CK_SESSION_HANDLE, pData C.CK_BYTE_PTR, ulDataLen C.CK_ULONG, pSignature C.CK_BYTE_PTR, pulSignatureLen C.CK_ULONG_PTR) C.CK_RV {
	log.Debugf("Called: C_Sign\n")
	if !module.Initialized {
		return C.CKR_CRYPTOKI_NOT_INITIALIZED
	}
	session, err := module.GetSession(module.CK_SESSION_HANDLE(hSession))
	if err != nil {
		return errorToRV(err)
	}
	if pulSignatureLen == nil {
		session.SignClear()
		return C.CKR_ARGUMENTS_BAD
	}

	data := C.GoBytes(unsafe.Pointer(pData), C.int(ulDataLen))
	err = session.SignUpdate(data)
	if err != nil {
		session.SignClear()
		return errorToRV(err)
	}
	signature, err := session.SignFinal()
	if err != nil {
		session.SignClear()
		return errorToRV(err)
	}
	sigLen := C.CK_ULONG(len(signature))
	if pSignature == nil {
		*pulSignatureLen = sigLen
		return C.CKR_OK
	} else if *pulSignatureLen < sigLen {
		*pulSignatureLen = sigLen
		return C.CKR_BUFFER_TOO_SMALL
	}
	*pulSignatureLen = sigLen
	C.memcpy(unsafe.Pointer(pSignature), unsafe.Pointer(&signature[0]), *pulSignatureLen)
	session.SignClear()
	return C.CKR_OK
}

//export C_VerifyInit
func C_VerifyInit(hSession C.CK_SESSION_HANDLE, pMechanism C.CK_MECHANISM_PTR, hKey C.CK_OBJECT_HANDLE) C.CK_RV {
	log.Debugf("Called: C_VerifyInit\n")
	return C.CKR_FUNCTION_NOT_SUPPORTED
}

//export C_Verify
func C_Verify(hSession C.CK_SESSION_HANDLE, pData C.CK_BYTE_PTR, ulDataLen C.CK_ULONG, pSignature C.CK_BYTE_PTR, ulSignatureLen C.CK_ULONG) C.CK_RV {
	log.Debugf("Called: C_Verify\n")
	return C.CKR_FUNCTION_NOT_SUPPORTED
}

//export C_VerifyUpdate
func C_VerifyUpdate(hSession C.CK_SESSION_HANDLE, pPart C.CK_BYTE_PTR, ulPartLen C.CK_ULONG) C.CK_RV {
	log.Debugf("Called: C_VerifyUpdate\n")
	return C.CKR_FUNCTION_NOT_SUPPORTED
}

//export C_VerifyFinal
func C_VerifyFinal(hSession C.CK_SESSION_HANDLE, pSignature C.CK_BYTE_PTR, ulSignatureLen C.CK_ULONG) C.CK_RV {
	log.Debugf("Called: C_VerifyFinal\n")
	return C.CKR_FUNCTION_NOT_SUPPORTED
}

//export C_DecryptInit
func C_DecryptInit(hSession C.CK_SESSION_HANDLE, pMechanism C.CK_MECHANISM_PTR, hKey C.CK_OBJECT_HANDLE) C.CK_RV {
	log.Debugf("Called: C_DecryptInit")
	if !module.Initialized {
		return C.CKR_CRYPTOKI_NOT_INITIALIZED
	}
	session, err := module.GetSession(module.CK_SESSION_HANDLE(hSession))
	if err != nil {
		return errorToRV(err)
	}
	mechanism := cToMechanism(pMechanism)
	err = session.DecryptInit(mechanism, module.CK_OBJECT_HANDLE(hKey))
	if err != nil {
		return errorToRV(err)
	}
	return C.CKR_OK
}

//export C_DecryptUpdate
func C_DecryptUpdate(hSession C.CK_SESSION_HANDLE, pEncryptedPart C.CK_BYTE_PTR,
	ulEncryptedPartLen C.CK_ULONG, pPart C.CK_BYTE_PTR,
	pulPartLen C.CK_ULONG_PTR) C.CK_RV {
	log.Debugf("Called: C_DecryptUpdate")
	if !module.Initialized {
		return C.CKR_CRYPTOKI_NOT_INITIALIZED
	}
	session, err := module.GetSession(module.CK_SESSION_HANDLE(hSession))
	if err != nil {
		return errorToRV(err)
	}
	data := C.GoBytes(unsafe.Pointer(pEncryptedPart), C.int(ulEncryptedPartLen))
	err = session.SignUpdate(data)
	if err != nil {
		return errorToRV(err)
	}
	*pulPartLen = 0
	return C.CKR_OK
}

//export C_DecryptFinal
func C_DecryptFinal(hSession C.CK_SESSION_HANDLE, pLastPart C.CK_BYTE_PTR, pulLastPartLen C.CK_ULONG_PTR) C.CK_RV {
	log.Debugf("Called: C_DecryptFinal")
	if !module.Initialized {
		return C.CKR_CRYPTOKI_NOT_INITIALIZED
	}
	session, err := module.GetSession(module.CK_SESSION_HANDLE(hSession))
	if err != nil {
		return errorToRV(err)
	}
	if pulLastPartLen == nil {
		session.DecryptClear()
		return C.CKR_ARGUMENTS_BAD
	}
	data, err := session.SignFinal()
	if err != nil {
		session.DecryptClear()
		return errorToRV(err)
	}
	dataLen := C.CK_ULONG(len(data))
	if pLastPart == nil {
		*pulLastPartLen = dataLen
		return C.CKR_OK
	} else if *pulLastPartLen < dataLen {
		*pulLastPartLen = dataLen
		return C.CKR_BUFFER_TOO_SMALL
	}
	*pulLastPartLen = dataLen
	C.memcpy(unsafe.Pointer(pLastPart), unsafe.Pointer(&data[0]), *pulLastPartLen)
	session.DecryptClear()
	return C.CKR_OK
}

//export C_Decrypt
func C_Decrypt(hSession C.CK_SESSION_HANDLE, pEncryptedData C.CK_BYTE_PTR,
	ulEncryptedDataLen C.CK_ULONG, pData C.CK_BYTE_PTR,
	pulDataLen C.CK_ULONG_PTR) C.CK_RV {
	log.Debugf("Called: C_Decrypt")
	if !module.Initialized {
		return C.CKR_CRYPTOKI_NOT_INITIALIZED
	}
	session, err := module.GetSession(module.CK_SESSION_HANDLE(hSession))
	if err != nil {
		return errorToRV(err)
	}
	if pulDataLen == nil {
		session.DecryptClear()
		return C.CKR_ARGUMENTS_BAD
	}
	encrypted := C.GoBytes(unsafe.Pointer(pEncryptedData), C.int(ulEncryptedDataLen))
	err = session.DecryptUpdate(encrypted)
	if err != nil {
		session.DecryptClear()
		return errorToRV(err)
	}
	data, err := session.DecryptFinal()
	// log.Debugf("signFinal ended")
	if err != nil {
		session.DecryptClear()
		return errorToRV(err)
	}
	dataLen := C.CK_ULONG(len(data))
	if pData == nil {
		*pulDataLen = dataLen
		return C.CKR_OK
	} else if *pulDataLen < dataLen {
		*pulDataLen = dataLen
		return C.CKR_BUFFER_TOO_SMALL
	}
	*pulDataLen = dataLen
	C.memcpy(unsafe.Pointer(pData), unsafe.Pointer(&data[0]), *pulDataLen)
	session.DecryptClear()
	return C.CKR_OK
}

//export C_DigestInit
func C_DigestInit(hSession C.CK_SESSION_HANDLE, pMechanism C.CK_MECHANISM_PTR) C.CK_RV {
	log.Debugf("Called: C_DigestInit\n")
	return C.CKR_FUNCTION_NOT_SUPPORTED
}

//export C_Digest
func C_Digest(hSession C.CK_SESSION_HANDLE, pData C.CK_BYTE_PTR, ulDataLen C.CK_ULONG, pDigest C.CK_BYTE_PTR, pulDigestLen C.CK_ULONG_PTR) C.CK_RV {
	log.Debugf("Called: C_Digest\n")
	return C.CKR_FUNCTION_NOT_SUPPORTED
}

//export C_SeedRandom
func C_SeedRandom(hSession C.CK_SESSION_HANDLE, pSeed C.CK_BYTE_PTR, ulSeedLen C.CK_ULONG) C.CK_RV {
	log.Debugf("Called: C_SeedRandom\n")
	return C.CKR_FUNCTION_NOT_SUPPORTED
}

//export C_GenerateRandom
func C_GenerateRandom(hSession C.CK_SESSION_HANDLE, pRandomData C.CK_BYTE_PTR, ulRandomLen C.CK_ULONG) C.CK_RV {
	log.Debugf("Called: C_GenerateRandom\n")
	return C.CKR_FUNCTION_NOT_SUPPORTED
}

// NOTE: Not implemented functions...

//export C_GetMechanismList
func C_GetMechanismList(C.CK_SLOT_ID, C.CK_MECHANISM_TYPE_PTR, C.CK_ULONG_PTR) C.CK_RV {
	log.Debugf("Called: C_GetMechanismList")
	return C.CKR_FUNCTION_NOT_SUPPORTED
}

//export C_GetMechanismInfo
func C_GetMechanismInfo(C.CK_SLOT_ID, C.CK_MECHANISM_TYPE, C.CK_MECHANISM_INFO_PTR) C.CK_RV {
	log.Debugf("Called: C_GetMechanismInfo")
	return C.CKR_FUNCTION_NOT_SUPPORTED
}

//export C_GetOperationState
func C_GetOperationState(C.CK_SESSION_HANDLE, C.CK_BYTE_PTR, C.CK_ULONG_PTR) C.CK_RV {
	log.Debugf("Called: C_GetOperationState")
	return C.CKR_FUNCTION_NOT_SUPPORTED
}

//export C_SetOperationState
func C_SetOperationState(C.CK_SESSION_HANDLE, C.CK_BYTE_PTR, C.CK_ULONG, C.CK_OBJECT_HANDLE, C.CK_OBJECT_HANDLE) C.CK_RV {
	log.Debugf("Called: C_SetOperationState")
	return C.CKR_FUNCTION_NOT_SUPPORTED
}

//export C_CopyObject
func C_CopyObject(C.CK_SESSION_HANDLE, C.CK_OBJECT_HANDLE, C.CK_ATTRIBUTE_PTR, C.CK_ULONG, C.CK_OBJECT_HANDLE_PTR) C.CK_RV {
	log.Debugf("Called: C_CopyObject")
	return C.CKR_FUNCTION_NOT_SUPPORTED
}

//export C_GetObjectSize
func C_GetObjectSize(C.CK_SESSION_HANDLE, C.CK_OBJECT_HANDLE, C.CK_ULONG_PTR) C.CK_RV {
	log.Debugf("Called: C_GetObjectSize")
	return C.CKR_FUNCTION_NOT_SUPPORTED
}

//export C_EncryptInit
func C_EncryptInit(C.CK_SESSION_HANDLE, C.CK_MECHANISM_PTR, C.CK_OBJECT_HANDLE) C.CK_RV {
	log.Debugf("Called: C_EncryptInit")
	return C.CKR_FUNCTION_NOT_SUPPORTED
}

//export C_Encrypt
func C_Encrypt(C.CK_SESSION_HANDLE, C.CK_BYTE_PTR, C.CK_ULONG,
	C.CK_BYTE_PTR, C.CK_ULONG_PTR) C.CK_RV {
	return C.CKR_FUNCTION_NOT_SUPPORTED
}

//export C_EncryptUpdate
func C_EncryptUpdate(C.CK_SESSION_HANDLE, C.CK_BYTE_PTR, C.CK_ULONG, C.CK_BYTE_PTR, C.CK_ULONG_PTR) C.CK_RV {
	log.Debugf("Called: C_EncryptUpdate")
	return C.CKR_FUNCTION_NOT_SUPPORTED
}

//export C_EncryptFinal
func C_EncryptFinal(C.CK_SESSION_HANDLE, C.CK_BYTE_PTR, C.CK_ULONG_PTR) C.CK_RV {
	log.Debugf("Called: C_EncryptFinal")
	return C.CKR_FUNCTION_NOT_SUPPORTED
}

//export C_DigestUpdate
func C_DigestUpdate(C.CK_SESSION_HANDLE, C.CK_BYTE_PTR, C.CK_ULONG) C.CK_RV {
	log.Debugf("Called: C_DigestUpdate")
	return C.CKR_FUNCTION_NOT_SUPPORTED
}

//export C_DigestKey
func C_DigestKey(C.CK_SESSION_HANDLE, C.CK_OBJECT_HANDLE) C.CK_RV {
	log.Debugf("Called: C_DigestKey")
	return C.CKR_FUNCTION_NOT_SUPPORTED
}

//export C_DigestFinal
func C_DigestFinal(C.CK_SESSION_HANDLE, C.CK_BYTE_PTR, C.CK_ULONG_PTR) C.CK_RV {
	log.Debugf("Called: C_DigestFinal")
	return C.CKR_FUNCTION_NOT_SUPPORTED
}

//export C_SignRecoverInit
func C_SignRecoverInit(C.CK_SESSION_HANDLE, C.CK_MECHANISM_PTR, C.CK_OBJECT_HANDLE) C.CK_RV {
	log.Debugf("Called: C_SignRecoverInit")
	return C.CKR_FUNCTION_NOT_SUPPORTED
}

//export C_SignRecover
func C_SignRecover(C.CK_SESSION_HANDLE, C.CK_BYTE_PTR, C.CK_ULONG, C.CK_BYTE_PTR, C.CK_ULONG_PTR) C.CK_RV {
	log.Debugf("Called: C_SignRecover")
	return C.CKR_FUNCTION_NOT_SUPPORTED
}

//export C_VerifyRecoverInit
func C_VerifyRecoverInit(C.CK_SESSION_HANDLE, C.CK_MECHANISM_PTR, C.CK_OBJECT_HANDLE) C.CK_RV {
	log.Debugf("Called: C_VerifyRecoverInit")
	return C.CKR_FUNCTION_NOT_SUPPORTED
}

//export C_VerifyRecover
func C_VerifyRecover(C.CK_SESSION_HANDLE, C.CK_BYTE_PTR, C.CK_ULONG, C.CK_BYTE_PTR, C.CK_ULONG_PTR) C.CK_RV {
	log.Debugf("Called: C_VerifyRecover")
	return C.CKR_FUNCTION_NOT_SUPPORTED
}

//export C_DigestEncryptUpdate
func C_DigestEncryptUpdate(C.CK_SESSION_HANDLE, C.CK_BYTE_PTR, C.CK_ULONG, C.CK_BYTE_PTR, C.CK_ULONG_PTR) C.CK_RV {
	log.Debugf("Called: C_DigestEncryptUpdate")
	return C.CKR_FUNCTION_NOT_SUPPORTED
}

//export C_DecryptDigestUpdate
func C_DecryptDigestUpdate(C.CK_SESSION_HANDLE, C.CK_BYTE_PTR, C.CK_ULONG, C.CK_BYTE_PTR, C.CK_ULONG_PTR) C.CK_RV {
	log.Debugf("Called: C_DecryptDigestUpdate")
	return C.CKR_FUNCTION_NOT_SUPPORTED
}

//export C_SignEncryptUpdate
func C_SignEncryptUpdate(C.CK_SESSION_HANDLE, C.CK_BYTE_PTR, C.CK_ULONG, C.CK_BYTE_PTR, C.CK_ULONG_PTR) C.CK_RV {
	log.Debugf("Called: C_SignEncryptUpdate")
	return C.CKR_FUNCTION_NOT_SUPPORTED
}

//export C_DecryptVerifyUpdate
func C_DecryptVerifyUpdate(C.CK_SESSION_HANDLE, C.CK_BYTE_PTR, C.CK_ULONG, C.CK_BYTE_PTR, C.CK_ULONG_PTR) C.CK_RV {
	log.Debugf("Called: C_DecryptVerifyUpdate")
	return C.CKR_FUNCTION_NOT_SUPPORTED
}

//export C_GenerateKey
func C_GenerateKey(C.CK_SESSION_HANDLE, C.CK_MECHANISM_PTR, C.CK_ATTRIBUTE_PTR, C.CK_ULONG, C.CK_OBJECT_HANDLE_PTR) C.CK_RV {
	log.Debugf("Called: C_GenerateKey")
	return C.CKR_FUNCTION_NOT_SUPPORTED
}

//export C_WrapKey
func C_WrapKey(C.CK_SESSION_HANDLE, C.CK_MECHANISM_PTR, C.CK_OBJECT_HANDLE, C.CK_OBJECT_HANDLE,
	C.CK_BYTE_PTR, C.CK_ULONG_PTR) C.CK_RV {
	return C.CKR_FUNCTION_NOT_SUPPORTED
}

//export C_UnwrapKey
func C_UnwrapKey(C.CK_SESSION_HANDLE, C.CK_MECHANISM_PTR, C.CK_OBJECT_HANDLE, C.CK_BYTE_PTR, C.CK_ULONG,
	C.CK_ATTRIBUTE_PTR, C.CK_ULONG, C.CK_OBJECT_HANDLE_PTR) C.CK_RV {
	return C.CKR_FUNCTION_NOT_SUPPORTED
}

//export C_DeriveKey
func C_DeriveKey(C.CK_SESSION_HANDLE, C.CK_MECHANISM_PTR, C.CK_OBJECT_HANDLE, C.CK_ATTRIBUTE_PTR,
	C.CK_ULONG, C.CK_OBJECT_HANDLE_PTR) C.CK_RV {
	return C.CKR_FUNCTION_NOT_SUPPORTED
}

//export C_GetFunctionStatus
func C_GetFunctionStatus(C.CK_SESSION_HANDLE) C.CK_RV {
	log.Debugf("Called: C_GetFunctionStatus")
	return C.CKR_FUNCTION_NOT_SUPPORTED
}

//export C_CancelFunction
func C_CancelFunction(C.CK_SESSION_HANDLE) C.CK_RV {
	log.Debugf("Called: C_CancelFunction")
	return C.CKR_FUNCTION_NOT_SUPPORTED
}

//export C_WaitForSlotEvent
func C_WaitForSlotEvent(C.CK_FLAGS, C.CK_SLOT_ID_PTR, C.CK_VOID_PTR) C.CK_RV {
	log.Debugf("Called: C_WaitForSlotEvent")
	return C.CKR_FUNCTION_NOT_SUPPORTED
}
