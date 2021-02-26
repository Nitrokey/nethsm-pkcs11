package core

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
	"strings"
	"unsafe"
)

const (
	libManufacturerID = "Nitrokey GmbH"
	libDescription    = "NetHSM PKCS#11 module"
	libVersionMajor   = 0
	libVersionMinor   = 1
	minPinLength      = 3
	maxPinLength      = 256
	serialNumber      = "1010101"
)

// assert that go CK_ULONG has correct size
const _ = byte(C.sizeof_CK_ULONG-unsafe.Sizeof(CK_ULONG(0))) << 8

// Extracts the Return Value from an error, and logs it.
func ErrorToRV(err error) C.CK_RV {
	if err == nil {
		return CKR_OK
	}
	//log.Debugf("%+v\n", err)
	switch err := err.(type) {
	case P11Error:
		log.Errorf("[%s] %s [Code %d]\n", err.Who, err.Description, int(err.Code))
		return C.CK_RV(err.Code)
	default:
		code := CKR_GENERAL_ERROR
		log.Errorf("[General error] %+v [Code %d]\n", err, int(code))
		return C.CK_RV(code)
	}
}

func str2Buf(s string, b []C.uchar) {
	sLen := len(s)
	bLen := len(b)
	if sLen < bLen {
		s += strings.Repeat(" ", bLen-sLen)
	}
	s2 := []byte(s)
	C.memcpy(unsafe.Pointer(&b[0]), unsafe.Pointer(&s2[0]), (C.size_t)(bLen))
}

//export C_Initialize
func C_Initialize(pInitArgs C.CK_VOID_PTR) C.CK_RV {
	log.Debugf("Called: C_Initialize")
	// by now, we support only CKF_OS_LOCKING_OK
	if App != nil {
		return CKR_CRYPTOKI_ALREADY_INITIALIZED
	}
	cInitArgs := (*C.CK_C_INITIALIZE_ARGS)(unsafe.Pointer(pInitArgs))
	if cInitArgs != nil && (cInitArgs.flags&CKF_OS_LOCKING_OK == 0 || cInitArgs.pReserved != nil) {
		return CKR_ARGUMENTS_BAD
	}
	var err error
	log.Infof("Initializing p11nethsm module")
	App, err = NewApplication()
	//log.Debugf("Created new app with %d slots.", len(App.Slots))
	return ErrorToRV(err)
}

//export C_Finalize
func C_Finalize(pReserved C.CK_VOID_PTR) C.CK_RV {
	log.Debugf("Called: C_Finalize\n")
	if App == nil {
		return CKR_CRYPTOKI_NOT_INITIALIZED
	}
	if pReserved != nil {
		return CKR_ARGUMENTS_BAD
	}
	err := App.Finalize()
	App = nil
	return ErrorToRV(err)
}

//export C_InitToken
func C_InitToken(slotID C.CK_SLOT_ID, pPin C.CK_UTF8CHAR_PTR, ulPinLen C.CK_ULONG, pLabel C.CK_UTF8CHAR_PTR) C.CK_RV {
	log.Debugf("Called: C_InitToken\n")
	return CKR_FUNCTION_NOT_SUPPORTED
}

//export C_InitPIN
func C_InitPIN(hSession C.CK_SESSION_HANDLE, pPin C.CK_UTF8CHAR_PTR, ulPinLen C.CK_ULONG) C.CK_RV {
	log.Debugf("Called: C_InitPIN\n")
	return CKR_FUNCTION_NOT_SUPPORTED
}

//export C_SetPIN
func C_SetPIN(hSession C.CK_SESSION_HANDLE, pOldPin C.CK_UTF8CHAR_PTR, ulOldPinLen C.CK_ULONG, pNewPin C.CK_UTF8CHAR_PTR, ulNewPinLen C.CK_ULONG) C.CK_RV {
	log.Debugf("Called: C_SetPIN\n")
	return CKR_FUNCTION_NOT_SUPPORTED
}

//export C_GetInfo
func C_GetInfo(pInfo C.CK_INFO_PTR) C.CK_RV {
	log.Debugf("Called: C_GetInfo\n")
	if App == nil {
		return CKR_CRYPTOKI_NOT_INITIALIZED
	}
	if pInfo == nil {
		return CKR_ARGUMENTS_BAD
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
	return CKR_OK
}

//export C_GetFunctionList
func C_GetFunctionList(ppFunctionList C.CK_FUNCTION_LIST_PTR_PTR) C.CK_RV {
	log.Debugf("Called: C_GetFunctionList\n")
	if ppFunctionList == nil {
		return CKR_ARGUMENTS_BAD
	}
	*ppFunctionList = &C.functionList
	return CKR_OK
}

//export C_GetSlotList
func C_GetSlotList(tokenPresent C.CK_BBOOL, pSlotList C.CK_SLOT_ID_PTR, pulCount C.CK_ULONG_PTR) C.CK_RV {
	log.Debugf("Called: C_GetSlotList\n")
	if App == nil {
		return CKR_CRYPTOKI_NOT_INITIALIZED
	}
	if pulCount == nil {
		return CKR_ARGUMENTS_BAD
	}
	bufSize := 0
	slotList := App.Slots
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
		return CKR_OK
	}
	if int(*pulCount) < bufSize {
		*pulCount = C.CK_ULONG(bufSize)
		return CKR_BUFFER_TOO_SMALL
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
	return CKR_OK
}

//export C_GetSlotInfo
func C_GetSlotInfo(slotId C.CK_SLOT_ID, pInfo C.CK_SLOT_INFO_PTR) C.CK_RV {
	log.Debugf("Called: C_GetSlotInfo\n")
	if App == nil {
		return CKR_CRYPTOKI_NOT_INITIALIZED
	}
	if pInfo == nil {
		return CKR_ARGUMENTS_BAD
	}
	slot, err := App.GetSlot(CK_SLOT_ID(slotId))
	if err != nil {
		return ErrorToRV(err)
	}
	err = slot.GetInfo(pInfo)
	if err != nil {
		return ErrorToRV(err)
	}
	//log.Debugf("pInfo: %v", *pInfo)
	return CKR_OK
}

//export C_GetTokenInfo
func C_GetTokenInfo(slotId C.CK_SLOT_ID, pInfo C.CK_TOKEN_INFO_PTR) C.CK_RV {
	log.Debugf("Called: C_GetTokenInfo\n")
	if App == nil {
		return CKR_CRYPTOKI_NOT_INITIALIZED
	}
	if pInfo == nil {
		return CKR_ARGUMENTS_BAD
	}
	slot, err := App.GetSlot(CK_SLOT_ID(slotId))
	if err != nil {
		return ErrorToRV(err)
	}
	token, err := slot.GetToken()
	if err != nil {
		return ErrorToRV(err)
	}
	err = token.GetInfo(pInfo)
	if err != nil {
		return ErrorToRV(err)
	}
	//log.Debugf("pInfo: %v", *pInfo)
	return CKR_OK
}

//export C_OpenSession
func C_OpenSession(slotId C.CK_SLOT_ID, flags C.CK_FLAGS, pApplication C.CK_VOID_PTR, notify C.CK_NOTIFY, phSession C.CK_SESSION_HANDLE_PTR) C.CK_RV {
	log.Debugf("Called: C_OpenSession\n")
	if App == nil {
		return CKR_CRYPTOKI_NOT_INITIALIZED
	}
	if flags == 0 {
		return CKR_SESSION_PARALLEL_NOT_SUPPORTED
	}
	if phSession == nil {
		return CKR_ARGUMENTS_BAD
	}
	slot, err := App.GetSlot(CK_SLOT_ID(slotId))
	if err != nil {
		return ErrorToRV(err)
	}
	_, err = slot.GetToken()
	if err != nil {
		return ErrorToRV(err)
	}
	session, err := slot.OpenSession(CK_FLAGS(flags))
	if err != nil {
		return ErrorToRV(err)
	}
	*phSession = C.CK_SESSION_HANDLE(session)
	return CKR_OK
}

//export C_CloseSession
func C_CloseSession(hSession C.CK_SESSION_HANDLE) C.CK_RV {
	log.Debugf("Called: C_CloseSession\n")
	if App == nil {
		return CKR_CRYPTOKI_NOT_INITIALIZED
	}
	slot, err := App.GetSessionSlot(CK_SESSION_HANDLE(hSession))
	if err != nil {
		return ErrorToRV(err)
	}
	err = slot.CloseSession(CK_SESSION_HANDLE(hSession))
	if err != nil {
		return ErrorToRV(err)
	}
	return CKR_OK
}

//export C_CloseAllSessions
func C_CloseAllSessions(slotId C.CK_SLOT_ID) C.CK_RV {
	log.Debugf("Called: C_CloseAllSessions\n")
	if App == nil {
		return CKR_CRYPTOKI_NOT_INITIALIZED
	}
	slot, err := App.GetSlot(CK_SLOT_ID(slotId))
	if err != nil {
		return ErrorToRV(err)
	}
	slot.CloseAllSessions()
	return CKR_OK
}

//export C_GetSessionInfo
func C_GetSessionInfo(hSession C.CK_SESSION_HANDLE, pInfo C.CK_SESSION_INFO_PTR) C.CK_RV {
	log.Debugf("Called: C_GetSessionInfo\n")
	if App == nil {
		return CKR_CRYPTOKI_NOT_INITIALIZED
	}
	session, err := App.GetSession(CK_SESSION_HANDLE(hSession))
	if err != nil {
		return ErrorToRV(err)
	}
	err = session.GetInfo(pInfo)
	if err != nil {
		return ErrorToRV(err)
	}
	return CKR_OK
}

//export C_Login
func C_Login(hSession C.CK_SESSION_HANDLE, userType C.CK_USER_TYPE, pPin C.CK_UTF8CHAR_PTR, ulPinLen C.CK_ULONG) C.CK_RV {
	log.Debugf("Called: C_Login\n")
	if App == nil {
		return CKR_CRYPTOKI_NOT_INITIALIZED
	}
	if pPin == nil {
		return CKR_ARGUMENTS_BAD
	}
	session, err := App.GetSession(CK_SESSION_HANDLE(hSession))
	if err != nil {
		return ErrorToRV(err)
	}
	pin := string(C.GoBytes(unsafe.Pointer(pPin), C.int(ulPinLen)))
	err = session.Login(CK_USER_TYPE(userType), pin)
	if err != nil {
		return ErrorToRV(err)
	}
	return CKR_OK
}

//export C_Logout
func C_Logout(hSession C.CK_SESSION_HANDLE) C.CK_RV {
	log.Debugf("Called: C_Logout\n")
	if App == nil {
		return CKR_CRYPTOKI_NOT_INITIALIZED
	}
	session, err := App.GetSession(CK_SESSION_HANDLE(hSession))
	if err != nil {
		// log.Errorf("error! %v\n", err)
		return ErrorToRV(err)
	}
	err = session.Logout()
	if err != nil {
		// log.Errorf("error! %v", err)
		return ErrorToRV(err)
	}
	// log.Debugf("Logged out.")
	return CKR_OK
}

//export C_CreateObject
func C_CreateObject(hSession C.CK_SESSION_HANDLE, pTemplate C.CK_ATTRIBUTE_PTR, ulCount C.CK_ULONG, phObject C.CK_OBJECT_HANDLE_PTR) C.CK_RV {
	log.Debugf("Called: C_CreateObject\n")
	return CKR_FUNCTION_NOT_SUPPORTED
}

//export C_DestroyObject
func C_DestroyObject(hSession C.CK_SESSION_HANDLE, hObject C.CK_OBJECT_HANDLE) C.CK_RV {
	log.Debugf("Called: C_DestroyObject\n")
	return CKR_FUNCTION_NOT_SUPPORTED
}

//export C_FindObjectsInit
func C_FindObjectsInit(hSession C.CK_SESSION_HANDLE, pTemplate C.CK_ATTRIBUTE_PTR, ulCount C.CK_ULONG) C.CK_RV {
	log.Debugf("Called: C_FindObjectsInit\n")
	if App == nil {
		return CKR_CRYPTOKI_NOT_INITIALIZED
	}
	// log.Debugf("Template: %v\n", pTemplate)
	if ulCount > 0 && pTemplate == nil {
		return CKR_ARGUMENTS_BAD
	}
	session, err := App.GetSession(CK_SESSION_HANDLE(hSession))
	if err != nil {
		return ErrorToRV(err)
	}
	var attrs Attributes
	if ulCount > 0 {
		attrs, err = CToAttributes(pTemplate, ulCount)
		if err != nil {
			return ErrorToRV(err)
		}
	}
	err = session.FindObjectsInit(attrs)
	if err != nil {
		return ErrorToRV(err)
	}
	return CKR_OK
}

//export C_FindObjects
func C_FindObjects(hSession C.CK_SESSION_HANDLE, phObject C.CK_OBJECT_HANDLE_PTR, ulMaxObjectCount C.CK_ULONG, pulObjectCount C.CK_ULONG_PTR) C.CK_RV {
	log.Debugf("Called: C_FindObjects\n")
	if App == nil {
		return CKR_CRYPTOKI_NOT_INITIALIZED
	}
	if phObject == nil || pulObjectCount == nil {
		return CKR_ARGUMENTS_BAD
	}
	session, err := App.GetSession(CK_SESSION_HANDLE(hSession))
	if err != nil {
		return ErrorToRV(err)
	}

	handles, err := session.FindObjects(int(ulMaxObjectCount))
	if err != nil {
		return ErrorToRV(err)
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
	return CKR_OK
}

//export C_FindObjectsFinal
func C_FindObjectsFinal(hSession C.CK_SESSION_HANDLE) C.CK_RV {
	log.Debugf("Called: C_FindObjectsFinal\n")
	if App == nil {
		return CKR_CRYPTOKI_NOT_INITIALIZED
	}
	session, err := App.GetSession(CK_SESSION_HANDLE(hSession))
	if err != nil {
		return ErrorToRV(err)
	}
	err = session.FindObjectsFinal()
	if err != nil {
		return ErrorToRV(err)
	}
	return CKR_OK
}

//export C_SetAttributeValue
func C_SetAttributeValue(hSession C.CK_SESSION_HANDLE, hObject C.CK_OBJECT_HANDLE, pTemplate C.CK_ATTRIBUTE_PTR,
	ulCount C.CK_ULONG) C.CK_RV {
	log.Debugf("Called: C_SetAttributeValue\n")
	return CKR_FUNCTION_NOT_SUPPORTED
}

//export C_GetAttributeValue
func C_GetAttributeValue(hSession C.CK_SESSION_HANDLE, hObject C.CK_OBJECT_HANDLE, pTemplate C.CK_ATTRIBUTE_PTR, ulCount C.CK_ULONG) C.CK_RV {
	log.Debugf("Called: C_GetAttributeValue, session:%v, object:%v\n", hSession, hObject)
	if App == nil {
		return CKR_CRYPTOKI_NOT_INITIALIZED
	}
	session, err := App.GetSession(CK_SESSION_HANDLE(hSession))
	if err != nil {
		return ErrorToRV(err)
	}
	object, err := session.GetObject(CK_OBJECT_HANDLE(hObject))
	if err != nil {
		return ErrorToRV(err)
	}
	// log.Debugf("Obj Attr: %+v", object.Attributes)
	if err := object.CopyAttributes(pTemplate, ulCount); err != nil {
		return ErrorToRV(err)
	}
	return CKR_OK
}

//export C_GenerateKeyPair
func C_GenerateKeyPair(hSession C.CK_SESSION_HANDLE, pMechanism C.CK_MECHANISM_PTR, pPublicKeyTemplate C.CK_ATTRIBUTE_PTR, ulPublicKeyAttributeCount C.CK_ULONG, pPrivateKeyTemplate C.CK_ATTRIBUTE_PTR, ulPrivateKeyAttributeCount C.CK_ULONG, phPublicKey C.CK_OBJECT_HANDLE_PTR, phPrivateKey C.CK_OBJECT_HANDLE_PTR) C.CK_RV {
	log.Debugf("Called: C_GenerateKeyPair\n")
	return CKR_FUNCTION_NOT_SUPPORTED
}

const _ = (C.sizeof_CK_OBJECT_HANDLE - unsafe.Sizeof(CK_OBJECT_HANDLE(0))) << 128

//export C_SignInit
func C_SignInit(hSession C.CK_SESSION_HANDLE, pMechanism C.CK_MECHANISM_PTR, hKey C.CK_OBJECT_HANDLE) C.CK_RV {
	log.Debugf("Called: C_SignInit\n")
	if App == nil {
		return CKR_CRYPTOKI_NOT_INITIALIZED
	}
	session, err := App.GetSession(CK_SESSION_HANDLE(hSession))
	if err != nil {
		return ErrorToRV(err)
	}
	mechanism := CToMechanism(pMechanism)
	err = session.SignInit(mechanism, CK_OBJECT_HANDLE(hKey))
	if err != nil {
		return ErrorToRV(err)
	}
	return CKR_OK
}

//export C_SignUpdate
func C_SignUpdate(hSession C.CK_SESSION_HANDLE, pPart C.CK_BYTE_PTR, ulPartLen C.CK_ULONG) C.CK_RV {
	log.Debugf("Called: C_SignUpdate\n")
	if App == nil {
		return CKR_CRYPTOKI_NOT_INITIALIZED
	}
	session, err := App.GetSession(CK_SESSION_HANDLE(hSession))
	if err != nil {
		return ErrorToRV(err)
	}
	data := C.GoBytes(unsafe.Pointer(pPart), C.int(ulPartLen))
	err = session.SignUpdate(data)
	if err != nil {
		return ErrorToRV(err)
	}
	return CKR_OK
}

//export C_SignFinal
func C_SignFinal(hSession C.CK_SESSION_HANDLE, pSignature C.CK_BYTE_PTR, pulSignatureLen C.CK_ULONG_PTR) C.CK_RV {
	log.Debugf("Called: C_SignFinal\n")
	if App == nil {
		return CKR_CRYPTOKI_NOT_INITIALIZED
	}
	session, err := App.GetSession(CK_SESSION_HANDLE(hSession))
	if err != nil {
		return ErrorToRV(err)
	}
	if pulSignatureLen == nil {
		session.SignClear()
		return CKR_ARGUMENTS_BAD
	}
	signature, err := session.SignFinal()
	// log.Debugf("signFinal done")
	if err != nil {
		session.SignClear()
		return ErrorToRV(err)
	}
	sigLen := C.CK_ULONG(len(signature))
	if pSignature == nil {
		*pulSignatureLen = sigLen
		return CKR_OK
	} else if *pulSignatureLen < sigLen {
		*pulSignatureLen = sigLen
		return CKR_BUFFER_TOO_SMALL
	}
	*pulSignatureLen = sigLen
	C.memcpy(unsafe.Pointer(pSignature), unsafe.Pointer(&signature[0]), *pulSignatureLen)
	session.SignClear()
	return CKR_OK
}

//export C_Sign
func C_Sign(hSession C.CK_SESSION_HANDLE, pData C.CK_BYTE_PTR, ulDataLen C.CK_ULONG, pSignature C.CK_BYTE_PTR, pulSignatureLen C.CK_ULONG_PTR) C.CK_RV {
	log.Debugf("Called: C_Sign\n")
	if App == nil {
		return CKR_CRYPTOKI_NOT_INITIALIZED
	}
	session, err := App.GetSession(CK_SESSION_HANDLE(hSession))
	if err != nil {
		return ErrorToRV(err)
	}
	if pulSignatureLen == nil {
		session.SignClear()
		return CKR_ARGUMENTS_BAD
	}

	data := C.GoBytes(unsafe.Pointer(pData), C.int(ulDataLen))
	err = session.SignUpdate(data)
	if err != nil {
		session.SignClear()
		return ErrorToRV(err)
	}
	signature, err := session.SignFinal()
	if err != nil {
		session.SignClear()
		return ErrorToRV(err)
	}
	sigLen := C.CK_ULONG(len(signature))
	if pSignature == nil {
		*pulSignatureLen = sigLen
		return CKR_OK
	} else if *pulSignatureLen < sigLen {
		*pulSignatureLen = sigLen
		return CKR_BUFFER_TOO_SMALL
	}
	*pulSignatureLen = sigLen
	C.memcpy(unsafe.Pointer(pSignature), unsafe.Pointer(&signature[0]), *pulSignatureLen)
	session.SignClear()
	return CKR_OK
}

//export C_VerifyInit
func C_VerifyInit(hSession C.CK_SESSION_HANDLE, pMechanism C.CK_MECHANISM_PTR, hKey C.CK_OBJECT_HANDLE) C.CK_RV {
	log.Debugf("Called: C_VerifyInit\n")
	return CKR_FUNCTION_NOT_SUPPORTED
}

//export C_Verify
func C_Verify(hSession C.CK_SESSION_HANDLE, pData C.CK_BYTE_PTR, ulDataLen C.CK_ULONG, pSignature C.CK_BYTE_PTR, ulSignatureLen C.CK_ULONG) C.CK_RV {
	log.Debugf("Called: C_Verify\n")
	return CKR_FUNCTION_NOT_SUPPORTED
}

//export C_VerifyUpdate
func C_VerifyUpdate(hSession C.CK_SESSION_HANDLE, pPart C.CK_BYTE_PTR, ulPartLen C.CK_ULONG) C.CK_RV {
	log.Debugf("Called: C_VerifyUpdate\n")
	return CKR_FUNCTION_NOT_SUPPORTED
}

//export C_VerifyFinal
func C_VerifyFinal(hSession C.CK_SESSION_HANDLE, pSignature C.CK_BYTE_PTR, ulSignatureLen C.CK_ULONG) C.CK_RV {
	log.Debugf("Called: C_VerifyFinal\n")
	return CKR_FUNCTION_NOT_SUPPORTED
}

//export C_DecryptInit
func C_DecryptInit(hSession C.CK_SESSION_HANDLE, pMechanism C.CK_MECHANISM_PTR, hKey C.CK_OBJECT_HANDLE) C.CK_RV {
	log.Debugf("Called: C_DecryptInit")
	if App == nil {
		return CKR_CRYPTOKI_NOT_INITIALIZED
	}
	session, err := App.GetSession(CK_SESSION_HANDLE(hSession))
	if err != nil {
		return ErrorToRV(err)
	}
	mechanism := CToMechanism(pMechanism)
	err = session.DecryptInit(mechanism, CK_OBJECT_HANDLE(hKey))
	if err != nil {
		return ErrorToRV(err)
	}
	return CKR_OK
}

//export C_DecryptUpdate
func C_DecryptUpdate(hSession C.CK_SESSION_HANDLE, pEncryptedPart C.CK_BYTE_PTR,
	ulEncryptedPartLen C.CK_ULONG, pPart C.CK_BYTE_PTR,
	pulPartLen C.CK_ULONG_PTR) C.CK_RV {
	log.Debugf("Called: C_DecryptUpdate")
	if App == nil {
		return CKR_CRYPTOKI_NOT_INITIALIZED
	}
	session, err := App.GetSession(CK_SESSION_HANDLE(hSession))
	if err != nil {
		return ErrorToRV(err)
	}
	data := C.GoBytes(unsafe.Pointer(pEncryptedPart), C.int(ulEncryptedPartLen))
	err = session.SignUpdate(data)
	if err != nil {
		return ErrorToRV(err)
	}
	*pulPartLen = 0
	return CKR_OK
}

//export C_DecryptFinal
func C_DecryptFinal(hSession C.CK_SESSION_HANDLE, pLastPart C.CK_BYTE_PTR, pulLastPartLen C.CK_ULONG_PTR) C.CK_RV {
	log.Debugf("Called: C_DecryptFinal")
	if App == nil {
		return CKR_CRYPTOKI_NOT_INITIALIZED
	}
	session, err := App.GetSession(CK_SESSION_HANDLE(hSession))
	if err != nil {
		return ErrorToRV(err)
	}
	if pulLastPartLen == nil {
		session.DecryptClear()
		return CKR_ARGUMENTS_BAD
	}
	data, err := session.SignFinal()
	if err != nil {
		session.DecryptClear()
		return ErrorToRV(err)
	}
	dataLen := C.CK_ULONG(len(data))
	if pLastPart == nil {
		*pulLastPartLen = dataLen
		return CKR_OK
	} else if *pulLastPartLen < dataLen {
		*pulLastPartLen = dataLen
		return CKR_BUFFER_TOO_SMALL
	}
	*pulLastPartLen = dataLen
	C.memcpy(unsafe.Pointer(pLastPart), unsafe.Pointer(&data[0]), *pulLastPartLen)
	session.DecryptClear()
	return CKR_OK
}

//export C_Decrypt
func C_Decrypt(hSession C.CK_SESSION_HANDLE, pEncryptedData C.CK_BYTE_PTR,
	ulEncryptedDataLen C.CK_ULONG, pData C.CK_BYTE_PTR,
	pulDataLen C.CK_ULONG_PTR) C.CK_RV {
	log.Debugf("Called: C_Decrypt")
	if App == nil {
		return CKR_CRYPTOKI_NOT_INITIALIZED
	}
	session, err := App.GetSession(CK_SESSION_HANDLE(hSession))
	if err != nil {
		return ErrorToRV(err)
	}
	if pulDataLen == nil {
		session.DecryptClear()
		return CKR_ARGUMENTS_BAD
	}
	encrypted := C.GoBytes(unsafe.Pointer(pEncryptedData), C.int(ulEncryptedDataLen))
	err = session.DecryptUpdate(encrypted)
	if err != nil {
		session.DecryptClear()
		return ErrorToRV(err)
	}
	data, err := session.DecryptFinal()
	// log.Debugf("signFinal ended")
	if err != nil {
		session.DecryptClear()
		return ErrorToRV(err)
	}
	dataLen := C.CK_ULONG(len(data))
	if pData == nil {
		*pulDataLen = dataLen
		return CKR_OK
	} else if *pulDataLen < dataLen {
		*pulDataLen = dataLen
		return CKR_BUFFER_TOO_SMALL
	}
	*pulDataLen = dataLen
	C.memcpy(unsafe.Pointer(pData), unsafe.Pointer(&data[0]), *pulDataLen)
	session.DecryptClear()
	return CKR_OK
}

//export C_DigestInit
func C_DigestInit(hSession C.CK_SESSION_HANDLE, pMechanism C.CK_MECHANISM_PTR) C.CK_RV {
	log.Debugf("Called: C_DigestInit\n")
	return CKR_FUNCTION_NOT_SUPPORTED
}

//export C_Digest
func C_Digest(hSession C.CK_SESSION_HANDLE, pData C.CK_BYTE_PTR, ulDataLen C.CK_ULONG, pDigest C.CK_BYTE_PTR, pulDigestLen C.CK_ULONG_PTR) C.CK_RV {
	log.Debugf("Called: C_Digest\n")
	return CKR_FUNCTION_NOT_SUPPORTED
}

//export C_SeedRandom
func C_SeedRandom(hSession C.CK_SESSION_HANDLE, pSeed C.CK_BYTE_PTR, ulSeedLen C.CK_ULONG) C.CK_RV {
	log.Debugf("Called: C_SeedRandom\n")
	return CKR_FUNCTION_NOT_SUPPORTED
}

//export C_GenerateRandom
func C_GenerateRandom(hSession C.CK_SESSION_HANDLE, pRandomData C.CK_BYTE_PTR, ulRandomLen C.CK_ULONG) C.CK_RV {
	log.Debugf("Called: C_GenerateRandom\n")
	return CKR_FUNCTION_NOT_SUPPORTED
}

// NOTE: Not implemented functions...

//export C_GetMechanismList
func C_GetMechanismList(C.CK_SLOT_ID, C.CK_MECHANISM_TYPE_PTR, C.CK_ULONG_PTR) C.CK_RV {
	log.Debugf("Called: C_GetMechanismList")
	return CKR_FUNCTION_NOT_SUPPORTED
}

//export C_GetMechanismInfo
func C_GetMechanismInfo(C.CK_SLOT_ID, C.CK_MECHANISM_TYPE, C.CK_MECHANISM_INFO_PTR) C.CK_RV {
	log.Debugf("Called: C_GetMechanismInfo")
	return CKR_FUNCTION_NOT_SUPPORTED
}

//export C_GetOperationState
func C_GetOperationState(C.CK_SESSION_HANDLE, C.CK_BYTE_PTR, C.CK_ULONG_PTR) C.CK_RV {
	log.Debugf("Called: C_GetOperationState")
	return CKR_FUNCTION_NOT_SUPPORTED
}

//export C_SetOperationState
func C_SetOperationState(C.CK_SESSION_HANDLE, C.CK_BYTE_PTR, C.CK_ULONG, C.CK_OBJECT_HANDLE, C.CK_OBJECT_HANDLE) C.CK_RV {
	log.Debugf("Called: C_SetOperationState")
	return CKR_FUNCTION_NOT_SUPPORTED
}

//export C_CopyObject
func C_CopyObject(C.CK_SESSION_HANDLE, C.CK_OBJECT_HANDLE, C.CK_ATTRIBUTE_PTR, C.CK_ULONG, C.CK_OBJECT_HANDLE_PTR) C.CK_RV {
	log.Debugf("Called: C_CopyObject")
	return CKR_FUNCTION_NOT_SUPPORTED
}

//export C_GetObjectSize
func C_GetObjectSize(C.CK_SESSION_HANDLE, C.CK_OBJECT_HANDLE, C.CK_ULONG_PTR) C.CK_RV {
	log.Debugf("Called: C_GetObjectSize")
	return CKR_FUNCTION_NOT_SUPPORTED
}

//export C_EncryptInit
func C_EncryptInit(C.CK_SESSION_HANDLE, C.CK_MECHANISM_PTR, C.CK_OBJECT_HANDLE) C.CK_RV {
	log.Debugf("Called: C_EncryptInit")
	return CKR_FUNCTION_NOT_SUPPORTED
}

//export C_Encrypt
func C_Encrypt(C.CK_SESSION_HANDLE, C.CK_BYTE_PTR, C.CK_ULONG,
	C.CK_BYTE_PTR, C.CK_ULONG_PTR) C.CK_RV {
	return CKR_FUNCTION_NOT_SUPPORTED
}

//export C_EncryptUpdate
func C_EncryptUpdate(C.CK_SESSION_HANDLE, C.CK_BYTE_PTR, C.CK_ULONG, C.CK_BYTE_PTR, C.CK_ULONG_PTR) C.CK_RV {
	log.Debugf("Called: C_EncryptUpdate")
	return CKR_FUNCTION_NOT_SUPPORTED
}

//export C_EncryptFinal
func C_EncryptFinal(C.CK_SESSION_HANDLE, C.CK_BYTE_PTR, C.CK_ULONG_PTR) C.CK_RV {
	log.Debugf("Called: C_EncryptFinal")
	return CKR_FUNCTION_NOT_SUPPORTED
}

//export C_DigestUpdate
func C_DigestUpdate(C.CK_SESSION_HANDLE, C.CK_BYTE_PTR, C.CK_ULONG) C.CK_RV {
	log.Debugf("Called: C_DigestUpdate")
	return CKR_FUNCTION_NOT_SUPPORTED
}

//export C_DigestKey
func C_DigestKey(C.CK_SESSION_HANDLE, C.CK_OBJECT_HANDLE) C.CK_RV {
	log.Debugf("Called: C_DigestKey")
	return CKR_FUNCTION_NOT_SUPPORTED
}

//export C_DigestFinal
func C_DigestFinal(C.CK_SESSION_HANDLE, C.CK_BYTE_PTR, C.CK_ULONG_PTR) C.CK_RV {
	log.Debugf("Called: C_DigestFinal")
	return CKR_FUNCTION_NOT_SUPPORTED
}

//export C_SignRecoverInit
func C_SignRecoverInit(C.CK_SESSION_HANDLE, C.CK_MECHANISM_PTR, C.CK_OBJECT_HANDLE) C.CK_RV {
	log.Debugf("Called: C_SignRecoverInit")
	return CKR_FUNCTION_NOT_SUPPORTED
}

//export C_SignRecover
func C_SignRecover(C.CK_SESSION_HANDLE, C.CK_BYTE_PTR, C.CK_ULONG, C.CK_BYTE_PTR, C.CK_ULONG_PTR) C.CK_RV {
	log.Debugf("Called: C_SignRecover")
	return CKR_FUNCTION_NOT_SUPPORTED
}

//export C_VerifyRecoverInit
func C_VerifyRecoverInit(C.CK_SESSION_HANDLE, C.CK_MECHANISM_PTR, C.CK_OBJECT_HANDLE) C.CK_RV {
	log.Debugf("Called: C_VerifyRecoverInit")
	return CKR_FUNCTION_NOT_SUPPORTED
}

//export C_VerifyRecover
func C_VerifyRecover(C.CK_SESSION_HANDLE, C.CK_BYTE_PTR, C.CK_ULONG, C.CK_BYTE_PTR, C.CK_ULONG_PTR) C.CK_RV {
	log.Debugf("Called: C_VerifyRecover")
	return CKR_FUNCTION_NOT_SUPPORTED
}

//export C_DigestEncryptUpdate
func C_DigestEncryptUpdate(C.CK_SESSION_HANDLE, C.CK_BYTE_PTR, C.CK_ULONG, C.CK_BYTE_PTR, C.CK_ULONG_PTR) C.CK_RV {
	log.Debugf("Called: C_DigestEncryptUpdate")
	return CKR_FUNCTION_NOT_SUPPORTED
}

//export C_DecryptDigestUpdate
func C_DecryptDigestUpdate(C.CK_SESSION_HANDLE, C.CK_BYTE_PTR, C.CK_ULONG, C.CK_BYTE_PTR, C.CK_ULONG_PTR) C.CK_RV {
	log.Debugf("Called: C_DecryptDigestUpdate")
	return CKR_FUNCTION_NOT_SUPPORTED
}

//export C_SignEncryptUpdate
func C_SignEncryptUpdate(C.CK_SESSION_HANDLE, C.CK_BYTE_PTR, C.CK_ULONG, C.CK_BYTE_PTR, C.CK_ULONG_PTR) C.CK_RV {
	log.Debugf("Called: C_SignEncryptUpdate")
	return CKR_FUNCTION_NOT_SUPPORTED
}

//export C_DecryptVerifyUpdate
func C_DecryptVerifyUpdate(C.CK_SESSION_HANDLE, C.CK_BYTE_PTR, C.CK_ULONG, C.CK_BYTE_PTR, C.CK_ULONG_PTR) C.CK_RV {
	log.Debugf("Called: C_DecryptVerifyUpdate")
	return CKR_FUNCTION_NOT_SUPPORTED
}

//export C_GenerateKey
func C_GenerateKey(C.CK_SESSION_HANDLE, C.CK_MECHANISM_PTR, C.CK_ATTRIBUTE_PTR, C.CK_ULONG, C.CK_OBJECT_HANDLE_PTR) C.CK_RV {
	log.Debugf("Called: C_GenerateKey")
	return CKR_FUNCTION_NOT_SUPPORTED
}

//export C_WrapKey
func C_WrapKey(C.CK_SESSION_HANDLE, C.CK_MECHANISM_PTR, C.CK_OBJECT_HANDLE, C.CK_OBJECT_HANDLE,
	C.CK_BYTE_PTR, C.CK_ULONG_PTR) C.CK_RV {
	return CKR_FUNCTION_NOT_SUPPORTED
}

//export C_UnwrapKey
func C_UnwrapKey(C.CK_SESSION_HANDLE, C.CK_MECHANISM_PTR, C.CK_OBJECT_HANDLE, C.CK_BYTE_PTR, C.CK_ULONG,
	C.CK_ATTRIBUTE_PTR, C.CK_ULONG, C.CK_OBJECT_HANDLE_PTR) C.CK_RV {
	return CKR_FUNCTION_NOT_SUPPORTED
}

//export C_DeriveKey
func C_DeriveKey(C.CK_SESSION_HANDLE, C.CK_MECHANISM_PTR, C.CK_OBJECT_HANDLE, C.CK_ATTRIBUTE_PTR,
	C.CK_ULONG, C.CK_OBJECT_HANDLE_PTR) C.CK_RV {
	return CKR_FUNCTION_NOT_SUPPORTED
}

//export C_GetFunctionStatus
func C_GetFunctionStatus(C.CK_SESSION_HANDLE) C.CK_RV {
	log.Debugf("Called: C_GetFunctionStatus")
	return CKR_FUNCTION_NOT_SUPPORTED
}

//export C_CancelFunction
func C_CancelFunction(C.CK_SESSION_HANDLE) C.CK_RV {
	log.Debugf("Called: C_CancelFunction")
	return CKR_FUNCTION_NOT_SUPPORTED
}

//export C_WaitForSlotEvent
func C_WaitForSlotEvent(C.CK_FLAGS, C.CK_SLOT_ID_PTR, C.CK_VOID_PTR) C.CK_RV {
	log.Debugf("Called: C_WaitForSlotEvent")
	return CKR_FUNCTION_NOT_SUPPORTED
}
