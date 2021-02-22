package core

/*
#include "pkcs11go.h"
*/
import "C"

import (
	"encoding/base64"
	"p11nethsm/api"
)

type OpContextRSA struct {
	session     *Session
	mechanism   *Mechanism // Mechanism used to sign in a Sign session.
	keyID       string     // Key ID used in signing.
	data        []byte     // Data to sign.
	initialized bool       // // True if the user executed a Sign method and it has not finished yet.
}

type SignContextRSA struct {
	OpContextRSA
}

type DecryptContextRSA struct {
	OpContextRSA
}

//type VerifyContextRSA contextRSA

func (context *OpContextRSA) Initialized() bool {
	return context.initialized
}

func (context *OpContextRSA) Init() (err error) {
	context.initialized = true
	return
}

func (context *OpContextRSA) ResultLength() int {
	// log.Debugf("context: %v", context)
	return 0 // XXX
}

func (context *OpContextRSA) Update(data []byte) error {
	context.data = append(context.data, data...)
	return nil
}

func (context *SignContextRSA) Final() ([]byte, error) {
	var err error
	var reqBody api.SignRequestData
	reqBody.SetMessage(base64.StdEncoding.EncodeToString(context.data))
	mode, err := context.mechanism.SignMode()
	if err != nil {
		return nil, err
	}
	reqBody.SetMode(mode)
	sigData, r, err := App.Api.KeysKeyIDSignPost(
		context.session.Slot.token.ApiCtx(), context.keyID).Body(reqBody).Execute()
	if err != nil {
		// log.Debugf("%v\n", r)
		// log.Debugf("%v\n", r.Request.Body)
		return nil, NewAPIError("SignContextRSA.Final()", "Signing failed.", r, err)
	}
	signature, err := base64.StdEncoding.DecodeString(sigData.GetSignature())
	if err != nil {
		return nil, err
	}
	return signature, nil
}

func (context *DecryptContextRSA) Final() ([]byte, error) {
	var err error
	var reqBody api.DecryptRequestData
	reqBody.SetEncrypted(base64.StdEncoding.EncodeToString(context.data))
	mode, err := context.mechanism.DecryptMode()
	if err != nil {
		return nil, err
	}
	reqBody.SetMode(mode)
	decryptData, r, err := App.Api.KeysKeyIDDecryptPost(
		context.session.Slot.token.ApiCtx(), context.keyID).Body(reqBody).Execute()
	if err != nil {
		// log.Debugf("%v\n", r)
		// log.Debugf("%v\n", r.Request.Body)
		return nil, NewAPIError("DecryptContextRSA.Final()", "Decryption failed.", r, err)
	}
	decrypted, err := base64.StdEncoding.DecodeString(decryptData.GetDecrypted())
	if err != nil {
		return nil, err
	}
	return decrypted, nil
}
