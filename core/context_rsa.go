package core

import (
	"encoding/base64"
	"p11nethsm/api"
)

type OpContextRSA struct {
	session     *Session
	mechanism   *Mechanism // Mechanism used to sign in a Sign session.
	keyID       string     // Key ID used in signing or decrypting.
	data        []byte     // Data to sign or decrypt.
	result      []byte
	initialized bool // // True if the user executed a Sign method and it has not finished yet.
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
	if context.result == nil {
		context.data = append(context.data, data...)
	}
	return nil
}

func (context *SignContextRSA) Final() ([]byte, error) {
	if context.result != nil {
		return context.result, nil
	}
	var err error
	var reqBody api.SignRequestData
	reqBody.SetMessage(base64.StdEncoding.EncodeToString(context.data))
	mode, err := context.mechanism.SignMode()
	if err != nil {
		return nil, err
	}
	reqBody.SetMode(mode)
	sigData, r, err := Instance.Api.KeysKeyIDSignPost(
		context.session.Slot.Token.ApiCtx(), context.keyID).Body(reqBody).Execute()
	if err != nil {
		// log.Debugf("%v\n", r)
		// log.Debugf("%v\n", r.Request.Body)
		return nil, NewAPIError("SignContextRSA.Final()", "Signing failed.", r, err)
	}
	signature, err := base64.StdEncoding.DecodeString(sigData.GetSignature())
	if err != nil {
		return nil, err
	}
	context.result = signature
	return signature, nil
}

func (context *DecryptContextRSA) Final() ([]byte, error) {
	if context.result != nil {
		return context.result, nil
	}
	var err error
	var reqBody api.DecryptRequestData
	reqBody.SetEncrypted(base64.StdEncoding.EncodeToString(context.data))
	mode, err := context.mechanism.DecryptMode()
	if err != nil {
		return nil, err
	}
	reqBody.SetMode(mode)
	decryptData, r, err := Instance.Api.KeysKeyIDDecryptPost(
		context.session.Slot.Token.ApiCtx(), context.keyID).Body(reqBody).Execute()
	if err != nil {
		// log.Debugf("%v\n", r)
		// log.Debugf("%v\n", r.Request.Body)
		return nil, NewAPIError("DecryptContextRSA.Final()", "Decryption failed.", r, err)
	}
	decrypted, err := base64.StdEncoding.DecodeString(decryptData.GetDecrypted())
	if err != nil {
		return nil, err
	}
	context.result = decrypted
	return decrypted, nil
}
