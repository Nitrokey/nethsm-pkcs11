package module

import (
	"encoding/base64"
	"p11nethsm/api"
)

type opContextRSA struct {
	session     *Session
	keyID       string // Key ID used in signing or decrypting.
	data        []byte // Data to sign or decrypt.
	result      []byte
	initialized bool // // True if the user executed a Sign method and it has not finished yet.
}

type SignContextRSA struct {
	opContextRSA
	mode api.SignMode
}

type DecryptContextRSA struct {
	opContextRSA
	mode api.DecryptMode
}

//type VerifyContextRSA contextRSA

func (context *opContextRSA) Initialized() bool {
	return context.initialized
}

func (context *opContextRSA) Init() (err error) {
	context.initialized = true
	return
}

func (context *opContextRSA) ResultLength() int {
	// log.Debugf("context: %v", context)
	return 0 // XXX
}

func (context *opContextRSA) Update(data []byte) error {
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
	reqBody.SetMode(context.mode)
	sigData, r, err := Api.KeysKeyIDSignPost(
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
	reqBody.SetMode(context.mode)
	decryptData, r, err := Api.KeysKeyIDDecryptPost(
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
