package module

import (
	"encoding/base64"
	"errors"
	"math/big"
	"p11nethsm/api"

	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"
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

// type VerifyContextRSA contextRSA

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
	slot := context.session.Slot
	reqBody.SetMessage(base64.StdEncoding.EncodeToString(context.data))
	reqBody.SetMode(context.mode)
	sigData, r, err := slot.Api.KeysKeyIDSignPost(
		slot.Token.ApiCtx(), context.keyID).Body(reqBody).Execute()
	if err != nil {
		// log.Debugf("%v\n", r)
		// log.Debugf("%v\n", r.Request.Body)
		return nil, NewAPIError("SignContextRSA.Final()", "Signing failed.", r, err)
	}
	signature, err := base64.StdEncoding.DecodeString(sigData.GetSignature())
	if err != nil {
		return nil, err
	}
	if context.mode == api.SIGNMODE_ECDSA {
		signature, err = sigAsn1ToRS(signature)
	}
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
	slot := context.session.Slot
	reqBody.SetEncrypted(base64.StdEncoding.EncodeToString(context.data))
	reqBody.SetMode(context.mode)
	decryptData, r, err := slot.Api.KeysKeyIDDecryptPost(
		slot.Token.ApiCtx(), context.keyID).Body(reqBody).Execute()
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

func sigAsn1ToRS(sig []byte) ([]byte, error) {
	var (
		r, s = &big.Int{}, &big.Int{}
		seq  cryptobyte.String
	)
	input := cryptobyte.String(sig)
	if ok := input.ReadASN1(&seq, asn1.SEQUENCE) &&
		input.Empty() &&
		seq.ReadASN1Integer(r) &&
		seq.ReadASN1Integer(s) &&
		seq.Empty(); !ok {
		return nil, errors.New("invalid ASN.1 signature")
	}
	maxBytes := func(x, y *big.Int) int {
		l := x.BitLen()
		if ly := y.BitLen(); ly > l {
			l = ly
		}
		return (l + 7) / 8
	}
	l := maxBytes(r, s)
	result := make([]byte, l*2)
	r.FillBytes(result[:l])
	s.FillBytes(result[l:])
	return result, nil
}
