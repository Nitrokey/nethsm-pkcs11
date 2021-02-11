package pkcs11_test

import (
	"fmt"
	"github.com/miekg/pkcs11"
	"github.com/niclabs/dtc/v3/utils"
	"log"
	"math/big"
	"os"
	"testing"
)

/*
Purpose: GenerateConfig ECDSA keypair with a given name and persistence.
Inputs: test object
	context
	session handle
	tokenLabel: string to set as the token labels
	tokenPersistent: boolean. Whether or not the token should be
			session based or persistent. If false, the
			token will not be saved in the HSM and is
			destroyed upon termination of the session.
Outputs: creates persistent or ephemeral tokens within the HSM.
Returns: object handles for public and private keys. Fatal on error.
*/
func generateECDSAKeyPair(t *testing.T, p *pkcs11.Ctx, session pkcs11.SessionHandle, tokenLabel string, tokenPersistent bool) (pkcs11.ObjectHandle, pkcs11.ObjectHandle) {
	/*
		inputs: test object, context, session handle
			tokenLabel: string to set as the token labels
			tokenPersistent: boolean. Whether or not the token should be
					session based or persistent. If false, the
					token will not be saved in the HSM and is
					destroyed upon termination of the session.
		outputs: creates persistent or ephemeral tokens within the HSM.
		returns: object handles for public and private keys.
	*/

	ecParams, _ := utils.CurveNameToASN1Bytes("P-256")

	publicKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, tokenPersistent),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
		pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, ecParams),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, tokenLabel),
	}
	privateKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, tokenPersistent),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, tokenLabel),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, true),
	}
	pbk, pvk, e := p.GenerateKeyPair(session,
		[]*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_ECDSA_KEY_PAIR_GEN, nil)},
		publicKeyTemplate, privateKeyTemplate)
	if e != nil {
		t.Fatalf("failed to generate keypair: %s\n", e)
	}

	return pbk, pvk
}

func TestGenerateKeyPairECDSA(t *testing.T) {
	p := setenv(t)
	session := getSession(p, t)
	defer finishSession(p, session)
	tokenLabel := "TestGenerateKeyPairECDSA"
	generateECDSAKeyPair(t, p, session, tokenLabel, false)
}

func TestSignECDSA(t *testing.T) {
	p := setenv(t)
	session := getSession(p, t)
	defer finishSession(p, session)

	tokenLabel := "TestSignECDSA"
	_, pvk := generateECDSAKeyPair(t, p, session, tokenLabel, false)

	err := p.SignInit(session, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_ECDSA_SHA256, nil)}, pvk)
	if err != nil {
		t.Fatalf("failed to sign: %s", err)
	}
	_, e := p.Sign(session, []byte("Sign me!"))
	if e != nil {
		t.Fatalf("failed to sign: %s\n", e)
	}
}

func TestFindECDSAObject(t *testing.T) {
	p := setenv(t)
	session := getSession(p, t)
	defer finishSession(p, session)

	tokenLabel := "TestFindECDSAObject"

	// There are 2 keys in the db with this tag
	generateECDSAKeyPair(t, p, session, tokenLabel, false)

	template := []*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_LABEL, tokenLabel)}
	if e := p.FindObjectsInit(session, template); e != nil {
		t.Fatalf("failed to init: %s\n", e)
	}
	obj, _, e := p.FindObjects(session, 2)
	if e != nil {
		t.Fatalf("failed to find: %s\n", e)
	}
	if e := p.FindObjectsFinal(session); e != nil {
		t.Fatalf("failed to finalize: %s\n", e)
	}
	if len(obj) != 2 {
		t.Fatal("should have found two objects")
	}
}

func TestGetECDSAAttributeValue(t *testing.T) {
	p := setenv(t)
	session := getSession(p, t)
	defer finishSession(p, session)

	pbk, _ := generateECDSAKeyPair(t, p, session, "GetAttributeValue", false)

	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, nil),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, nil),
	}
	attr, err := p.GetAttributeValue(session, pkcs11.ObjectHandle(pbk), template)
	if err != nil {
		t.Fatalf("err %s\n", err)
	}
	for i, a := range attr {
		t.Logf("attr %d, type %d, valuelen %d", i, a.Type, len(a.Value))
		if a.Type == pkcs11.CKA_MODULUS {
			mod := big.NewInt(0)
			mod.SetBytes(a.Value)
			t.Logf("modulus %s\n", mod.String())
		}
	}
}

// Create and destroy persistent keys
func TestDestroyECDSAObject(t *testing.T) {
	p := setenv(t)
	session := getSession(p, t)
	defer finishSession(p, session)

	generateECDSAKeyPair(t, p, session, "TestDestroyKey", true)
	if e := destroyObject(t, p, session, "TestDestroyKey", pkcs11.CKO_PUBLIC_KEY); e != nil {
		t.Fatalf("Failed to destroy object: %s\n", e)
	}
	if e := destroyObject(t, p, session, "TestDestroyKey", pkcs11.CKO_PRIVATE_KEY); e != nil {
		t.Fatalf("Failed to destroy object: %s\n", e)
	}

}

// ExampleSign shows how to sign some data with a private key.
// Note: error correction is not implemented in this example.
func ExampleCtx_SignECDSA() {
	if x := os.Getenv("PKCS11_LIB"); x != "" {
		module = x
	}
	p := pkcs11.New(module)
	if p == nil {
		log.Fatal("Failed to init lib")
	}

	p.Initialize()
	defer p.Destroy()
	defer p.Finalize()
	slots, _ := p.GetSlotList(true)
	session, _ := p.OpenSession(slots[0], pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	defer p.CloseSession(session)
	p.Login(session, pkcs11.CKU_USER, pin)
	defer p.Logout(session)

	ecParams, _ := utils.CurveNameToASN1Bytes("P-256")

	publicKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, false),
		pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, ecParams),

		pkcs11.NewAttribute(pkcs11.CKA_LABEL, "ExampleSign"),
	}
	privateKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, false),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, "ExampleSign"),
	}
	_, priv, err := p.GenerateKeyPair(session,
		[]*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_ECDSA_KEY_PAIR_GEN, nil)},
		publicKeyTemplate, privateKeyTemplate)
	if err != nil {
		log.Fatal(err)
	}
	p.SignInit(session, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_ECDSA_SHA256, nil)}, priv)
	// Sign something with the private key.
	data := []byte("Lets sign this data")

	_, err = p.Sign(session, data)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("It works!")
	// Output: It works!
}

// Copyright 2013 Miek Gieben. All rights reserved.
