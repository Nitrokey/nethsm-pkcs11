package pkcs11_test

import (
	"crypto"
	"crypto/rsa"
	"fmt"
	"math/big"
	"testing"

	"github.com/miekg/pkcs11"
)

func getRSAPublicKey(p *pkcs11.Ctx, session pkcs11.SessionHandle, o pkcs11.ObjectHandle) (*rsa.PublicKey, error) {
	attr, err := p.GetAttributeValue(session, o,
		[]*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_MODULUS, nil),
			pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, nil),
		})
	if err != nil {
		return nil, err
	}
	if len(attr) != 2 {
		return nil, fmt.Errorf("Can't read public key")
	}
	modulus := big.NewInt(0)
	pubExp := 0
	for i := range attr {
		switch attr[i].Type {
		case pkcs11.CKA_MODULUS:
			modulus.SetBytes(attr[i].Value)
		case pkcs11.CKA_PUBLIC_EXPONENT:
			for _, x := range attr[i].Value {
				pubExp <<= 8
				pubExp += int(x)
			}
		}
	}
	return &rsa.PublicKey{N: modulus, E: pubExp}, nil
}

func TestGetKeyPairRSA(t *testing.T) {
	p := setenv(t)
	session := getSession(p, t)
	defer finishSession(p, session)
	label := keyRSA2048
	getKeyPair(t, p, session, label)
}

func TestSignRSA(t *testing.T) {
	p := setenv(t)
	session := getSession(p, t)
	defer finishSession(p, session)

	tokenLabel := keyRSA2048
	pbk, pvk := getKeyPair(t, p, session, tokenLabel)

	pubKey, _ := getRSAPublicKey(p, session, pbk)
	err := p.SignInit(session, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS, nil)}, pvk)
	if err != nil {
		t.Fatalf("failed to sign: %s", err)
	}

	message := []byte("Sign me!")

	sig, e := p.Sign(session, message)
	if e != nil {
		t.Fatalf("Failed to sign: %s\n", e)
	}
	if rsa.VerifyPKCS1v15(pubKey, 0, message, sig) != nil {
		t.Fatalf("Verification failed!")
	}
}

func TestSignRSAPSS(t *testing.T) {
	p := setenv(t)
	session := getSession(p, t)
	defer finishSession(p, session)

	hashes := []struct {
		ck uint
		cr crypto.Hash
	}{
		{pkcs11.CKM_SHA_1, crypto.SHA1},
		{pkcs11.CKM_SHA224, crypto.SHA224},
		{pkcs11.CKM_SHA256, crypto.SHA256},
		{pkcs11.CKM_SHA384, crypto.SHA384},
		{pkcs11.CKM_SHA512, crypto.SHA512},
	}
	for _, h := range hashes {
		t.Run(h.cr.String(), func(t *testing.T) {
			tokenLabel := keyRSA2048
			pbk, pvk := getKeyPair(t, p, session, tokenLabel)

			pubKey, _ := getRSAPublicKey(p, session, pbk)
			params := pkcs11.NewPSSParams(h.ck, 0, 0)
			err := p.SignInit(session, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS_PSS, params)}, pvk)
			if err != nil {
				t.Fatalf("failed to sign: %s", err)
			}

			h2 := h.cr.New()
			_, _ = h2.Write([]byte("Sign me!"))
			digest := h2.Sum(nil)

			sig, e := p.Sign(session, digest[:])
			if e != nil {
				t.Fatalf("Failed to sign: %s\n", e)
			}
			if rsa.VerifyPSS(pubKey, h.cr, digest, sig, nil) != nil {
				t.Fatalf("Verification failed!")
			}
		})
	}
}

func TestFindRSAObject(t *testing.T) {
	p := setenv(t)
	session := getSession(p, t)
	defer finishSession(p, session)

	tokenLabel := keyRSA2048

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

func TestGetRSAAttributeValue(t *testing.T) {
	p := setenv(t)
	session := getSession(p, t)
	defer finishSession(p, session)

	pbk, _ := getKeyPair(t, p, session, keyRSA2048)

	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, nil),
		pkcs11.NewAttribute(pkcs11.CKA_MODULUS_BITS, nil),
		pkcs11.NewAttribute(pkcs11.CKA_MODULUS, nil),
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
