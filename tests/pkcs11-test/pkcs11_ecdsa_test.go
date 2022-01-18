package pkcs11_test

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/asn1"
	"fmt"
	"math/big"
	"testing"

	"github.com/miekg/pkcs11"
)

func getECPoint(p *pkcs11.Ctx, s pkcs11.SessionHandle, o pkcs11.ObjectHandle) ([]byte, error) {
	attr, err := p.GetAttributeValue(s, o,
		[]*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_EC_POINT, nil),
		})
	if err != nil {
		return nil, err
	}
	if len(attr) != 1 {
		return nil, fmt.Errorf("can't read public key")
	}
	var ecPoint []byte
	rest, err := asn1.Unmarshal(attr[0].Value, &ecPoint)
	if err != nil || len(rest) != 0 {
		return nil, fmt.Errorf("can't unserialize ECPoint")
	}
	return ecPoint, nil
}

func getP256PublicKey(p *pkcs11.Ctx, s pkcs11.SessionHandle, o pkcs11.ObjectHandle) (*ecdsa.PublicKey, error) {
	ecPoint, err := getECPoint(p, s, o)
	if err != nil {
		return nil, err
	}
	c := elliptic.P256()
	x, y := elliptic.Unmarshal(c, ecPoint)
	if x == nil {
		return nil, fmt.Errorf("can't parse ECPoint")
	}
	return &ecdsa.PublicKey{X: x, Y: y, Curve: c}, nil
}

func getEd25519PublicKey(p *pkcs11.Ctx, s pkcs11.SessionHandle, o pkcs11.ObjectHandle) (ed25519.PublicKey, error) {
	ecPoint, err := getECPoint(p, s, o)
	if err != nil {
		return nil, err
	}
	return ed25519.PublicKey(ecPoint), nil
}

func TestSignECDSA(t *testing.T) {
	p := setenv(t)
	session := getSession(p, t)
	defer finishSession(p, session)

	tokenLabel := keyEcP256
	pbk, pvk := getKeyPair(t, p, session, tokenLabel)

	pubKey, err := getP256PublicKey(p, session, pbk)
	if err != nil {
		t.Fatalf("failed to get public key: %s", err)
	}
	err = p.SignInit(session, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_ECDSA, nil)}, pvk)
	if err != nil {
		t.Fatalf("failed to sign: %s", err)
	}

	digest := sha256.Sum256([]byte("Sign me!"))

	sig, e := p.Sign(session, digest[:])
	if e != nil {
		t.Fatalf("failed to sign: %s\n", e)
	}
	var r, s big.Int
	l := len(sig) / 2
	r.SetBytes(sig[:l])
	s.SetBytes(sig[l:])
	if !ecdsa.Verify(pubKey, digest[:], &r, &s) {
		t.Fatalf("Verification failed!")
	}
}

func TestSignEdDSA(t *testing.T) {
	p := setenv(t)
	session := getSession(p, t)
	defer finishSession(p, session)

	tokenLabel := keyEd25519
	pbk, pvk := getKeyPair(t, p, session, tokenLabel)
	pubKey, err := getEd25519PublicKey(p, session, pbk)
	if err != nil {
		t.Fatalf("failed to get public key: %s", err)
	}

	const CKM_EDDSA = 4183
	err = p.SignInit(session, []*pkcs11.Mechanism{pkcs11.NewMechanism(CKM_EDDSA, nil)}, pvk)
	if err != nil {
		t.Fatalf("failed to sign: %s", err)
	}

	digest := sha256.Sum256([]byte("Sign me!"))

	sig, e := p.Sign(session, digest[:])
	if e != nil {
		t.Fatalf("failed to sign: %s\n", e)
	}
	var r, s big.Int
	l := len(sig) / 2
	r.SetBytes(sig[:l])
	s.SetBytes(sig[l:])
	if !ed25519.Verify(pubKey, digest[:], sig) {
		t.Fatalf("Verification failed!")
	}
}

func TestGetECDSAAttributeValue(t *testing.T) {
	p := setenv(t)
	session := getSession(p, t)
	defer finishSession(p, session)

	pbk, _ := getKeyPair(t, p, session, keyEd25519)

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
	}
}
