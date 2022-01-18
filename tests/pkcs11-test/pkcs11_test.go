// Heavily based on tests found in github.com/miekg/pkcs11
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package pkcs11_test

// These tests depend on SoftHSM and the library being in
// in /usr/lib/softhsm/libsofthsm.so

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
	"p11nethsm/api"
	"strings"
	"testing"

	"github.com/miekg/pkcs11"
)

var (
	soFile   = "../../p11nethsm.so"
	hsmURL   = "https://nethsmdemo.nitrokey.com/api/v1"
	admin    = "admin"
	admPass  = "adminadmin"
	operator = "testOperator"
	opPass   = "opPassphrase"
)

const (
	keyRSA2048 = "testkeyrsa2048"
	keyEcP256  = "testkeyecp256"
	keyEd25519 = "testkeyed25519"
)

/*
This test supports the following environment variables:

* PKCS11_LIB: complete path to HSM Library
*/

func check(t *testing.T, e error) {
	if e != nil {
		t.Fatal(e)
	}
}

func setenv(t *testing.T) *pkcs11.Ctx {
	if x := os.Getenv("PKCS11_LIB"); x != "" {
		soFile = x
	}
	t.Logf("loading %s", soFile)
	p := pkcs11.New(soFile)
	if p == nil {
		t.Fatal("Failed to init module")
	}
	return p
}

func getKeyPair(t *testing.T, p *pkcs11.Ctx, session pkcs11.SessionHandle, label string) (pkcs11.ObjectHandle, pkcs11.ObjectHandle) {
	var pbk, pvk pkcs11.ObjectHandle

	pubKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
	}
	privKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
	}
	e := p.FindObjectsInit(session, pubKeyTemplate)
	check(t, e)
	obj, _, e := p.FindObjects(session, 1)
	check(t, e)
	if len(obj) == 0 {
		t.Fatalf("Couldn't find public key %s", label)
	}
	pbk = obj[0]
	e = p.FindObjectsFinal(session)
	check(t, e)
	e = p.FindObjectsInit(session, privKeyTemplate)
	check(t, e)
	obj, _, e = p.FindObjects(session, 1)
	check(t, e)
	if len(obj) == 0 {
		t.Fatalf("Couldn't find private key %s", label)
	}
	pvk = obj[0]
	e = p.FindObjectsFinal(session)
	check(t, e)

	return pbk, pvk
}

func TestMain(m *testing.M) {
	apiConf := api.NewConfiguration()
	apiConf.Debug = true
	apiConf.Servers = api.ServerConfigurations{
		{
			URL: hsmURL,
		},
	}
	customTransport := http.DefaultTransport.(*http.Transport).Clone()
	customTransport.TLSClientConfig = &tls.Config{
		InsecureSkipVerify: true,
	}
	apiConf.HTTPClient = &http.Client{Transport: customTransport}
	service := api.NewAPIClient(apiConf).DefaultApi

	basicAuth := api.BasicAuth{
		UserName: admin,
		Password: admPass,
	}
	ctx := context.WithValue(context.Background(), api.ContextBasicAuth, basicAuth)

	check := func(resp *http.Response, err error) {
		if err != nil && resp != nil && !strings.Contains(fmt.Sprint(resp), "already exists") {
			fmt.Printf("err: %v\n", err)
			fmt.Printf("resp: %v\n", resp)
			os.Exit(1)
		}
	}

	resp, err := service.UsersUserIDPut(ctx, operator).
		Body(*api.NewUserPostData(
			"Test Operator", api.USERROLE_OPERATOR, opPass)).Execute()
	check(resp, err)

	keyData := api.NewKeyGenerateRequestData([]api.KeyMechanism{
		api.KEYMECHANISM_RSA_DECRYPTION_RAW,
		api.KEYMECHANISM_RSA_DECRYPTION_PKCS1,
		api.KEYMECHANISM_RSA_DECRYPTION_OAEP_MD5,
		api.KEYMECHANISM_RSA_DECRYPTION_OAEP_SHA1,
		api.KEYMECHANISM_RSA_DECRYPTION_OAEP_SHA224,
		api.KEYMECHANISM_RSA_DECRYPTION_OAEP_SHA256,
		api.KEYMECHANISM_RSA_DECRYPTION_OAEP_SHA384,
		api.KEYMECHANISM_RSA_DECRYPTION_OAEP_SHA512,
		api.KEYMECHANISM_RSA_SIGNATURE_PKCS1,
		api.KEYMECHANISM_RSA_SIGNATURE_PSS_MD5,
		api.KEYMECHANISM_RSA_SIGNATURE_PSS_SHA1,
		api.KEYMECHANISM_RSA_SIGNATURE_PSS_SHA224,
		api.KEYMECHANISM_RSA_SIGNATURE_PSS_SHA256,
		api.KEYMECHANISM_RSA_SIGNATURE_PSS_SHA384,
		api.KEYMECHANISM_RSA_SIGNATURE_PSS_SHA512,
	}, api.KEYTYPE_RSA)
	keyData.SetId(keyRSA2048)
	keyData.SetLength(2048)
	resp, err = service.KeysGeneratePost(ctx).
		Body(*keyData).Execute()
	check(resp, err)

	keyData = api.NewKeyGenerateRequestData([]api.KeyMechanism{
		api.KEYMECHANISM_ECDSA_SIGNATURE,
	}, api.KEYTYPE_EC_P256)
	keyData.SetId(keyEcP256)
	keyData.SetLength(2048)
	resp, err = service.KeysGeneratePost(ctx).
		Body(*keyData).Execute()
	check(resp, err)

	keyData = api.NewKeyGenerateRequestData([]api.KeyMechanism{
		api.KEYMECHANISM_ED_DSA_SIGNATURE,
	}, api.KEYTYPE_CURVE25519)
	keyData.SetId(keyEd25519)
	keyData.SetLength(2048)
	resp, err = service.KeysGeneratePost(ctx).
		Body(*keyData).Execute()
	check(resp, err)

	os.Exit(m.Run())
}

func getSession(p *pkcs11.Ctx, t *testing.T) pkcs11.SessionHandle {
	if e := p.Initialize(); e != nil {
		t.Fatalf("init error %s\n", e)
	}
	slots, e := p.GetSlotList(true)
	if e != nil {
		t.Fatalf("slots %s\n", e)
	}
	session, e := p.OpenSession(slots[0], pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if e != nil {
		t.Fatalf("session %s\n", e)
	}
	if e := p.Login(session, pkcs11.CKU_USER, opPass); e != nil {
		t.Fatalf("user pin %s\n", e)
	}
	return session
}

func TestInitialize(t *testing.T) {
	p := setenv(t)
	if e := p.Initialize(); e != nil {
		t.Fatalf("init error %s\n", e)
	}
	check(t, p.Finalize())
	p.Destroy()
}

func finishSession(p *pkcs11.Ctx, session pkcs11.SessionHandle) {
	_ = p.Logout(session)
	_ = p.CloseSession(session)
	_ = p.Finalize()
	p.Destroy()
}

func TestGetInfo(t *testing.T) {
	p := setenv(t)
	session := getSession(p, t)
	defer finishSession(p, session)
	info, err := p.GetInfo()
	if err != nil {
		t.Fatalf("non zero error %s\n", err)
	}
	if info.ManufacturerID != "Nitrokey GmbH" {
		t.Fatalf("ID should be 'Nitrokey GmbH' and is '%s'", info.ManufacturerID)
	}
	t.Logf("%+v\n", info)
}
