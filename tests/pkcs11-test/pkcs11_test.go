// Heavily based on tests found in github.com/miekg/pkcs11
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package pkcs11_test

// These tests depend on SoftHSM and the library being in
// in /usr/lib/softhsm/libsofthsm.so

import (
	"fmt"
	"github.com/miekg/pkcs11"
	"os"
	"testing"
)

var (
	module = "./dtc.so"
	pin    = "1234"
)

/*
This test supports the following environment variables:

* PKCS11_LIB: complete path to HSM Library
* PKCS11_TOKENLABEL
* PKCS11_PRIVKEYLABEL
* PKCS11_PIN
*/

func setenv(t *testing.T) *pkcs11.Ctx {
	if x := os.Getenv("PKCS11_LIB"); x != "" {
		module = x
	}
	t.Logf("loading %s", module)
	p := pkcs11.New(module)
	if p == nil {
		t.Fatal("Failed to init lib")
	}
	return p
}

func TestSetenv(t *testing.T) {
	if x := os.Getenv("PKCS11_LIB"); x != "" {
		module = x
	}
	p := pkcs11.New(module)
	if p == nil {
		t.Fatal("Failed to init pkcs11")
	}
	p.Destroy()
	return
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
	if e := p.Login(session, pkcs11.CKU_USER, pin); e != nil {
		t.Fatalf("user pin %s\n", e)
	}
	return session
}

func TestInitialize(t *testing.T) {
	p := setenv(t)
	if e := p.Initialize(); e != nil {
		t.Fatalf("init error %s\n", e)
	}
	p.Finalize()
	p.Destroy()
}

func finishSession(p *pkcs11.Ctx, session pkcs11.SessionHandle) {
	p.Logout(session)
	p.CloseSession(session)
	p.Finalize()
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
	if info.ManufacturerID != "NICLabs" {
		t.Fatalf("ID should be NICLabs and is %s", info.ManufacturerID)
	}
	t.Logf("%+v\n", info)
}

func TestDigest(t *testing.T) {
	p := setenv(t)
	session := getSession(p, t)
	testDigest(t, p, session, []byte("this is a string"), "517592df8fec3ad146a79a9af153db2a4d784ec5")
	finishSession(p, session)
}

func testDigest(t *testing.T, p *pkcs11.Ctx, session pkcs11.SessionHandle, input []byte, expected string) {
	e := p.DigestInit(session, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_SHA_1, nil)})
	if e != nil {
		t.Fatalf("DigestInit: %s\n", e)
	}

	hash, e := p.Digest(session, input)
	if e != nil {
		t.Fatalf("digest: %s\n", e)
	}
	hex := ""
	for _, d := range hash {
		hex += fmt.Sprintf("%02x", d)
	}
	if hex != expected {
		t.Fatalf("wrong digest: %s", hex)
	}
}

/* destroyObject
Purpose: destroy and object from the HSM
Inputs: test handle
	session handle
	searchToken: String containing the token label to search for.
	class: Key type (pkcs11.CKO_PRIVATE_KEY or CKO_PUBLIC_KEY) to remove.
Outputs: removes object from HSM
Returns: Fatal error on failure.
*/
func destroyObject(t *testing.T, p *pkcs11.Ctx, session pkcs11.SessionHandle, searchToken string, class uint) (err error) {
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, searchToken),
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, class)}

	if e := p.FindObjectsInit(session, template); e != nil {
		t.Fatalf("failed to init: %s\n", e)
	}
	obj, _, e := p.FindObjects(session, 1)
	if e != nil || len(obj) == 0 {
		t.Fatalf("failed to find objects")
	}
	if e := p.FindObjectsFinal(session); e != nil {
		t.Fatalf("failed to finalize: %s\n", e)
	}

	if e := p.DestroyObject(session, obj[0]); e != nil {
		t.Fatalf("DestroyObject failed: %s\n", e)
	}
	return
}
