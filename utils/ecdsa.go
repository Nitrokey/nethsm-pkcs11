package utils

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/asn1"
	"fmt"
	"p11nethsm/api"
)

var keyTypeToASN1 = map[api.KeyType]asn1.ObjectIdentifier{
	api.KEYTYPE_EC_P224:    {1, 3, 132, 0, 33},
	api.KEYTYPE_EC_P256:    {1, 2, 840, 10045, 3, 1, 7},
	api.KEYTYPE_EC_P384:    {1, 3, 132, 0, 34},
	api.KEYTYPE_EC_P521:    {1, 3, 132, 0, 35},
	api.KEYTYPE_CURVE25519: {1, 3, 101, 112},
}

func KeyTypeToASN1Bytes(curve api.KeyType) ([]byte, error) {
	// if curve == api.KEYTYPE_CURVE25519 {
	// 	obj, _ := asn1.Marshal("Edwards25519")
	// 	return obj, nil
	// }
	obj, ok := keyTypeToASN1[curve]
	if !ok {
		return nil, fmt.Errorf("curve unsupported")
	}
	return asn1.Marshal(obj)
}

// func ASN1ToCurveName(b []byte) (string, error) {
// 	var v asn1.ObjectIdentifier
// 	extra, err := asn1.Unmarshal(b, &v)
// 	if len(extra) > 0 {
// 		return "", fmt.Errorf("extra data in params")
// 	}
// 	if err != nil {
// 		return "", fmt.Errorf("error decrypting params: %s", err)
// 	}
// 	for name, item := range CurveNameToASN1 {
// 		if v.Equal(item) {
// 			return name, nil
// 		}
// 	}
// 	return "", fmt.Errorf("curve unsupported")
// }

func PubKeyToASN1Bytes(pk *ecdsa.PublicKey) ([]byte, error) {
	ecPointBytes := elliptic.Marshal(pk.Curve, pk.X, pk.Y)
	ecPointASN1, err := asn1.Marshal(ecPointBytes)
	if err != nil {
		return nil, err
	}
	return ecPointASN1, nil
}

// func ASN1BytesToPubKey(c elliptic.Curve, b []byte) (*ecdsa.PublicKey, error) {
// 	var pointBytes []byte
// 	rest, err := asn1.Unmarshal(b, &pointBytes)
// 	if err != nil {
// 		return nil, fmt.Errorf("error decoding ec pubkey: %s", err.Error())
// 	}
// 	if len(rest) > 0 {
// 		return nil, fmt.Errorf("error decoding ec pubkey: rest length is greater than zero")
// 	}
// 	x, y := elliptic.Unmarshal(c, pointBytes)
// 	if x == nil {
// 		return nil, fmt.Errorf("error decoding ec pubkey: cannot transform the binary value into a point using curve %s", c.Params().Name)

// 	}
// 	return &ecdsa.PublicKey{
// 		Curve: c,
// 		X:     x,
// 		Y:     y,
// 	}, nil
// }
