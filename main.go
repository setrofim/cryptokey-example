package main

import (
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"

	"github.com/veraison/corim/comid"
)

var DerKeyType = "pkix-der-key"
var DerKeyTag = uint64(9999)

type TaggedDerKey []byte

func NewTaggedDerKey(k any) (*comid.CryptoKey, error) {
	var b []byte
	var err error

	if k == nil {
		k = *new([]byte)
	}

	switch t := k.(type) {
	case []byte:
		b = t
	case string:
		b, err = base64.StdEncoding.DecodeString(t)
		if err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("value must be a []byte; found %T", k)
	}

	key := TaggedDerKey(b)

	return &comid.CryptoKey{Value: key}, nil
}

func (o TaggedDerKey) String() string {
	return base64.StdEncoding.EncodeToString(o)
}

func (o TaggedDerKey) Valid() error {
	_, err := o.PublicKey()
	return err
}

func (o TaggedDerKey) Type() string {
	return DerKeyType
}

func (o TaggedDerKey) PublicKey() (crypto.PublicKey, error) {
	if len(o) == 0 {
		return nil, errors.New("key value not set")
	}

	key, err := x509.ParsePKIXPublicKey(o)
	if err != nil {
		return nil, fmt.Errorf("unable to parse public key: %w", err)
	}

	return key, nil
}

var testKeyJSON = `
{
	"type": "pkix-der-key",
	"value": "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEW1BvqF+/ry8BWa7ZEMU1xYYHEQ8BlLT4MFHOaO+ICTtIvrEeEpr/sfTAP66H2hCHdb5HEXKtRKod6QLcOLPA1Q=="
}
`

func main() {
	if err := comid.RegisterCryptoKeyType(DerKeyType, DerKeyTag, NewTaggedDerKey); err != nil {
		log.Fatal(err)
	}

	var key comid.CryptoKey

	if err := json.Unmarshal([]byte(testKeyJSON), &key); err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Decoded DER key: %x\n", key)
}
