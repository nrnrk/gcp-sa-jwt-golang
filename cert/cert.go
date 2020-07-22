package cert

import (
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"math/big"
)

// Cert is JWK form certificate
type Cert struct {
	Curve     string `json:"crv"`
	KeyID     string `json:"kid"`
	KeyType   string `json:"kty"`
	Algorithm string `json:"alg"`
	E         string `json:"e"`
	N         string `json:"n"`
}

// ToPublicKey returns public key from JWK cert
func (c *Cert) ToPublicKey() (*rsa.PublicKey, error) {
	if c.KeyType != "RSA" {
		return nil, errors.New(`Unsupported key type`)
	}
	n, err := parseBigInt(c.N)
	if err != nil {
		return nil, errors.New(`Could not parse N`)
	}

	e, err := parseBigInt(c.E)
	if err != nil {
		return nil, errors.New(`Could not parse E`)
	}

	return &rsa.PublicKey{
		N: n,
		E: int(e.Int64()),
	}, nil
}

func parseBigInt(s string) (*big.Int, error) {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}

	return new(big.Int).SetBytes(b), nil
}
