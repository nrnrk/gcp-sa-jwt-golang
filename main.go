package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/dgrijalva/jwt-go"
	"golang.org/x/oauth2/google"
	"golang.org/x/oauth2/jws"
	gjwt "golang.org/x/oauth2/jwt"

	"github.com/nrnrk/gcp-sa-jwt-golang/cert"
)

// jwkEndpoint is endpoint to fetch JWK of a Google API Service Account
// `%s` should be replaced with a service account email
const jwkEndpoint = `https://www.googleapis.com/service_accounts/v1/jwk/%s`

// CertsResponse is response of JWK Endpoint of Google Api Service Accounts
type CertsResponse struct {
	Certs []cert.Cert `json:"keys"`
}

// generate & verify JWT
func main() {
	saJSON, err := ioutil.ReadFile(os.Getenv(`GCP_SA_CREDENTIAL_JSON`))
	if err != nil {
		log.Fatalf("Could not read service account file: %v", err)
	}
	conf, err := google.JWTConfigFromJSON(saJSON)
	if err != nil {
		log.Fatalf("Could not parse service account JSON: %v", err)
	}

	token, err := generateJWT(conf, os.Getenv(`GCP_AUDIENCE`), time.Hour)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(`****************************************************************************************************`)
	fmt.Println(`JWT generated! You can check the content of it here ( https://jwt.io/ )`)
	fmt.Printf("%s\n", token)
	fmt.Println(`****************************************************************************************************`)

	cert, err := fetchJWKKey(conf.Email, conf.PrivateKeyID)
	if err != nil {
		log.Fatal(err)
	}
	_, err = jwt.Parse(token, func(token *jwt.Token) (i interface{}, e error) {
		pubKey, err := cert.ToPublicKey()
		if err != nil {
			return nil, err
		}
		// return interface{}(pubKey), e
		return pubKey, e
	})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(`Succeeded to verify JWT!`)
}

// generateJWT creates a signed JSON Web Token using a Google API Service Account
// ref. https://cloud.google.com/endpoints/docs/openapi/service-account-authentication?hl=ja#go
func generateJWT(conf *gjwt.Config, audience string, expirationTime time.Duration) (string, error) {
	now := time.Now()
	jwt := &jws.ClaimSet{
		Iat:           now.Unix(),                                       // issued at
		Exp:           now.Add(expirationTime).Unix(),                   // expired at
		Iss:           conf.Email,                                       // issuer
		Aud:           audience,                                         // audience
		Sub:           conf.Email,                                       // (optional) service account email for sub
		PrivateClaims: map[string]interface{}{"kid": conf.PrivateKeyID}, // (optional) private claims
	}
	jwsHeader := &jws.Header{
		Algorithm: "RS256",
		Typ:       "JWT",
	}

	block, _ := pem.Decode(conf.PrivateKey)
	parsedKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("Private key parse error: %v", err)
	}
	rsaKey, ok := parsedKey.(*rsa.PrivateKey)
	if !ok {
		return "", errors.New("Private key failed rsa.PrivateKey type assertion")
	}
	jwtStr, err := jws.Encode(jwsHeader, jwt, rsaKey)
	if err != nil {
		return "", fmt.Errorf("Could not encode JWT: %v", err)
	}
	return jwtStr, nil
}

// fetchJWKKey fetches JWK key by key ID from Google API
func fetchJWKKey(saEmail, keyID string) (*cert.Cert, error) {
	req, err := http.NewRequest("GET", fmt.Sprintf(jwkEndpoint, saEmail), nil)
	if err != nil {
		return nil, fmt.Errorf("Could not create request: %v", err)
	}

	client := &http.Client{
		Timeout: 15 * time.Second,
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("Could not get jwks: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("Got not OK status from JWK endpoint")
	}

	var certsResp CertsResponse
	if err := json.NewDecoder(resp.Body).Decode(&certsResp); err != nil {
		return nil, fmt.Errorf("Could not decode response: %v", err)
	}
	for _, c := range certsResp.Certs {
		if c.KeyID == keyID {
			return &c, nil
		}
	}
	return nil, fmt.Errorf(`Could not find certificate by keyID(: %s)`, keyID)
}
