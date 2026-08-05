/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Package entra manages certificate credentials (keyCredentials) on an Entra ID
// (Azure AD) app registration via Microsoft Graph. The controller uses it to
// add a renewed certificate to an app and to remove expired ones. Requests are
// authenticated with a client certificate (azidentity) and each mutation
// carries a proof-of-possession JWT signed by a certificate the app already
// trusts.
package entra

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/cloud"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"

	"github.com/markeytos/ezca-cert-controller/internal/jwt"
)

// graphProofAudience is the well-known (legacy Azure AD Graph) application ID
// that Microsoft Graph requires as the audience of an addKey/removeKey proof.
// It is an application identifier, not an endpoint, so it is the same across
// sovereign clouds.
const graphProofAudience = "00000002-0000-0000-c000-000000000000"

const (
	graphEndpointPublic     = "https://graph.microsoft.com"
	graphEndpointGovernment = "https://graph.microsoft.us"
)

// Cloud selects the Azure sovereign cloud.
type Cloud string

const (
	// CloudPublic is the Azure public cloud.
	CloudPublic Cloud = "Public"
	// CloudUSGov is the Azure US Government cloud.
	CloudUSGov Cloud = "USGov"
)

type cloudConfig struct {
	azureCloud    cloud.Configuration
	graphEndpoint string
}

var cloudConfigs = map[Cloud]cloudConfig{
	CloudPublic: {cloud.AzurePublic, graphEndpointPublic},
	CloudUSGov:  {cloud.AzureGovernment, graphEndpointGovernment},
}

type tokenGetter interface {
	GetToken(ctx context.Context, opts policy.TokenRequestOptions) (azcore.AccessToken, error)
}

type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

// Client talks to Microsoft Graph for a single app registration, authenticated
// as that app with a client certificate.
type Client struct {
	appID         string
	graphEndpoint string
	scope         string
	cred          tokenGetter
	http          httpDoer
	cert          *x509.Certificate
	key           *rsa.PrivateKey
	now           func() time.Time
}

// NewClient builds a Graph client for the given app, authenticating as that app
// with the provided certificate and RSA private key. The same certificate signs
// the proof-of-possession token for mutations, so it must be a credential the
// app already trusts.
func NewClient(tenantID, appID string, cl Cloud, cert *x509.Certificate, key *rsa.PrivateKey) (*Client, error) {
	cfg, ok := cloudConfigs[cl]
	if !ok {
		return nil, fmt.Errorf("entra: unknown cloud %q", cl)
	}
	cred, err := azidentity.NewClientCertificateCredential(
		tenantID,
		appID,
		[]*x509.Certificate{cert},
		crypto.PrivateKey(key),
		&azidentity.ClientCertificateCredentialOptions{
			ClientOptions: azcore.ClientOptions{Cloud: cfg.azureCloud},
		},
	)
	if err != nil {
		return nil, err
	}
	return &Client{
		appID:         appID,
		graphEndpoint: cfg.graphEndpoint,
		scope:         cfg.graphEndpoint + "/.default",
		cred:          cred,
		http:          http.DefaultClient,
		cert:          cert,
		key:           key,
		now:           time.Now,
	}, nil
}

// VerifyCredential attempts to acquire a Graph token with the client's
// certificate. It returns an error while the certificate is not yet usable —
// for example, a freshly added keyCredential that is still propagating across
// Entra ID's token-issuing replicas.
func (c *Client) VerifyCredential(ctx context.Context) error {
	_, err := c.cred.GetToken(ctx, policy.TokenRequestOptions{Scopes: []string{c.scope}})
	return err
}

// AddKey adds a certificate to the app registration and returns the keyId Graph
// assigned to it. newCertDER is the DER encoding of the certificate to add.
func (c *Client) AddKey(ctx context.Context, objectID string, newCertDER []byte) (string, error) {
	proof, err := c.newProof()
	if err != nil {
		return "", err
	}
	body := map[string]any{
		"keyCredential": map[string]any{
			"type":  "AsymmetricX509Cert",
			"usage": "Verify",
			"key":   base64.StdEncoding.EncodeToString(newCertDER),
		},
		"passwordCredential": nil,
		"proof":              proof,
	}
	reqURL := fmt.Sprintf("%s/v1.0/applications/%s/addKey", c.graphEndpoint, objectID)

	var res struct {
		KeyID string `json:"keyId"`
	}
	if err := c.doJSON(ctx, http.MethodPost, reqURL, body, &res); err != nil {
		return "", err
	}
	if res.KeyID == "" {
		return "", errors.New("entra: addKey response did not include a keyId")
	}
	return res.KeyID, nil
}

// RemoveKey removes the keyCredential with the given keyId from the app.
func (c *Client) RemoveKey(ctx context.Context, objectID, keyID string) error {
	proof, err := c.newProof()
	if err != nil {
		return err
	}
	body := map[string]any{
		"keyId": keyID,
		"proof": proof,
	}
	reqURL := fmt.Sprintf("%s/v1.0/applications/%s/removeKey", c.graphEndpoint, objectID)
	return c.doJSON(ctx, http.MethodPost, reqURL, body, nil)
}

// newProof builds the proof-of-possession JWT, signed by the app's current
// (trusted) certificate, that Graph requires for addKey and removeKey.
func (c *Client) newProof() (string, error) {
	now := c.now()
	sum := sha1.Sum(c.cert.Raw)
	x5t := base64.RawURLEncoding.EncodeToString(sum[:])
	header := map[string]any{
		"alg": "RS256",
		"typ": "JWT",
		"x5t": x5t,
		"kid": x5t,
	}
	claims := map[string]any{
		"aud": graphProofAudience,
		"iss": c.appID,
		"nbf": now.Unix(),
		"exp": now.Add(10 * time.Minute).Unix(),
	}
	return jwt.SignRS256(header, claims, c.key)
}

// doJSON attaches a Graph bearer token, sends the request (with an optional JSON
// body), checks for a 2xx status, and decodes the response into out when non-nil.
func (c *Client) doJSON(ctx context.Context, method, reqURL string, body any, out any) error {
	var reader io.Reader
	if body != nil {
		bodyBytes, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(bodyBytes)
	}
	req, err := http.NewRequestWithContext(ctx, method, reqURL, reader)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	token, err := c.cred.GetToken(ctx, policy.TokenRequestOptions{Scopes: []string{c.scope}})
	if err != nil {
		return fmt.Errorf("entra: acquiring Graph token: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token.Token)

	res, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = res.Body.Close() }()

	resBytes, err := io.ReadAll(res.Body)
	if err != nil {
		return err
	}
	if res.StatusCode < http.StatusOK || res.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("entra: Graph request to %s failed with status %d: %s", reqURL, res.StatusCode, string(resBytes))
	}
	if out != nil && len(bytes.TrimSpace(resBytes)) > 0 {
		return json.Unmarshal(resBytes, out)
	}
	return nil
}
