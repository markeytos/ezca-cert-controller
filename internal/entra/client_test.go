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

package entra

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
)

type fakeToken struct{}

func (fakeToken) GetToken(_ context.Context, _ policy.TokenRequestOptions) (azcore.AccessToken, error) {
	return azcore.AccessToken{Token: "fake-token", ExpiresOn: time.Now().Add(time.Hour)}, nil
}

type fakeDoer struct {
	fn func(*http.Request) (*http.Response, error)
}

func (f *fakeDoer) Do(req *http.Request) (*http.Response, error) { return f.fn(req) }

func newTestCertKey(t *testing.T) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "app"}, NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}

func testClient(t *testing.T, doer *fakeDoer) *Client {
	t.Helper()
	cert, key := newTestCertKey(t)
	return &Client{
		appID:         "app-guid",
		graphEndpoint: graphEndpointPublic,
		scope:         graphEndpointPublic + "/.default",
		cred:          fakeToken{},
		http:          doer,
		cert:          cert,
		key:           key,
		now:           func() time.Time { return time.Date(2026, 8, 4, 0, 0, 0, 0, time.UTC) },
	}
}

func jsonResponse(status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}
}

func decodeProofClaims(t *testing.T, proof string) map[string]any {
	t.Helper()
	parts := strings.Split(proof, ".")
	if len(parts) != 3 {
		t.Fatalf("proof is not a JWT: %q", proof)
	}
	claimsJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var claims map[string]any
	if err := json.Unmarshal(claimsJSON, &claims); err != nil {
		t.Fatal(err)
	}
	return claims
}

func TestAddKey(t *testing.T) {
	var body map[string]any
	doer := &fakeDoer{fn: func(req *http.Request) (*http.Response, error) {
		if !strings.Contains(req.URL.Path, "/applications/obj-1/addKey") {
			t.Fatalf("unexpected path %s", req.URL.Path)
		}
		raw, _ := io.ReadAll(req.Body)
		if err := json.Unmarshal(raw, &body); err != nil {
			t.Fatal(err)
		}
		if req.Header.Get("Authorization") != "Bearer fake-token" {
			t.Fatalf("missing bearer token")
		}
		return jsonResponse(http.StatusOK, `{"keyId":"new-key-id"}`), nil
	}}
	c := testClient(t, doer)

	keyID, err := c.AddKey(context.Background(), "obj-1", []byte{0x30, 0x82, 0x01})
	if err != nil {
		t.Fatal(err)
	}
	if keyID != "new-key-id" {
		t.Fatalf("keyID = %q", keyID)
	}

	kc, ok := body["keyCredential"].(map[string]any)
	if !ok {
		t.Fatalf("keyCredential missing: %v", body)
	}
	if kc["type"] != "AsymmetricX509Cert" || kc["usage"] != "Verify" {
		t.Fatalf("keyCredential type/usage wrong: %v", kc)
	}
	if kc["key"] != base64.StdEncoding.EncodeToString([]byte{0x30, 0x82, 0x01}) {
		t.Fatalf("key not base64 DER: %v", kc["key"])
	}
	proof, _ := body["proof"].(string)
	claims := decodeProofClaims(t, proof)
	if claims["aud"] != graphProofAudience {
		t.Fatalf("proof aud = %v", claims["aud"])
	}
	if claims["iss"] != "app-guid" {
		t.Fatalf("proof iss = %v", claims["iss"])
	}
}

func TestRemoveKey(t *testing.T) {
	var body map[string]any
	doer := &fakeDoer{fn: func(req *http.Request) (*http.Response, error) {
		if !strings.Contains(req.URL.Path, "/applications/obj-1/removeKey") {
			t.Fatalf("unexpected path %s", req.URL.Path)
		}
		raw, _ := io.ReadAll(req.Body)
		_ = json.Unmarshal(raw, &body)
		return &http.Response{StatusCode: http.StatusNoContent, Body: io.NopCloser(strings.NewReader("")), Header: make(http.Header)}, nil
	}}
	c := testClient(t, doer)

	if err := c.RemoveKey(context.Background(), "obj-1", "k1"); err != nil {
		t.Fatal(err)
	}
	if body["keyId"] != "k1" {
		t.Fatalf("keyId = %v", body["keyId"])
	}
	if _, ok := body["proof"].(string); !ok {
		t.Fatalf("proof missing")
	}
}

func TestGraphErrorStatus(t *testing.T) {
	doer := &fakeDoer{fn: func(_ *http.Request) (*http.Response, error) {
		return jsonResponse(http.StatusForbidden, `{"error":{"code":"Authorization_RequestDenied"}}`), nil
	}}
	c := testClient(t, doer)
	if _, err := c.AddKey(context.Background(), "obj-1", []byte{0x30}); err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("expected 403 error, got %v", err)
	}
}

type errToken struct{ err error }

func (e errToken) GetToken(_ context.Context, _ policy.TokenRequestOptions) (azcore.AccessToken, error) {
	return azcore.AccessToken{}, e.err
}

func TestVerifyCredential(t *testing.T) {
	c := testClient(t, &fakeDoer{})
	if err := c.VerifyCredential(context.Background()); err != nil {
		t.Fatalf("expected success, got %v", err)
	}

	c.cred = errToken{err: errors.New("AADSTS700027")}
	if err := c.VerifyCredential(context.Background()); err == nil {
		t.Fatalf("expected error while credential is not yet usable")
	}
}

func TestNewClientCloudConfig(t *testing.T) {
	cert, key := newTestCertKey(t)

	pub, err := NewClient("tenant", "app", CloudPublic, cert, key)
	if err != nil {
		t.Fatal(err)
	}
	if pub.graphEndpoint != graphEndpointPublic || pub.scope != graphEndpointPublic+"/.default" {
		t.Fatalf("public endpoints wrong: %s %s", pub.graphEndpoint, pub.scope)
	}

	gov, err := NewClient("tenant", "app", CloudUSGov, cert, key)
	if err != nil {
		t.Fatal(err)
	}
	if gov.graphEndpoint != "https://graph.microsoft.us" {
		t.Fatalf("usgov endpoint wrong: %s", gov.graphEndpoint)
	}

	if _, err := NewClient("tenant", "app", Cloud("Mars"), cert, key); err == nil {
		t.Fatalf("expected error for unknown cloud")
	}
}
