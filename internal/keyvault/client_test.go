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

package keyvault

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"math/big"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azcertificates"
	"software.sslmate.com/src/go-pkcs12"
)

type fakeCertOps struct {
	getCER       []byte
	getCT        *string
	getPolicyCT  *string
	getErr       error
	importCalled bool
	imported     azcertificates.ImportCertificateParameters
}

func (f *fakeCertOps) GetCertificate(_ context.Context, _, _ string, _ *azcertificates.GetCertificateOptions) (azcertificates.GetCertificateResponse, error) {
	if f.getErr != nil {
		return azcertificates.GetCertificateResponse{}, f.getErr
	}
	cert := azcertificates.Certificate{CER: f.getCER, ContentType: f.getCT}
	if f.getPolicyCT != nil {
		cert.Policy = &azcertificates.CertificatePolicy{SecretProperties: &azcertificates.SecretProperties{ContentType: f.getPolicyCT}}
	}
	return azcertificates.GetCertificateResponse{Certificate: cert}, nil
}

func strPtr(s string) *string { return &s }

func (f *fakeCertOps) ImportCertificate(_ context.Context, _ string, params azcertificates.ImportCertificateParameters, _ *azcertificates.ImportCertificateOptions) (azcertificates.ImportCertificateResponse, error) {
	f.importCalled = true
	f.imported = params
	return azcertificates.ImportCertificateResponse{}, nil
}

func testCertDER(t *testing.T) []byte {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "kv"}, NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestCertificateMatches(t *testing.T) {
	der := testCertDER(t)
	sum := sha1.Sum(der)
	thumb := strings.ToUpper(hex.EncodeToString(sum[:]))

	t.Run("match", func(t *testing.T) {
		c := &Client{certs: &fakeCertOps{getCER: der}}
		ok, err := c.CertificateMatches(context.Background(), "cert", thumb)
		if err != nil || !ok {
			t.Fatalf("expected match, got ok=%v err=%v", ok, err)
		}
	})

	t.Run("match stored as PFX", func(t *testing.T) {
		c := &Client{certs: &fakeCertOps{getCER: der, getCT: strPtr(pkcs12ContentType)}}
		ok, err := c.CertificateMatches(context.Background(), "cert", thumb)
		if err != nil || !ok {
			t.Fatalf("expected match, got ok=%v err=%v", ok, err)
		}
	})

	t.Run("match stored as PEM", func(t *testing.T) {
		// Same certificate, but stored as PEM by an earlier controller version:
		// it must be re-imported as PFX.
		c := &Client{certs: &fakeCertOps{getCER: der, getCT: strPtr("application/x-pem-file")}}
		ok, err := c.CertificateMatches(context.Background(), "cert", thumb)
		if err != nil || ok {
			t.Fatalf("expected no match for a PEM-stored cert, got ok=%v err=%v", ok, err)
		}
	})

	t.Run("match with PEM policy only", func(t *testing.T) {
		// The content type falls back to the policy when the certificate omits it.
		c := &Client{certs: &fakeCertOps{getCER: der, getPolicyCT: strPtr("application/x-pem-file")}}
		ok, err := c.CertificateMatches(context.Background(), "cert", thumb)
		if err != nil || ok {
			t.Fatalf("expected no match for a PEM policy, got ok=%v err=%v", ok, err)
		}
	})

	t.Run("mismatch", func(t *testing.T) {
		c := &Client{certs: &fakeCertOps{getCER: der}}
		ok, err := c.CertificateMatches(context.Background(), "cert", "DEADBEEF")
		if err != nil || ok {
			t.Fatalf("expected mismatch, got ok=%v err=%v", ok, err)
		}
	})

	t.Run("not found", func(t *testing.T) {
		c := &Client{certs: &fakeCertOps{getErr: &azcore.ResponseError{StatusCode: http.StatusNotFound}}}
		ok, err := c.CertificateMatches(context.Background(), "cert", thumb)
		if err != nil || ok {
			t.Fatalf("expected (false,nil) for missing cert, got ok=%v err=%v", ok, err)
		}
	})

	t.Run("other error propagates", func(t *testing.T) {
		// A non-404 error (e.g. forbidden) must surface, not be swallowed.
		c := &Client{certs: &fakeCertOps{getErr: &azcore.ResponseError{StatusCode: http.StatusForbidden}}}
		ok, err := c.CertificateMatches(context.Background(), "cert", thumb)
		if err == nil || ok {
			t.Fatalf("expected the error to propagate, got ok=%v err=%v", ok, err)
		}
	})

	t.Run("empty cert body", func(t *testing.T) {
		// A certificate object with no CER content is treated as no match.
		c := &Client{certs: &fakeCertOps{getCER: nil}}
		ok, err := c.CertificateMatches(context.Background(), "cert", thumb)
		if err != nil || ok {
			t.Fatalf("expected (false,nil) for empty CER, got ok=%v err=%v", ok, err)
		}
	})
}

func TestNewClient(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(testCertDERWithKey(t, key))
	if err != nil {
		t.Fatal(err)
	}

	t.Run("unknown cloud", func(t *testing.T) {
		if _, err := NewCredential("tenant", "app", Cloud("Mars"), cert, key); err == nil {
			t.Fatalf("expected error for unknown cloud")
		}
	})

	for _, cl := range []Cloud{CloudPublic, CloudUSGov} {
		t.Run(string(cl), func(t *testing.T) {
			// Credential and client construction are offline, so this must
			// succeed without contacting Azure.
			cred, err := NewCredential("00000000-0000-0000-0000-000000000000", "00000000-0000-0000-0000-000000000000", cl, cert, key)
			if err != nil {
				t.Fatalf("NewCredential(%s): %v", cl, err)
			}
			// One credential opens any number of vaults.
			for _, vault := range []string{"vault-a", "vault-b"} {
				c, err := cred.NewClient(vault)
				if err != nil {
					t.Fatalf("NewClient(%s, %s): %v", cl, vault, err)
				}
				if c == nil || c.certs == nil {
					t.Fatalf("NewClient(%s, %s) returned an incomplete client", cl, vault)
				}
			}
		})
	}
}

// testCertDERWithKey builds a self-signed certificate DER for the given key, so
// the certificate and key form a matching pair for credential construction.
func testCertDERWithKey(t *testing.T, key *rsa.PrivateKey) []byte {
	t.Helper()
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "kv"}, NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestImportCertificate(t *testing.T) {
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "ca"}, NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	leafTmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "kv"}, NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour)}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, ca, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}

	f := &fakeCertOps{}
	c := &Client{certs: f}
	if err := c.ImportCertificate(context.Background(), "cert", []*x509.Certificate{leaf, ca}, leafKey); err != nil {
		t.Fatal(err)
	}
	if !f.importCalled {
		t.Fatal("ImportCertificate was not called")
	}
	pfx, err := base64.StdEncoding.DecodeString(*f.imported.Base64EncodedCertificate)
	if err != nil {
		t.Fatal(err)
	}
	key, gotLeaf, caCerts, err := pkcs12.DecodeChain(pfx, "")
	if err != nil {
		t.Fatalf("imported value is not a PFX with an empty password: %v", err)
	}
	if !gotLeaf.Equal(leaf) {
		t.Fatalf("PFX leaf mismatch")
	}
	if len(caCerts) != 1 || !caCerts[0].Equal(ca) {
		t.Fatalf("PFX CA certificates = %d, want the intermediate", len(caCerts))
	}
	if rk, ok := key.(*rsa.PrivateKey); !ok || !rk.Equal(leafKey) {
		t.Fatalf("PFX private key mismatch")
	}
	if f.imported.Password != nil {
		t.Fatalf("password = %q, want unset", *f.imported.Password)
	}
	ct := f.imported.CertificatePolicy.SecretProperties.ContentType
	if ct == nil || *ct != pkcs12ContentType {
		t.Fatalf("content type = %v, want %s", ct, pkcs12ContentType)
	}
}

func TestImportCertificateEmptyChain(t *testing.T) {
	f := &fakeCertOps{}
	c := &Client{certs: f}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.ImportCertificate(context.Background(), "cert", nil, key); err == nil {
		t.Fatal("expected an error for an empty chain")
	}
	if f.importCalled {
		t.Fatal("Key Vault must not be called with an empty chain")
	}
}
