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
	"bytes"
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
)

type fakeCertOps struct {
	getCER       []byte
	getErr       error
	importCalled bool
	imported     azcertificates.ImportCertificateParameters
}

func (f *fakeCertOps) GetCertificate(_ context.Context, _, _ string, _ *azcertificates.GetCertificateOptions) (azcertificates.GetCertificateResponse, error) {
	if f.getErr != nil {
		return azcertificates.GetCertificateResponse{}, f.getErr
	}
	return azcertificates.GetCertificateResponse{Certificate: azcertificates.Certificate{CER: f.getCER}}, nil
}

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
}

func TestImportCertificate(t *testing.T) {
	f := &fakeCertOps{}
	c := &Client{certs: f}
	bundle := []byte("-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----\n")

	if err := c.ImportCertificate(context.Background(), "cert", bundle); err != nil {
		t.Fatal(err)
	}
	if !f.importCalled {
		t.Fatal("ImportCertificate was not called")
	}
	decoded, err := base64.StdEncoding.DecodeString(*f.imported.Base64EncodedCertificate)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decoded, bundle) {
		t.Fatalf("imported bundle mismatch")
	}
	ct := f.imported.CertificatePolicy.SecretProperties.ContentType
	if ct == nil || *ct != pemContentType {
		t.Fatalf("content type = %v, want %s", ct, pemContentType)
	}
}
