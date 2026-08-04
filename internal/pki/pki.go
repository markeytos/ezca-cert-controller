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

// Package pki holds certificate and key helpers used by the controller:
// parsing the bootstrapped TLS Secret, measuring certificate lifetime, and
// building the renewal CSR.
package pki

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"
)

// privateKeyPEMType is the PEM block type for a PKCS#8 private key.
const privateKeyPEMType = "PRIVATE KEY"

// ParseCertChainPEM parses one or more concatenated PEM CERTIFICATE blocks. The
// first certificate is the leaf.
func ParseCertChainPEM(pemBytes []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	rest := pemBytes
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		// Skip non-certificate blocks and empty CERTIFICATE blocks (some CA
		// responses include an empty PEM block for an absent chain element).
		if block.Type != "CERTIFICATE" || len(block.Bytes) == 0 {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		certs = append(certs, cert)
	}
	if len(certs) == 0 {
		return nil, errors.New("pki: no certificates found in PEM data")
	}
	return certs, nil
}

// ParseRSAPrivateKey parses a PEM-encoded RSA private key in PKCS#1 or PKCS#8
// form. Non-RSA keys are rejected: EZCA renewal and the Entra proof both
// require RSA.
func ParseRSAPrivateKey(pemBytes []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("pki: no PEM block found in private key data")
	}
	switch block.Type {
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	case privateKeyPEMType:
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		rsaKey, ok := key.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.New("pki: private key is not RSA")
		}
		return rsaKey, nil
	default:
		return nil, fmt.Errorf("pki: unsupported private key type %q", block.Type)
	}
}

// LifetimeFractionRemaining returns the percentage (0-100) of the certificate's
// total validity window that is still remaining at now.
func LifetimeFractionRemaining(cert *x509.Certificate, now time.Time) float64 {
	total := cert.NotAfter.Sub(cert.NotBefore)
	if total <= 0 {
		return 0
	}
	remaining := cert.NotAfter.Sub(now)
	if remaining <= 0 {
		return 0
	}
	return float64(remaining) / float64(total) * 100
}

// NextRenewalTime returns the moment the certificate's remaining lifetime
// fraction reaches thresholdPct, i.e. when renewal becomes due.
func NextRenewalTime(cert *x509.Certificate, thresholdPct int32) time.Time {
	total := cert.NotAfter.Sub(cert.NotBefore)
	thresholdDuration := time.Duration(float64(total) * float64(thresholdPct) / 100)
	return cert.NotAfter.Add(-thresholdDuration)
}

// ValidityInDays returns the certificate's total lifetime rounded to whole
// days, used as the requested lifetime of the renewed certificate.
func ValidityInDays(cert *x509.Certificate) int {
	total := cert.NotAfter.Sub(cert.NotBefore)
	days := int(total.Hours() / 24)
	if days < 1 {
		return 1
	}
	return days
}

// Thumbprint returns the SHA-1 thumbprint of the certificate as an uppercase
// hex string.
func Thumbprint(cert *x509.Certificate) string {
	sum := sha1.Sum(cert.Raw)
	return strings.ToUpper(hex.EncodeToString(sum[:]))
}

// BuildRenewalCSR generates a new RSA key (matching the existing key size) and
// a DER-encoded PKCS#10 CSR that preserves the existing certificate's subject
// and subject alternative names, so EZCA accepts the renewal.
func BuildRenewalCSR(oldCert *x509.Certificate) ([]byte, *rsa.PrivateKey, error) {
	pub, ok := oldCert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, nil, errors.New("pki: existing certificate is not RSA")
	}
	newKey, err := rsa.GenerateKey(rand.Reader, pub.N.BitLen())
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.CertificateRequest{
		// RawSubject preserves the exact DN encoding of the existing cert.
		RawSubject:     oldCert.RawSubject,
		DNSNames:       oldCert.DNSNames,
		EmailAddresses: oldCert.EmailAddresses,
		IPAddresses:    oldCert.IPAddresses,
		URIs:           oldCert.URIs,
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, tmpl, newKey)
	if err != nil {
		return nil, nil, err
	}
	return csrDER, newKey, nil
}

// EncodeCertChainPEM concatenates the certificates into PEM CERTIFICATE blocks.
func EncodeCertChainPEM(certs []*x509.Certificate) []byte {
	var buf bytes.Buffer
	for _, c := range certs {
		// pem.Encode only errors on writer failure; a bytes.Buffer never fails.
		_ = pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
	}
	return buf.Bytes()
}

// EncodeRSAPrivateKeyPEM encodes the RSA private key as a PKCS#8 PEM block.
func EncodeRSAPrivateKeyPEM(key *rsa.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: privateKeyPEMType, Bytes: der}), nil
}
