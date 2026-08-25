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

package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/url"
	"testing"
	"time"
)

func makeCert(t *testing.T, notBefore, notAfter time.Time) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()
	const cn = "app.ezca.io"
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	uri, _ := url.Parse("spiffe://cluster/app")
	tmpl := &x509.Certificate{
		SerialNumber:   big.NewInt(1),
		Subject:        pkix.Name{CommonName: cn, Organization: []string{testOrg}},
		NotBefore:      notBefore,
		NotAfter:       notAfter,
		DNSNames:       []string{cn, "alt." + cn},
		EmailAddresses: []string{"admin@" + cn},
		IPAddresses:    []net.IP{net.ParseIP("10.0.0.1")},
		URIs:           []*url.URL{uri},
	}
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

func TestParseCertChainAndKeyRoundTrip(t *testing.T) {
	cert, key := makeCert(t, time.Now(), time.Now().Add(24*time.Hour))

	certPEM := EncodeCertChainPEM([]*x509.Certificate{cert})
	keyPEM, err := EncodeRSAPrivateKeyPEM(key)
	if err != nil {
		t.Fatal(err)
	}

	chain, err := ParseCertChainPEM(certPEM)
	if err != nil {
		t.Fatalf("parse chain: %v", err)
	}
	if len(chain) != 1 || !chain[0].Equal(cert) {
		t.Fatalf("round-trip cert mismatch")
	}

	parsedKey, err := ParseRSAPrivateKey(keyPEM)
	if err != nil {
		t.Fatalf("parse key: %v", err)
	}
	if parsedKey.N.Cmp(key.N) != 0 {
		t.Fatalf("round-trip key mismatch")
	}
}

func TestParseCertChainSkipsEmptyBlocks(t *testing.T) {
	cert, _ := makeCert(t, time.Now(), time.Now().Add(24*time.Hour))
	// A valid leaf followed by an empty CERTIFICATE block (as some CA
	// responses emit for an absent root).
	pemBytes := append(EncodeCertChainPEM([]*x509.Certificate{cert}),
		[]byte("-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n")...)

	chain, err := ParseCertChainPEM(pemBytes)
	if err != nil {
		t.Fatalf("expected empty block to be skipped, got: %v", err)
	}
	if len(chain) != 1 || !chain[0].Equal(cert) {
		t.Fatalf("expected only the leaf, got %d certs", len(chain))
	}
}

func TestParseRSAPrivateKeyPKCS1(t *testing.T) {
	_, key := makeCert(t, time.Now(), time.Now().Add(time.Hour))
	pkcs1 := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	if _, err := ParseRSAPrivateKey(pkcs1); err != nil {
		t.Fatalf("PKCS1 parse: %v", err)
	}
}

func TestParseRSAPrivateKeyRejectsNonRSA(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(ecKey)
	if err != nil {
		t.Fatal(err)
	}
	ecPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if _, err := ParseRSAPrivateKey(ecPEM); err == nil {
		t.Fatalf("expected error for non-RSA key")
	}
}

func TestLifetimeFractionRemaining(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	cert, _ := makeCert(t, now.Add(-90*24*time.Hour), now.Add(10*24*time.Hour))
	got := LifetimeFractionRemaining(cert, now)
	if got < 9.9 || got > 10.1 {
		t.Fatalf("expected ~10%%, got %v", got)
	}

	expired, _ := makeCert(t, now.Add(-2*time.Hour), now.Add(-time.Hour))
	if f := LifetimeFractionRemaining(expired, now); f != 0 {
		t.Fatalf("expected 0 for expired, got %v", f)
	}
}

func TestNextRenewalTime(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	// 100-day lifetime; threshold 20% => renew when 20 days remain => day 80.
	cert, _ := makeCert(t, now, now.Add(100*24*time.Hour))
	next := NextRenewalTime(cert, 20)
	want := now.Add(80 * 24 * time.Hour)
	if next.Sub(want).Abs() > time.Minute {
		t.Fatalf("expected renewal near %v, got %v", want, next)
	}
}

func TestValidityInDays(t *testing.T) {
	now := time.Now()
	cert, _ := makeCert(t, now, now.Add(90*24*time.Hour))
	if d := ValidityInDays(cert); d != 90 {
		t.Fatalf("expected 90 days, got %d", d)
	}
}

func TestBuildRenewalCSRPreservesIdentity(t *testing.T) {
	cert, _ := makeCert(t, time.Now(), time.Now().Add(24*time.Hour))

	csrDER, newKey, err := BuildRenewalCSR(cert)
	if err != nil {
		t.Fatal(err)
	}
	if newKey.N.BitLen() != 2048 {
		t.Fatalf("expected 2048-bit key, got %d", newKey.N.BitLen())
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		t.Fatal(err)
	}
	if err := csr.CheckSignature(); err != nil {
		t.Fatalf("CSR signature: %v", err)
	}
	if csr.Subject.CommonName != "app.ezca.io" {
		t.Fatalf("subject CN not preserved: %q", csr.Subject.CommonName)
	}
	if len(csr.DNSNames) != 2 || len(csr.EmailAddresses) != 1 || len(csr.IPAddresses) != 1 || len(csr.URIs) != 1 {
		t.Fatalf("SANs not preserved: dns=%v email=%v ip=%v uri=%v", csr.DNSNames, csr.EmailAddresses, csr.IPAddresses, csr.URIs)
	}
	// The CSR must be signed by the new key, not the old one.
	if csr.PublicKey.(*rsa.PublicKey).N.Cmp(newKey.N) != 0 {
		t.Fatalf("CSR not signed with the new key")
	}
}

const (
	testDNSName = "app.example.com"
	testCN      = "app"
	testOU      = "team"
	testOrg     = "Keytos"
	testEmail   = "admin@example.com"
)

func TestBuildIssuanceCSRPreservesFullDN(t *testing.T) {
	req := CertRequest{
		SubjectName: "CN=app,OU=team,O=Keytos,C=US",
		DNSNames:    []string{testDNSName},
	}
	csrDER, _, err := BuildIssuanceCSR(req)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		t.Fatal(err)
	}
	if csr.Subject.CommonName != testCN {
		t.Fatalf("CN: %q", csr.Subject.CommonName)
	}
	if len(csr.Subject.OrganizationalUnit) != 1 || csr.Subject.OrganizationalUnit[0] != testOU {
		t.Fatalf("OU not preserved: %v", csr.Subject.OrganizationalUnit)
	}
	if len(csr.Subject.Organization) != 1 || csr.Subject.Organization[0] != testOrg {
		t.Fatalf("O not preserved: %v", csr.Subject.Organization)
	}
	if len(csr.Subject.Country) != 1 || csr.Subject.Country[0] != "US" {
		t.Fatalf("C not preserved: %v", csr.Subject.Country)
	}
}

func TestBuildIssuanceCSRBareCommonName(t *testing.T) {
	csrDER, _, err := BuildIssuanceCSR(CertRequest{SubjectName: testDNSName})
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		t.Fatal(err)
	}
	if csr.Subject.CommonName != testDNSName {
		t.Fatalf("bare name not used as CN: %q", csr.Subject.CommonName)
	}
	if len(csr.Subject.Organization) != 0 {
		t.Fatalf("unexpected organization for a bare common name: %v", csr.Subject.Organization)
	}
}

func TestBuildIssuanceCSRUnsupportedAttribute(t *testing.T) {
	if _, _, err := BuildIssuanceCSR(CertRequest{SubjectName: "CN=app,XX=nope"}); err == nil {
		t.Fatalf("expected an error for an unsupported subject attribute")
	}
}

func TestThumbprint(t *testing.T) {
	cert, _ := makeCert(t, time.Now(), time.Now().Add(time.Hour))
	tp := Thumbprint(cert)
	if len(tp) != 40 {
		t.Fatalf("expected 40 hex chars, got %d (%q)", len(tp), tp)
	}
}

// makeLeafCert builds a self-signed certificate from a template so tests can
// control the subject, SANs, and key usages that LeafMatchesSpec inspects.
func makeLeafCert(t *testing.T, tmpl *x509.Certificate) *x509.Certificate {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	if tmpl.SerialNumber == nil {
		tmpl.SerialNumber = big.NewInt(1)
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func TestLeafMatchesSpecMatches(t *testing.T) {
	uri, _ := url.Parse("spiffe://cluster/app")
	cert := makeLeafCert(t, &x509.Certificate{
		Subject:        pkix.Name{CommonName: testCN, Organization: []string{testOrg}, Country: []string{"US"}},
		DNSNames:       []string{testDNSName, "alt.example.com"},
		EmailAddresses: []string{testEmail},
		IPAddresses:    []net.IP{net.ParseIP("10.0.0.1")},
		URIs:           []*url.URL{uri},
		KeyUsage:       x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	})
	req := CertRequest{
		// Type casing and spacing differ from the encoded subject; the
		// symmetric canonicalization must absorb it.
		SubjectName:     "cn=app,  o=Keytos , c=US",
		DNSNames:        []string{"alt.example.com", testDNSName}, // reordered
		EmailAddresses:  []string{testEmail},
		IPAddresses:     []net.IP{net.ParseIP("10.0.0.1")},
		URIs:            []*url.URL{uri},
		KeyUsage:        x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsageOIDs: []string{oidExtKeyUsageClientAuth, "1.3.6.1.5.5.7.3.1"}, // reordered
	}
	if !LeafMatchesSpec(cert, req) {
		t.Fatalf("expected match despite cosmetic ordering/spacing differences")
	}
}

func TestLeafMatchesSpecBareCommonName(t *testing.T) {
	cert := makeLeafCert(t, &x509.Certificate{Subject: pkix.Name{CommonName: testDNSName}})
	// A request subject with no "=" is treated as a bare common name.
	if !LeafMatchesSpec(cert, CertRequest{SubjectName: testDNSName}) {
		t.Fatalf("expected bare common name to match")
	}
}

func TestLeafMatchesSpecDetectsDrift(t *testing.T) {
	base := &x509.Certificate{
		Subject:        pkix.Name{CommonName: testCN},
		DNSNames:       []string{testDNSName},
		EmailAddresses: []string{testEmail},
		IPAddresses:    []net.IP{net.ParseIP("10.0.0.1")},
		KeyUsage:       x509.KeyUsageDigitalSignature,
		ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	cert := makeLeafCert(t, base)

	cases := []struct {
		name string
		req  CertRequest
	}{
		{"subject", CertRequest{SubjectName: "other"}},
		{"dns", CertRequest{SubjectName: testCN, DNSNames: []string{"other.example.com"}}},
		{"email", CertRequest{SubjectName: testCN, DNSNames: []string{testDNSName}, EmailAddresses: []string{"nope@example.com"}}},
		{"ip", CertRequest{SubjectName: testCN, DNSNames: []string{testDNSName}, EmailAddresses: []string{testEmail}, IPAddresses: []net.IP{net.ParseIP("10.0.0.2")}}},
		{"keyusage", CertRequest{SubjectName: testCN, DNSNames: []string{testDNSName}, EmailAddresses: []string{testEmail}, IPAddresses: []net.IP{net.ParseIP("10.0.0.1")}, KeyUsage: x509.KeyUsageCertSign}},
		{"eku", CertRequest{SubjectName: testCN, DNSNames: []string{testDNSName}, EmailAddresses: []string{testEmail}, IPAddresses: []net.IP{net.ParseIP("10.0.0.1")}, ExtKeyUsageOIDs: []string{oidExtKeyUsageClientAuth}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if LeafMatchesSpec(cert, tc.req) {
				t.Fatalf("expected %s drift to be detected", tc.name)
			}
		})
	}
}

func TestLeafMatchesSpecIgnoresRDNOrder(t *testing.T) {
	cert := makeLeafCert(t, &x509.Certificate{
		Subject: pkix.Name{CommonName: testCN, Organization: []string{"corp"}, OrganizationalUnit: []string{testOU}},
	})
	// The request lists the same RDNs in a different order; order must not matter.
	if !LeafMatchesSpec(cert, CertRequest{SubjectName: "O=corp,OU=team,CN=app"}) {
		t.Fatalf("expected match regardless of RDN order")
	}
	if !LeafMatchesSpec(cert, CertRequest{SubjectName: "OU=team,CN=app,O=corp"}) {
		t.Fatalf("expected match regardless of RDN order")
	}
}

func TestLeafMatchesSpecIgnoresUnsetUsages(t *testing.T) {
	cert := makeLeafCert(t, &x509.Certificate{
		Subject:     pkix.Name{CommonName: testCN},
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	// KeyUsage 0 and empty ExtKeyUsageOIDs mean "issuer chose", so a differing
	// certificate must still match.
	if !LeafMatchesSpec(cert, CertRequest{SubjectName: testCN}) {
		t.Fatalf("unset key usages should not be compared")
	}
}

func TestParseIPAddresses(t *testing.T) {
	ips, err := ParseIPAddresses([]string{"10.0.0.1", "2001:db8::1"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ips) != 2 {
		t.Fatalf("expected 2 IPs, got %d", len(ips))
	}
	if got, err := ParseIPAddresses(nil); err != nil || got != nil {
		t.Fatalf("empty input: got %v, %v", got, err)
	}
	if _, err := ParseIPAddresses([]string{"not-an-ip"}); err == nil {
		t.Fatalf("expected error for malformed IP")
	}
}

func TestParseURIs(t *testing.T) {
	uris, err := ParseURIs([]string{"spiffe://cluster/app", "https://example.com/x"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(uris) != 2 || uris[0].Scheme != "spiffe" {
		t.Fatalf("unexpected parse result: %v", uris)
	}
	if got, err := ParseURIs(nil); err != nil || got != nil {
		t.Fatalf("empty input: got %v, %v", got, err)
	}
	if _, err := ParseURIs([]string{"://bad"}); err == nil {
		t.Fatalf("expected error for malformed URI")
	}
}

func TestSubjectFromNameMultiValuedRDN(t *testing.T) {
	// A "+"-joined RDN and a DC domain component exercise the escaped-separator
	// split and the ExtraNames path.
	csrDER, _, err := BuildIssuanceCSR(CertRequest{SubjectName: "CN=app+OU=team,DC=example"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		t.Fatal(err)
	}
	if csr.Subject.CommonName != testCN {
		t.Fatalf("CN: %q", csr.Subject.CommonName)
	}
	if len(csr.Subject.OrganizationalUnit) != 1 || csr.Subject.OrganizationalUnit[0] != testOU {
		t.Fatalf("multi-valued RDN not parsed: %v", csr.Subject.OrganizationalUnit)
	}
}

func TestSubjectFromNameMissingValue(t *testing.T) {
	// An RDN with no "=" after splitting is malformed.
	if _, _, err := BuildIssuanceCSR(CertRequest{SubjectName: "CN=app,justtext"}); err == nil {
		t.Fatalf("expected error for RDN without an assignment")
	}
}
