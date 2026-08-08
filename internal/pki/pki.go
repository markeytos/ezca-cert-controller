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
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/url"
	"slices"
	"strings"
	"time"
)

// privateKeyPEMType is the PEM block type for a PKCS#8 private key.
const privateKeyPEMType = "PRIVATE KEY"

// issuanceKeyBits is the RSA key size used for freshly issued certificates.
const issuanceKeyBits = 4096

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

// CertRequest is the desired subject and subject alternative names for a
// freshly issued certificate, with the SANs already parsed into their typed
// forms.
type CertRequest struct {
	// SubjectName may be a full RFC 4514 distinguished name or a bare common
	// name (treated as the CN).
	SubjectName    string
	DNSNames       []string
	IPAddresses    []net.IP
	URIs           []*url.URL
	EmailAddresses []string
	// KeyUsage is the requested key-usage bitmask. Zero means unspecified (the
	// issuer chooses), so it is not compared for drift.
	KeyUsage x509.KeyUsage
	// ExtKeyUsageOIDs are the requested extended key usages as dotted OID
	// strings. Empty means unspecified, so it is not compared for drift.
	ExtKeyUsageOIDs []string
}

// BuildIssuanceCSR generates a new RSA key and a DER-encoded PKCS#10 CSR for a
// freshly issued (not renewed) certificate. EZCA sets the authoritative subject
// and SANs from the sign request itself, so the CSR primarily carries the public
// key, but it mirrors the requested subject and SANs.
func BuildIssuanceCSR(req CertRequest) ([]byte, *rsa.PrivateKey, error) {
	subject, err := subjectFromName(req.SubjectName)
	if err != nil {
		return nil, nil, err
	}
	newKey, err := rsa.GenerateKey(rand.Reader, issuanceKeyBits)
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.CertificateRequest{
		Subject:        subject,
		DNSNames:       req.DNSNames,
		IPAddresses:    req.IPAddresses,
		URIs:           req.URIs,
		EmailAddresses: req.EmailAddresses,
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, tmpl, newKey)
	if err != nil {
		return nil, nil, err
	}
	return csrDER, newKey, nil
}

// LeafMatchesSpec reports whether the leaf certificate's subject, subject
// alternative names, and (when requested) key usages match the request. The
// subject comparison canonicalizes both sides symmetrically, so cosmetic
// formatting differences do not register as drift; SANs and extended key usages
// are compared as sets. Key usages and extended key usages are only compared
// when the request sets them (an empty request means the issuer chose the
// defaults, so there is nothing to compare against).
func LeafMatchesSpec(cert *x509.Certificate, req CertRequest) bool {
	spec := req.SubjectName
	if !strings.Contains(spec, "=") {
		// No attribute assignment: treat the whole value as a common name.
		spec = "CN=" + spec
	}
	if canonicalDN(spec) != canonicalDN(cert.Subject.String()) {
		return false
	}
	if !equalStringSet(cert.DNSNames, req.DNSNames) ||
		!equalStringSet(cert.EmailAddresses, req.EmailAddresses) ||
		!equalStringSet(ipStrings(cert.IPAddresses), ipStrings(req.IPAddresses)) ||
		!equalStringSet(uriStrings(cert.URIs), uriStrings(req.URIs)) {
		return false
	}
	if req.KeyUsage != 0 && cert.KeyUsage != req.KeyUsage {
		return false
	}
	if len(req.ExtKeyUsageOIDs) > 0 && !equalStringSet(certExtKeyUsageOIDs(cert), req.ExtKeyUsageOIDs) {
		return false
	}
	return true
}

// oidExtKeyUsageClientAuth is the dotted OID for the TLS client-authentication
// extended key usage, shared between the lookup table and the tests.
const oidExtKeyUsageClientAuth = "1.3.6.1.5.5.7.3.2"

// extKeyUsageOID maps the parsed x509 extended key usages back to their dotted
// OID strings, so a certificate's EKUs can be compared against a request.
var extKeyUsageOID = map[x509.ExtKeyUsage]string{
	x509.ExtKeyUsageAny:                            "2.5.29.37.0",
	x509.ExtKeyUsageServerAuth:                     "1.3.6.1.5.5.7.3.1",
	x509.ExtKeyUsageClientAuth:                     oidExtKeyUsageClientAuth,
	x509.ExtKeyUsageCodeSigning:                    "1.3.6.1.5.5.7.3.3",
	x509.ExtKeyUsageEmailProtection:                "1.3.6.1.5.5.7.3.4",
	x509.ExtKeyUsageIPSECEndSystem:                 "1.3.6.1.5.5.7.3.5",
	x509.ExtKeyUsageIPSECTunnel:                    "1.3.6.1.5.5.7.3.6",
	x509.ExtKeyUsageIPSECUser:                      "1.3.6.1.5.5.7.3.7",
	x509.ExtKeyUsageTimeStamping:                   "1.3.6.1.5.5.7.3.8",
	x509.ExtKeyUsageOCSPSigning:                    "1.3.6.1.5.5.7.3.9",
	x509.ExtKeyUsageMicrosoftServerGatedCrypto:     "1.3.6.1.4.1.311.10.3.3",
	x509.ExtKeyUsageNetscapeServerGatedCrypto:      "2.16.840.1.113730.4.1",
	x509.ExtKeyUsageMicrosoftCommercialCodeSigning: "1.3.6.1.4.1.311.2.1.22",
	x509.ExtKeyUsageMicrosoftKernelCodeSigning:     "1.3.6.1.4.1.311.61.1.1",
}

// certExtKeyUsageOIDs returns every extended key usage on the certificate as a
// dotted OID string, including any the x509 parser did not recognize.
func certExtKeyUsageOIDs(cert *x509.Certificate) []string {
	oids := make([]string, 0, len(cert.ExtKeyUsage)+len(cert.UnknownExtKeyUsage))
	for _, eku := range cert.ExtKeyUsage {
		if oid, ok := extKeyUsageOID[eku]; ok {
			oids = append(oids, oid)
		}
	}
	for _, oid := range cert.UnknownExtKeyUsage {
		oids = append(oids, oid.String())
	}
	return oids
}

// ParseIPAddresses parses IP-address SAN strings into net.IP, erroring on any
// malformed entry.
func ParseIPAddresses(addrs []string) ([]net.IP, error) {
	if len(addrs) == 0 {
		return nil, nil
	}
	ips := make([]net.IP, 0, len(addrs))
	for _, a := range addrs {
		ip := net.ParseIP(a)
		if ip == nil {
			return nil, fmt.Errorf("pki: invalid IP address %q", a)
		}
		ips = append(ips, ip)
	}
	return ips, nil
}

// ParseURIs parses URI SAN strings into *url.URL, erroring on any malformed
// entry.
func ParseURIs(uris []string) ([]*url.URL, error) {
	if len(uris) == 0 {
		return nil, nil
	}
	out := make([]*url.URL, 0, len(uris))
	for _, u := range uris {
		parsed, err := url.Parse(u)
		if err != nil {
			return nil, fmt.Errorf("pki: invalid URI %q: %w", u, err)
		}
		out = append(out, parsed)
	}
	return out, nil
}

func ipStrings(ips []net.IP) []string {
	out := make([]string, len(ips))
	for i, ip := range ips {
		out[i] = ip.String()
	}
	return out
}

func uriStrings(uris []*url.URL) []string {
	out := make([]string, len(uris))
	for i, u := range uris {
		out[i] = u.String()
	}
	return out
}

// attributeTypeOID maps the distinguished-name attribute types not represented
// by a dedicated pkix.Name field to their object identifiers.
var attributeTypeOID = map[string]asn1.ObjectIdentifier{
	"DC":           {0, 9, 2342, 19200300, 100, 1, 25},
	"UID":          {0, 9, 2342, 19200300, 100, 1, 1},
	"E":            {1, 2, 840, 113549, 1, 9, 1},
	"EMAILADDRESS": {1, 2, 840, 113549, 1, 9, 1},
}

// subjectFromName builds a certificate subject from a subject string. The string
// may be a full RFC 4514 distinguished name (for example
// "CN=app,OU=team,O=corp"), whose relative distinguished names are all
// preserved, or a bare common name, which is treated as the CN.
func subjectFromName(subjectName string) (pkix.Name, error) {
	if !strings.Contains(subjectName, "=") {
		return pkix.Name{CommonName: subjectName}, nil
	}
	var name pkix.Name
	for _, rdn := range splitUnescaped(subjectName, ',') {
		for _, part := range splitUnescaped(rdn, '+') {
			typ, val, ok := strings.Cut(part, "=")
			if !ok {
				return pkix.Name{}, fmt.Errorf("pki: invalid subject RDN %q", part)
			}
			t := strings.ToUpper(strings.TrimSpace(typ))
			v := strings.TrimSpace(val)
			switch t {
			case "CN":
				name.CommonName = v
			case "O":
				name.Organization = append(name.Organization, v)
			case "OU":
				name.OrganizationalUnit = append(name.OrganizationalUnit, v)
			case "C":
				name.Country = append(name.Country, v)
			case "L":
				name.Locality = append(name.Locality, v)
			case "ST", "S":
				name.Province = append(name.Province, v)
			case "STREET":
				name.StreetAddress = append(name.StreetAddress, v)
			case "POSTALCODE":
				name.PostalCode = append(name.PostalCode, v)
			case "SERIALNUMBER":
				name.SerialNumber = v
			default:
				oid, ok := attributeTypeOID[t]
				if !ok {
					return pkix.Name{}, fmt.Errorf("pki: unsupported subject attribute %q", t)
				}
				name.ExtraNames = append(name.ExtraNames, pkix.AttributeTypeAndValue{Type: oid, Value: v})
			}
		}
	}
	return name, nil
}

// canonicalDN normalizes a distinguished name string into a comparable form:
// attribute types upper-cased, whitespace trimmed, multi-valued RDN parts
// sorted, and the relative distinguished names themselves sorted so their order
// does not matter (for example "O=corp,OU=team" compares equal to
// "OU=team,O=corp"). It is intentionally lightweight and is applied
// symmetrically to both compared DNs, so equal DNs written with minor
// formatting or ordering differences normalize identically.
func canonicalDN(dn string) string {
	rdns := splitUnescaped(dn, ',')
	for i, rdn := range rdns {
		parts := splitUnescaped(rdn, '+')
		for j, part := range parts {
			if typ, val, ok := strings.Cut(part, "="); ok {
				parts[j] = strings.ToUpper(strings.TrimSpace(typ)) + "=" + strings.TrimSpace(val)
			} else {
				parts[j] = strings.TrimSpace(part)
			}
		}
		slices.Sort(parts)
		rdns[i] = strings.Join(parts, "+")
	}
	slices.Sort(rdns)
	return strings.Join(rdns, ",")
}

// splitUnescaped splits s on sep, ignoring separators preceded by a backslash,
// and trims surrounding whitespace from each field.
func splitUnescaped(s string, sep byte) []string {
	var fields []string
	var cur strings.Builder
	escaped := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case escaped:
			cur.WriteByte(c)
			escaped = false
		case c == '\\':
			cur.WriteByte(c)
			escaped = true
		case c == sep:
			fields = append(fields, strings.TrimSpace(cur.String()))
			cur.Reset()
		default:
			cur.WriteByte(c)
		}
	}
	fields = append(fields, strings.TrimSpace(cur.String()))
	return fields
}

// equalStringSet reports whether a and b contain the same set of strings,
// ignoring order and duplicates.
func equalStringSet(a, b []string) bool {
	set := make(map[string]struct{}, len(a))
	for _, v := range a {
		set[v] = struct{}{}
	}
	other := make(map[string]struct{}, len(b))
	for _, v := range b {
		other[v] = struct{}{}
	}
	if len(set) != len(other) {
		return false
	}
	for v := range set {
		if _, ok := other[v]; !ok {
			return false
		}
	}
	return true
}
