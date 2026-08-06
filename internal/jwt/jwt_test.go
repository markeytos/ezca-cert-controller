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

package jwt

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func TestSignRS256(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	header := map[string]any{"alg": "RS256", "typ": "JWT", "x5t": "abc"}
	claims := map[string]any{"aud": "audience", "iss": "issuer"}

	token, err := SignRS256(header, claims, key)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("expected 3 JWS parts, got %d", len(parts))
	}

	// Header and claims round-trip.
	var gotHeader, gotClaims map[string]any
	hb, _ := base64.RawURLEncoding.DecodeString(parts[0])
	cb, _ := base64.RawURLEncoding.DecodeString(parts[1])
	if err := json.Unmarshal(hb, &gotHeader); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(cb, &gotClaims); err != nil {
		t.Fatal(err)
	}
	if gotHeader["x5t"] != "abc" || gotClaims["aud"] != "audience" {
		t.Fatalf("payload mismatch: %v %v", gotHeader, gotClaims)
	}

	// Signature verifies against the public key.
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, digest[:], sig); err != nil {
		t.Fatalf("signature verify failed: %v", err)
	}
}

func TestSignRS256MarshalErrors(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	// A channel value cannot be JSON-marshalled, so both the header and the
	// claims marshal paths must surface the error rather than sign garbage.
	bad := map[string]any{"x": make(chan int)}
	ok := map[string]any{"alg": "RS256"}

	if _, err := SignRS256(bad, ok, key); err == nil {
		t.Fatalf("expected error for unmarshalable header")
	}
	if _, err := SignRS256(ok, bad, key); err == nil {
		t.Fatalf("expected error for unmarshalable claims")
	}
}
