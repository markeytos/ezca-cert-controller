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

package telemetry

import (
	"errors"
	"testing"
	"time"
)

func TestNewNoopWhenEmpty(t *testing.T) {
	for _, cs := range []*string{nil, ptr(""), ptr("   ")} {
		tel := New(cs)
		if tel.enabled {
			t.Fatalf("expected disabled telemetry for %v", cs)
		}
		// All methods must be safe no-ops.
		tel.TrackEvent("CertificateRenewed", map[string]string{"identity": "x"})
		tel.TrackError(errors.New("boom"), "failed", nil)
		tel.Flush(time.Second)
		if tel.client != nil {
			t.Fatalf("no-op telemetry should not create a client")
		}
	}
}

func TestParseConnString(t *testing.T) {
	cases := []struct {
		in       string
		ikey     string
		endpoint string
	}{
		{
			in:       "InstrumentationKey=abc-123;IngestionEndpoint=https://region.in.applicationinsights.azure.com/;LiveEndpoint=https://x/",
			ikey:     "abc-123",
			endpoint: "https://region.in.applicationinsights.azure.com/v2/track",
		},
		{in: "InstrumentationKey=only-key", ikey: "only-key", endpoint: ""},
		{in: "bare-key", ikey: "bare-key", endpoint: ""},
		{in: "IngestionEndpoint=https://x/", ikey: "", endpoint: "https://x/v2/track"},
	}
	for _, c := range cases {
		ikey, endpoint := parseConnString(c.in)
		if ikey != c.ikey || endpoint != c.endpoint {
			t.Fatalf("parseConnString(%q) = (%q,%q), want (%q,%q)", c.in, ikey, endpoint, c.ikey, c.endpoint)
		}
	}
}

func TestNewEnabled(t *testing.T) {
	tel := New(ptr("InstrumentationKey=00000000-0000-0000-0000-000000000000;IngestionEndpoint=https://region.in.applicationinsights.azure.com/"))
	if !tel.enabled {
		t.Fatalf("expected enabled telemetry")
	}
	if tel.ikey != "00000000-0000-0000-0000-000000000000" {
		t.Fatalf("ikey = %q", tel.ikey)
	}
	// A connection string with no instrumentation key is a no-op.
	if New(ptr("IngestionEndpoint=https://x/")).enabled {
		t.Fatalf("expected disabled without instrumentation key")
	}
}

func ptr(s string) *string { return &s }
