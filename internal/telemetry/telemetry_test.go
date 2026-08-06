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

	"github.com/microsoft/ApplicationInsights-Go/appinsights"
	"github.com/microsoft/ApplicationInsights-Go/appinsights/contracts"
)

// fakeClient captures tracked telemetry without contacting Application
// Insights. The embedded interface is nil; only Track is ever called by the
// code under test, so the other methods are never reached.
type fakeClient struct {
	appinsights.TelemetryClient
	tracked []appinsights.Telemetry
}

func (f *fakeClient) Track(item appinsights.Telemetry) {
	f.tracked = append(f.tracked, item)
}

// enabledWithFake returns an enabled Telemetry whose lazily-created client has
// already been replaced with a capturing fake.
func enabledWithFake() (*Telemetry, *fakeClient) {
	fake := &fakeClient{}
	return &Telemetry{enabled: true, ikey: "test", client: fake}, fake
}

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

func TestTrackEventForwardsNameAndProps(t *testing.T) {
	tel, fake := enabledWithFake()
	tel.TrackEvent("CertificateRenewed", map[string]string{"identity": "app"})

	if len(fake.tracked) != 1 {
		t.Fatalf("expected 1 tracked item, got %d", len(fake.tracked))
	}
	ev, ok := fake.tracked[0].(*appinsights.EventTelemetry)
	if !ok {
		t.Fatalf("expected an EventTelemetry, got %T", fake.tracked[0])
	}
	if ev.Name != "CertificateRenewed" {
		t.Fatalf("event name = %q", ev.Name)
	}
	if ev.Properties["identity"] != "app" {
		t.Fatalf("event properties not copied: %v", ev.Properties)
	}
}

func TestTrackErrorTracksTraceAndException(t *testing.T) {
	tel, fake := enabledWithFake()
	tel.TrackError(errors.New("boom"), "renewal failed", map[string]string{"identity": "app"})

	// An error produces both an error-severity trace and an exception.
	if len(fake.tracked) != 2 {
		t.Fatalf("expected trace + exception, got %d items", len(fake.tracked))
	}
	trace, ok := fake.tracked[0].(*appinsights.TraceTelemetry)
	if !ok {
		t.Fatalf("first item = %T, want *TraceTelemetry", fake.tracked[0])
	}
	if trace.Message != "renewal failed" || trace.SeverityLevel != contracts.Error {
		t.Fatalf("trace = %q sev=%v", trace.Message, trace.SeverityLevel)
	}
	if trace.Properties["error"] != "boom" || trace.Properties["identity"] != "app" {
		t.Fatalf("trace properties: %v", trace.Properties)
	}
	if _, ok := fake.tracked[1].(*appinsights.ExceptionTelemetry); !ok {
		t.Fatalf("second item = %T, want *ExceptionTelemetry", fake.tracked[1])
	}
}

func TestTrackErrorNilErrorSkipsException(t *testing.T) {
	tel, fake := enabledWithFake()
	// With no error there is nothing to raise as an exception, only the trace.
	tel.TrackError(nil, "informational", nil)

	if len(fake.tracked) != 1 {
		t.Fatalf("expected only a trace, got %d items", len(fake.tracked))
	}
	trace, ok := fake.tracked[0].(*appinsights.TraceTelemetry)
	if !ok {
		t.Fatalf("item = %T, want *TraceTelemetry", fake.tracked[0])
	}
	if _, hasErr := trace.Properties["error"]; hasErr {
		t.Fatalf("no error property expected when err is nil: %v", trace.Properties)
	}
}

func ptr(s string) *string { return &s }
