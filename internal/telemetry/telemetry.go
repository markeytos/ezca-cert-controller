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

// Package telemetry wraps Azure Application Insights so the controller can
// report renewals, rotations, and errors. It is a no-op when no connection
// string is configured, and it emits events sparingly so a frequent reconcile
// loop does not flood Application Insights.
package telemetry

import (
	"maps"
	"strings"
	"time"

	"github.com/microsoft/ApplicationInsights-Go/appinsights"
	"github.com/microsoft/ApplicationInsights-Go/appinsights/contracts"
)

// Telemetry reports controller events to Application Insights. The zero value
// and a Telemetry built from an empty connection string are safe no-ops.
type Telemetry struct {
	ikey     string
	endpoint string
	enabled  bool
	client   appinsights.TelemetryClient
}

// New builds a Telemetry from an Application Insights connection string. When
// the string is nil, empty, or has no instrumentation key, the result is a
// no-op.
func New(connString *string) *Telemetry {
	if connString == nil || strings.TrimSpace(*connString) == "" {
		return &Telemetry{}
	}
	ikey, endpoint := parseConnString(*connString)
	if ikey == "" {
		return &Telemetry{}
	}
	return &Telemetry{ikey: ikey, endpoint: endpoint, enabled: true}
}

// parseConnString extracts the instrumentation key and (optional) ingestion
// track endpoint from an Application Insights connection string. A bare
// instrumentation key is also accepted.
func parseConnString(cs string) (ikey, endpoint string) {
	for part := range strings.SplitSeq(cs, ";") {
		kv := strings.SplitN(part, "=", 2)
		if len(kv) != 2 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(kv[0]))
		val := strings.TrimSpace(kv[1])
		switch key {
		case "instrumentationkey":
			ikey = val
		case "ingestionendpoint":
			endpoint = strings.TrimRight(val, "/") + "/v2/track"
		}
	}
	if ikey == "" && !strings.Contains(cs, "=") {
		ikey = strings.TrimSpace(cs)
	}
	return ikey, endpoint
}

// ensureClient lazily constructs the underlying telemetry client so an enabled
// but idle reconcile does not spin up a channel goroutine.
func (t *Telemetry) ensureClient() appinsights.TelemetryClient {
	if !t.enabled {
		return nil
	}
	if t.client == nil {
		config := appinsights.NewTelemetryConfiguration(t.ikey)
		if t.endpoint != "" {
			config.EndpointUrl = t.endpoint
		}
		t.client = appinsights.NewTelemetryClientFromConfig(config)
	}
	return t.client
}

// TrackEvent records a meaningful state change (e.g. a renewal or rotation).
// Call it sparingly.
func (t *Telemetry) TrackEvent(name string, props map[string]string) {
	c := t.ensureClient()
	if c == nil {
		return
	}
	ev := appinsights.NewEventTelemetry(name)
	maps.Copy(ev.Properties, props)
	c.Track(ev)
}

// TrackError records a failure as both an error-severity trace and an
// exception. It is always safe to call and is a no-op when telemetry is
// disabled.
func (t *Telemetry) TrackError(err error, message string, props map[string]string) {
	c := t.ensureClient()
	if c == nil {
		return
	}
	trace := appinsights.NewTraceTelemetry(message, contracts.Error)
	maps.Copy(trace.Properties, props)
	if err != nil {
		trace.Properties["error"] = err.Error()
	}
	c.Track(trace)
	if err != nil {
		exc := appinsights.NewExceptionTelemetry(err)
		maps.Copy(exc.Properties, props)
		c.Track(exc)
	}
}

// Flush submits any buffered telemetry, waiting up to timeout. It is a no-op
// when nothing has been tracked.
func (t *Telemetry) Flush(timeout time.Duration) {
	if t.client == nil {
		return
	}
	select {
	case <-t.client.Channel().Close(timeout):
	case <-time.After(timeout + time.Second):
	}
}
