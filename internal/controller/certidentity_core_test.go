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

package controller

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/microsoft/ApplicationInsights-Go/appinsights"
	"github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"

	ezcav1 "github.com/markeytos/ezca-cert-controller/api/v1"
	"github.com/markeytos/ezca-cert-controller/internal/pki"
	"github.com/markeytos/ezca-cert-controller/internal/telemetry"
)

func TestPropagationRequeueAfter(t *testing.T) {
	now := time.Date(2026, 8, 7, 0, 0, 0, 0, time.UTC)
	at := func(d time.Duration) *metav1.Time { return &metav1.Time{Time: now.Add(d)} }

	for name, v := range map[string]struct {
		since *metav1.Time
		want  time.Duration
	}{
		// Inside the grace window: wait out the remainder in one go rather than
		// polling, since authenticating with the certificate cannot succeed yet.
		"just staged":          {at(0), DefaultPropagationGrace},
		"partway through":      {at(-2 * time.Minute), DefaultPropagationGrace - 2*time.Minute},
		"one second remaining": {at(-DefaultPropagationGrace + time.Second), time.Second},

		// Grace elapsed: poll at the propagation interval.
		"exactly at grace": {at(-DefaultPropagationGrace), propagationRequeue},
		"past grace":       {at(-DefaultPropagationGrace - time.Minute), propagationRequeue},
		"long past grace":  {at(-10 * 24 * time.Hour), propagationRequeue},

		// No reference time recorded (e.g. staged by an older version): fall back
		// to polling rather than dereferencing a nil timestamp.
		"nil since": {nil, propagationRequeue},
	} {
		t.Run(name, func(t *testing.T) {
			got := propagationRequeueAfter(now, v.since, DefaultPropagationGrace)
			if got != v.want {
				t.Errorf("propagationRequeueAfter() = %v, want %v", got, v.want)
			}
			// A non-positive RequeueAfter means "do not requeue" to
			// controller-runtime, which would strand the certificate forever.
			if got <= 0 {
				t.Errorf("propagationRequeueAfter() = %v, must always be positive", got)
			}
		})
	}
}

func TestPropagationTimingValidate(t *testing.T) {
	for name, v := range map[string]struct {
		timing  PropagationTiming
		wantErr bool
	}{
		"defaults":                {PropagationTiming{Grace: DefaultPropagationGrace, Timeout: DefaultPropagationTimeout}, false},
		"zero grace":              {PropagationTiming{Grace: 0, Timeout: time.Hour}, true},
		"negative grace":          {PropagationTiming{Grace: -time.Minute, Timeout: time.Hour}, true},
		"timeout equals grace":    {PropagationTiming{Grace: time.Hour, Timeout: time.Hour}, true},
		"timeout below the grace": {PropagationTiming{Grace: time.Hour, Timeout: 30 * time.Minute}, true},
	} {
		t.Run(name, func(t *testing.T) {
			if err := v.timing.Validate(); (err != nil) != v.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, v.wantErr)
			}
		})
	}
}

// capturingClient records tracked telemetry instead of sending it. The
// embedded interface is nil; only Track is called by the code under test.
type capturingClient struct {
	appinsights.TelemetryClient
	tracked []appinsights.Telemetry
}

func (c *capturingClient) Track(item appinsights.Telemetry) {
	c.tracked = append(c.tracked, item)
}

// errorMessages returns the messages of the error traces tracked so far, one
// per TrackError call.
func (c *capturingClient) errorMessages() []string {
	var msgs []string
	for _, item := range c.tracked {
		if trace, ok := item.(*appinsights.TraceTelemetry); ok {
			msgs = append(msgs, trace.Message)
		}
	}
	return msgs
}

func TestExpiryWarningTime(t *testing.T) {
	notBefore := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	notAfter := notBefore.Add(100 * 24 * time.Hour)
	// Renewal starts with 20% of the lifetime left; the warning comes once half
	// of that window has passed.
	if got, want := expiryWarningTime(notBefore, notAfter, 20), notAfter.Add(-10*24*time.Hour); !got.Equal(want) {
		t.Errorf("expiryWarningTime() = %v, want %v", got, want)
	}
}

func TestWarnIfExpiring(t *testing.T) {
	notBefore := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	notAfter := notBefore.Add(100 * 24 * time.Hour)
	warnAt := notAfter.Add(-10 * 24 * time.Hour)
	ctx := context.Background()

	newIdentity := func() *ezcav1.CertIdentity {
		ci := &ezcav1.CertIdentity{
			ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: "team", UID: types.UID("uid-1")},
			Spec:       ezcav1.CertIdentitySpec{CertIdentitySpecBase: ezcav1.CertIdentitySpecBase{RenewalThreshold: 20}},
		}
		ci.Status.Thumbprint = "ABC"
		ci.Status.NotBefore = &metav1.Time{Time: notBefore}
		ci.Status.NotAfter = &metav1.Time{Time: notAfter}
		return ci
	}

	t.Run("before the warning window", func(t *testing.T) {
		r := &ReconcilerBase{}
		fake := &capturingClient{}
		now := warnAt.Add(-48 * time.Hour)
		var result ctrl.Result
		r.warnIfExpiring(ctx, newIdentity(), now, telemetry.NewWithClient(fake), &result)
		if len(fake.tracked) != 0 {
			t.Fatalf("tracked %d items before the warning window", len(fake.tracked))
		}
		// An identity that would otherwise not requeue (or requeue later) is
		// reconciled when the warning becomes due.
		if result.RequeueAfter != 48*time.Hour {
			t.Errorf("RequeueAfter = %v, want %v", result.RequeueAfter, 48*time.Hour)
		}
		result = ctrl.Result{RequeueAfter: time.Hour}
		r.warnIfExpiring(ctx, newIdentity(), now, telemetry.NewWithClient(fake), &result)
		if result.RequeueAfter != time.Hour {
			t.Errorf("RequeueAfter = %v, want an earlier requeue kept", result.RequeueAfter)
		}
	})

	t.Run("reports once per interval", func(t *testing.T) {
		r := &ReconcilerBase{}
		fake := &capturingClient{}
		tel := telemetry.NewWithClient(fake)
		now := warnAt.Add(time.Hour)
		var result ctrl.Result
		r.warnIfExpiring(ctx, newIdentity(), now, tel, &result)
		if got := fake.errorMessages(); len(got) != 1 || got[0] != "Certificate is close to expiry and has not been renewed" {
			t.Fatalf("reported %q", got)
		}
		exc, ok := fake.tracked[1].(*appinsights.ExceptionTelemetry)
		if !ok {
			t.Fatalf("second item = %T, want an exception", fake.tracked[1])
		}
		if exc.Properties["notAfter"] != notAfter.Format(time.RFC3339) || exc.Properties["identity"] != "app" {
			t.Errorf("exception properties = %v", exc.Properties)
		}
		if result.RequeueAfter != expiryWarningInterval {
			t.Errorf("RequeueAfter = %v, want %v", result.RequeueAfter, expiryWarningInterval)
		}

		r.warnIfExpiring(ctx, newIdentity(), now.Add(expiryWarningInterval-time.Minute), tel, &ctrl.Result{})
		if got := fake.errorMessages(); len(got) != 1 {
			t.Fatalf("reported again within the interval: %q", got)
		}
		r.warnIfExpiring(ctx, newIdentity(), now.Add(expiryWarningInterval), tel, &ctrl.Result{})
		if got := fake.errorMessages(); len(got) != 2 {
			t.Fatalf("not reported again after the interval: %q", got)
		}
	})

	t.Run("expired", func(t *testing.T) {
		r := &ReconcilerBase{}
		fake := &capturingClient{}
		r.warnIfExpiring(ctx, newIdentity(), notAfter.Add(time.Minute), telemetry.NewWithClient(fake), &ctrl.Result{})
		if got := fake.errorMessages(); len(got) != 1 || got[0] != "Certificate has expired" {
			t.Fatalf("reported %q", got)
		}
	})

	t.Run("renewal resets the interval", func(t *testing.T) {
		r := &ReconcilerBase{}
		fake := &capturingClient{}
		tel := telemetry.NewWithClient(fake)
		now := warnAt.Add(time.Hour)
		r.warnIfExpiring(ctx, newIdentity(), now, tel, &ctrl.Result{})

		renewed := newIdentity()
		renewed.Status.NotBefore = &metav1.Time{Time: now}
		renewed.Status.NotAfter = &metav1.Time{Time: now.Add(100 * 24 * time.Hour)}
		r.warnIfExpiring(ctx, renewed, now.Add(time.Minute), tel, &ctrl.Result{})
		if got := fake.errorMessages(); len(got) != 1 {
			t.Fatalf("reported a renewed certificate: %q", got)
		}
		// A certificate that is close to expiry again is reported straight
		// away, not held back by the earlier report.
		r.warnIfExpiring(ctx, newIdentity(), now.Add(2*time.Minute), tel, &ctrl.Result{})
		if got := fake.errorMessages(); len(got) != 2 {
			t.Fatalf("not reported after the interval was reset: %q", got)
		}
	})

	t.Run("no observed certificate", func(t *testing.T) {
		r := &ReconcilerBase{}
		fake := &capturingClient{}
		ci := newIdentity()
		ci.Status.NotBefore, ci.Status.NotAfter = nil, nil
		var result ctrl.Result
		r.warnIfExpiring(ctx, ci, notAfter, telemetry.NewWithClient(fake), &result)
		if len(fake.tracked) != 0 || result.RequeueAfter != 0 {
			t.Errorf("tracked %d items, RequeueAfter = %v; want nothing", len(fake.tracked), result.RequeueAfter)
		}
	})
}

func TestReportLostCertificate(t *testing.T) {
	secretName := types.NamespacedName{Namespace: "team", Name: "app-cert"}

	// Never bootstrapped: nothing was lost, so nothing is reported.
	fake := &capturingClient{}
	reportLostCertificate(&ezcav1.CertIdentity{}, secretName, telemetry.NewWithClient(fake))
	if len(fake.tracked) != 0 {
		t.Fatalf("tracked %d items for an identity that never had a certificate", len(fake.tracked))
	}

	ci := &ezcav1.CertIdentity{}
	ci.Status.Thumbprint = "ABC"
	reportLostCertificate(ci, secretName, telemetry.NewWithClient(fake))
	if got := fake.errorMessages(); len(got) != 1 || got[0] != "Certificate Secret lost its certificate" {
		t.Fatalf("reported %q", got)
	}
}

func TestRenewReportsEZCAClientFailure(t *testing.T) {
	gomega.RegisterTestingT(t) // genCertSANs asserts with Gomega
	now := time.Now()
	_, keyPEM, cert := genCertSANs("app", nil, now.Add(-time.Hour), now.Add(time.Hour))
	key, err := pki.ParseRSAPrivateKey(keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	r := &CertIdentityReconciler{ReconcilerBase: ReconcilerBase{
		NewEZCAClient: func(string) (ezcaRenewer, error) { return nil, errors.New("invalid EZCA URL") },
	}}
	ezcaURL := "https://ezca.example"
	ci := &ezcav1.CertIdentity{Spec: ezcav1.CertIdentitySpec{CertIdentitySpecBase: ezcav1.CertIdentitySpecBase{EZCAURL: &ezcaURL}}}
	fake := &capturingClient{}

	if _, _, err := renew(context.Background(), r, ci, cert, key, telemetry.NewWithClient(fake)); err == nil {
		t.Fatal("renew() succeeded, want the EZCA client error")
	}
	if got := fake.errorMessages(); len(got) != 1 || got[0] != "Failed to create EZCA client" {
		t.Fatalf("reported %q", got)
	}
}
