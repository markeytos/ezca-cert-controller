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
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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
		"just staged":          {at(0), propagationGrace},
		"partway through":      {at(-2 * time.Minute), propagationGrace - 2*time.Minute},
		"one second remaining": {at(-propagationGrace + time.Second), time.Second},

		// Grace elapsed: poll at the propagation interval.
		"exactly at grace": {at(-propagationGrace), propagationRequeue},
		"past grace":       {at(-6 * time.Minute), propagationRequeue},
		"long past grace":  {at(-10 * 24 * time.Hour), propagationRequeue},

		// No reference time recorded (e.g. staged by an older version): fall back
		// to polling rather than dereferencing a nil timestamp.
		"nil since": {nil, propagationRequeue},
	} {
		t.Run(name, func(t *testing.T) {
			got := propagationRequeueAfter(now, v.since)
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
