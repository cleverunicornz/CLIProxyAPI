// Verbatim probe of validator a232 (CLIProxyAPI #9 at cda83cdf, round 3).
package management

import (
	"net/http"
	"runtime"
	"strings"
	"testing"
	"time"
)

// Force the status reader to record expiry just before the poller's expired
// result can acquire the same state lock. This is the ordering behind the
// full-package TestCodexDeviceLoginExpires failure, without a sleep race.
func TestA232ExpiryRaceLeavesLegacyWaiting(t *testing.T) {
	store := a234IsolateStore(t)
	h := newCodexDeviceHarness(t, 0)
	gate := a232NewGate()
	defer gate.open()
	pr9UseClient(&http.Client{Transport: pr9Transport(func(r *http.Request) (*http.Response, error) {
		if r.URL.String() == fakeOpenAIPollURL {
			gate.hold()
			return pr9Response(r, http.StatusBadRequest, `{"error":"expired_token"}`)
		}
		return h.fake.RoundTrip(r)
	})}, 0)
	state := h.start()["state"].(string)
	pr9Wait(t, gate.reached)
	store.mu.Lock()
	locked := true
	defer func() {
		if locked {
			store.mu.Unlock()
		}
	}()
	gate.open()
	deadline := time.Now().Add(5 * time.Second)
	for {
		stack := make([]byte, 1<<20)
		n := runtime.Stack(stack, true)
		if strings.Contains(string(stack[:n]), "(*codexDeviceLoginStore).transition(") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("poller did not reach its terminal transition")
		}
		runtime.Gosched()
	}
	record := store.records[state]
	expires := record.expiresAt
	store.now = func() time.Time { return expires }
	store.expireLocked(record)
	store.mu.Unlock()
	locked = false
	h.waitWatcher(state)
	_, current, _ := h.status(state)
	_, legacy, _ := h.do(http.MethodGet, "/v0/management/get-auth-status?state="+state, true)
	t.Logf("after poller joined: device-status=%v legacy-status=%v", current["status"], legacy["status"])
	if current["status"] != "expired" || legacy["status"] != "error" {
		t.Error("the legacy status retains wait after the device login expired and its poller exited")
	}
}
