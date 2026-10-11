package api

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"runtime"
	"testing"

	"github.com/klauspost/compress/zstd"
)

// Round-3 regression tests for the request body bound (R3-1 of the fallback validator's round 3 on #10 at 4ad6f587,
// validator-evidence/cliproxy-pr10-r3/probes/r3_edges_test.go TestR3DecompressedBodyBound): a small compressed body
// that decodes to a huge one is refused with 413 before it is materialized or executed, with the gate on or off, and
// the bound is configurable. All identities, credentials and bodies are fake.

// zstdOfPaddedBody compresses mib MiB of JSON whitespace followed by a member request, streaming the padding so the
// clear body is never held in memory.
func zstdOfPaddedBody(t *testing.T, mib int) []byte {
	t.Helper()
	var compressed bytes.Buffer
	w, err := zstd.NewWriter(&compressed, zstd.WithEncoderConcurrency(1))
	if err != nil {
		t.Fatal(err)
	}
	chunk := bytes.Repeat([]byte(" "), 1<<20)
	for i := 0; i < mib; i++ {
		if _, err = w.Write(chunk); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = w.Write([]byte(`{"model":"gpt-6-astra","input":"hi"}`)); err != nil {
		t.Fatal(err)
	}
	if err = w.Close(); err != nil {
		t.Fatal(err)
	}
	return compressed.Bytes()
}

func postEncoded(t *testing.T, h *memberGateHarness, path, token, encoding string, raw []byte) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if encoding != "" {
		req.Header.Set("Content-Encoding", encoding)
	}
	rec := httptest.NewRecorder()
	h.server.engine.ServeHTTP(rec, req)
	return rec
}

func TestSessionMemberGateR3DecompressedBodyBound(t *testing.T) {
	h := newMemberGateHarness(t, true)
	for _, tc := range []struct {
		mib        int
		wantStatus int
		wantRuns   int
	}{{1, http.StatusOK, 1}, {16, http.StatusOK, 1}, {64, http.StatusRequestEntityTooLarge, 0}} {
		compressed := zstdOfPaddedBody(t, tc.mib)
		runtime.GC()
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		runs := len(h.codex.calls())
		rec := postEncoded(t, h, "/v1/responses", codexSessionToken, "zstd", compressed)
		runtime.ReadMemStats(&after)
		t.Logf("decompressed_MiB=%d compressed_bytes=%d status=%d executions=%d allocated_bytes=%d",
			tc.mib, len(compressed), rec.Code, len(h.codex.calls())-runs, after.TotalAlloc-before.TotalAlloc)
		if rec.Code != tc.wantStatus || len(h.codex.calls())-runs != tc.wantRuns {
			t.Fatalf("%d MiB decoded: status = %d with %d executions, want %d with %d; body %s",
				tc.mib, rec.Code, len(h.codex.calls())-runs, tc.wantStatus, tc.wantRuns, rec.Body.String())
		}
	}
}

func TestSessionMemberGateR3PlainBodyBound(t *testing.T) {
	h := newMemberGateHarness(t, true)
	body := append(bytes.Repeat([]byte(" "), 64<<20), []byte(`{"model":"gpt-6-astra","input":"hi"}`)...)
	rec := postEncoded(t, h, "/v1/responses", codexSessionToken, "", body)
	if rec.Code != http.StatusRequestEntityTooLarge || len(h.codex.calls()) != 0 {
		t.Fatalf("a 64 MiB plain body: status = %d with %d executions, want 413 with none", rec.Code, len(h.codex.calls()))
	}
}

func TestRequestBodyBoundAppliesWithTheGateOff(t *testing.T) {
	h := newMemberGateHarness(t, false)
	rec := postEncoded(t, h, "/v1/responses", memberGatePlainKey, "zstd", zstdOfPaddedBody(t, 64))
	if rec.Code != http.StatusRequestEntityTooLarge || len(h.codex.calls()) != 0 {
		t.Fatalf("gate off, 64 MiB decoded: status = %d with %d executions, want 413 with none", rec.Code, len(h.codex.calls()))
	}
}

func TestSessionMemberGateR3RequestBodyBoundIsConfigurable(t *testing.T) {
	h := newMemberGateHarnessWithConfig(t, true, "requests:\n  max-body-mb: 1\n")
	small := zstdOfPaddedBody(t, 0)
	if rec := postEncoded(t, h, "/v1/responses", codexSessionToken, "zstd", small); rec.Code != http.StatusOK {
		t.Fatalf("a small body under a 1 MiB bound: status = %d; body %s", rec.Code, rec.Body.String())
	}
	rec := postEncoded(t, h, "/v1/responses", codexSessionToken, "zstd", zstdOfPaddedBody(t, 2))
	if rec.Code != http.StatusRequestEntityTooLarge || len(h.codex.calls()) != 1 {
		t.Fatalf("2 MiB decoded under a 1 MiB bound: status = %d with %d executions, want 413 and only the first",
			rec.Code, len(h.codex.calls()))
	}
}
