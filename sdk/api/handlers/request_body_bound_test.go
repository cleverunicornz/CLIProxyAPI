package handlers

import (
	"bytes"
	"io"
	"net/http/httptest"
	"runtime"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/klauspost/compress/zstd"
)

// R3-1 (the fallback validator's round 3 on #10 at 4ad6f587, validator-evidence/cliproxy-pr10-r3/probes/
// r3_decoder_test.go): the shared request body decoder bounds what it reads and what each decoding stage produces,
// while streaming, so a small compressed body cannot expand into memory without limit.

func zstdCompress(t *testing.T, clear io.Reader) []byte {
	t.Helper()
	var b bytes.Buffer
	w, err := zstd.NewWriter(&b, zstd.WithEncoderConcurrency(1))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = io.Copy(w, clear); err != nil {
		t.Fatal(err)
	}
	if err = w.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func paddedMember(mib int) io.Reader {
	return io.MultiReader(io.LimitReader(repeatByte(' '), int64(mib)<<20), bytes.NewReader([]byte(`{"model":"gpt-6-astra","input":"hi"}`)))
}

type repeatByte byte

func (r repeatByte) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = byte(r)
	}
	return len(p), nil
}

func readWithEncoding(t *testing.T, body []byte, encoding string) ([]byte, error) {
	t.Helper()
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest("POST", "/v1/responses", bytes.NewReader(body))
	if encoding != "" {
		c.Request.Header.Set("Content-Encoding", encoding)
	}
	return ReadRequestBody(c)
}

func TestR3DecoderTotalOutputBound(t *testing.T) {
	for _, mib := range []int{1, 16, 64} {
		encoded := zstdCompress(t, paddedMember(mib))
		runtime.GC()
		var a, d runtime.MemStats
		runtime.ReadMemStats(&a)
		raw, err := readWithEncoding(t, encoded, "zstd")
		runtime.ReadMemStats(&d)
		t.Logf("decompressed_MiB=%d encoded_bytes=%d decoded_bytes=%d allocated_bytes=%d error=%v", mib, len(encoded), len(raw), d.TotalAlloc-a.TotalAlloc, err)
		if mib == 64 && err == nil {
			t.Error("64 MiB expanded into memory with no total-output limit")
		}
		if mib < 64 && err != nil {
			t.Errorf("%d MiB refused: %v", mib, err)
		}
	}
}

func TestRequestBodyBoundAppliesToEveryDecodingStage(t *testing.T) {
	// The outer zstd stage decodes to a small body; the inner one would expand past the bound.
	inner := zstdCompress(t, paddedMember(64))
	stacked := zstdCompress(t, bytes.NewReader(inner))
	if _, err := readWithEncoding(t, stacked, "zstd, zstd"); err == nil {
		t.Fatal("the inner stage expanded past the bound")
	}
	if _, err := readWithEncoding(t, zstdCompress(t, bytes.NewReader(zstdCompress(t, paddedMember(1)))), "zstd, zstd"); err != nil {
		t.Fatalf("a stacked body under the bound was refused: %v", err)
	}
}

func TestRequestBodyBoundAppliesToTheEncodedBody(t *testing.T) {
	plain, err := io.ReadAll(paddedMember(64))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = readWithEncoding(t, plain, ""); err == nil {
		t.Fatal("a 64 MiB request body was read whole")
	}
}
