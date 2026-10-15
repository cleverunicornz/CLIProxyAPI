package handlers

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync/atomic"

	"github.com/gin-gonic/gin"
	"github.com/klauspost/compress/zstd"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
)

// MaxRequestBodyBytesContextKey stores the configured request body size limit (in bytes) on the Gin context.
const MaxRequestBodyBytesContextKey = "maxRequestBodyBytes"

// maxRequestBodyBytes bounds a request body as received and after each decoding stage; 0 means unbounded. It is
// the configured value (config.SDKConfig.EffectiveMaxRequestBodyBytes), set whenever the handlers' configuration
// is. The server's maxRequestBodyBytesMiddleware sets the same bound on the request's context and wraps the body,
// so a Content-Length over it is refused before anything is read.
var maxRequestBodyBytes atomic.Int64

func init() {
	maxRequestBodyBytes.Store(int64(config.DefaultMaxRequestBodyMB) << 20)
}

// SetMaxRequestBodyBytes sets the request body bound from cfg. It is the fork's bound (requests.max-body-mb,
// default 64 MiB) when that key is set, otherwise upstream's (server.max-request-body-bytes), otherwise the
// fork's default.
func SetMaxRequestBodyBytes(cfg *config.SDKConfig) {
	maxRequestBodyBytes.Store(cfg.EffectiveMaxRequestBodyBytes())
}

// RequestBodyTooLargeError reports a request body over the bound, as received or after a decoding stage.
type RequestBodyTooLargeError struct {
	Limit int64
	Stage string
}

func (e *RequestBodyTooLargeError) Error() string {
	return fmt.Sprintf("request body exceeds the %d-byte limit (%s)", e.Limit, e.Stage)
}

// StatusCode makes the error carry upstream's 413 status, so clienterror.HTTPStatusFromErrorOr and the fork's
// RequestBodyReadErrorStatus answer the same status for a body over the bound.
func (e *RequestBodyTooLargeError) StatusCode() int {
	return http.StatusRequestEntityTooLarge
}

// IsRequestBodyTooLarge reports whether err is a body over the bound, as the fork's RequestBodyTooLargeError or
// as the http.MaxBytesError the server's bounding middleware wraps the body with.
func IsRequestBodyTooLarge(err error) bool {
	var tooLarge *RequestBodyTooLargeError
	if errors.As(err, &tooLarge) {
		return true
	}
	var maxBytesErr *http.MaxBytesError
	return errors.As(err, &maxBytesErr)
}

// RequestBodyReadErrorStatus is the HTTP status for a ReadRequestBody error: 413 for a body over the bound, else 400.
func RequestBodyReadErrorStatus(err error) int {
	if IsRequestBodyTooLarge(err) {
		return http.StatusRequestEntityTooLarge
	}
	return http.StatusBadRequest
}

// readBounded reads r to its end, stopping with a RequestBodyTooLargeError as soon as it passes limit bytes, so
// nothing past the bound is held.
func readBounded(r io.Reader, limit int64, stage string) ([]byte, error) {
	if limit <= 0 {
		return io.ReadAll(r)
	}
	data, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, &RequestBodyTooLargeError{Limit: limit, Stage: stage}
	}
	return data, nil
}

// requestBodyLimit is the bound that applies to this request: the server's per-request value when it set one,
// else the handlers' configured bound.
func requestBodyLimit(c *gin.Context) int64 {
	if c != nil {
		if limit := c.GetInt64(MaxRequestBodyBytesContextKey); limit > 0 {
			return limit
		}
	}
	return maxRequestBodyBytes.Load()
}

// ReadRequestBody reads the incoming request body and decodes supported
// Content-Encoding values before handlers inspect JSON fields. The body as
// received and the output of every decoding stage are bounded while they are
// read; a body over the bound is a RequestBodyTooLargeError (413).
func ReadRequestBody(c *gin.Context) ([]byte, error) {
	limit := requestBodyLimit(c)
	var raw []byte
	var err error
	if c != nil && c.Request != nil && c.Request.Body != nil {
		raw, err = readBounded(c.Request.Body, limit, "as received")
	}
	if err != nil {
		return nil, err
	}

	encoding := ""
	if c != nil && c.Request != nil {
		encoding = strings.TrimSpace(c.Request.Header.Get("Content-Encoding"))
	}
	if encoding == "" || strings.EqualFold(encoding, "identity") {
		return raw, nil
	}

	decoded, err := decodeRequestBody(raw, encoding, limit)
	if err != nil {
		if !IsRequestBodyTooLarge(err) && json.Valid(raw) {
			return raw, nil
		}
		return nil, err
	}
	return decoded, nil
}

func decodeRequestBody(raw []byte, encoding string, limit int64) ([]byte, error) {
	parts := strings.Split(encoding, ",")
	body := raw
	for i := len(parts) - 1; i >= 0; i-- {
		enc := strings.ToLower(strings.TrimSpace(parts[i]))
		switch enc {
		case "", "identity":
			continue
		case "zstd":
			decoded, err := decodeZstdRequestBody(body, limit)
			if err != nil {
				return nil, err
			}
			body = decoded
		default:
			return nil, fmt.Errorf("unsupported request content encoding: %s", enc)
		}
	}
	return body, nil
}

func decodeZstdRequestBody(raw []byte, limit int64) ([]byte, error) {
	options := []zstd.DOption{zstd.WithDecoderConcurrency(1)}
	if limit > 0 {
		options = append(options, zstd.WithDecoderMaxMemory(uint64(limit)+1))
	}
	decoder, err := zstd.NewReader(bytes.NewReader(raw), options...)
	if err != nil {
		return nil, fmt.Errorf("failed to create zstd request decoder: %w", err)
	}
	defer decoder.Close()

	decoded, err := readBounded(decoder, limit, "after zstd decoding")
	if err != nil {
		if IsRequestBodyTooLarge(err) {
			return nil, err
		}
		if errors.Is(err, zstd.ErrDecoderSizeExceeded) || errors.Is(err, zstd.ErrWindowSizeExceeded) {
			return nil, &RequestBodyTooLargeError{Limit: limit, Stage: "after zstd decoding"}
		}
		return nil, fmt.Errorf("failed to decode zstd request body: %w", err)
	}
	return decoded, nil
}
