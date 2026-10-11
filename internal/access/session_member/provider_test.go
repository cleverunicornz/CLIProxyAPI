package sessionmember

import (
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	internalconfig "github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	sdkaccess "github.com/router-for-me/CLIProxyAPI/v8/sdk/access"
)

func TestLooksLikeJWT(t *testing.T) {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256"}`))
	for token, want := range map[string]bool{
		header + ".cGF5bG9hZA.c2ln":   true,
		"plain-user-key":              false,
		header + ".cGF5bG9hZA":        false,
		header + "..c2ln":             false,
		"bm90LWpzb24.cGF5bG9hZA.c2ln": false,
		base64.RawURLEncoding.EncodeToString([]byte(`{"typ":"JWT"}`)) + ".cGF5bG9hZA.c2ln": false,
	} {
		if got := looksLikeJWT(token); got != want {
			t.Errorf("looksLikeJWT(%q) = %v, want %v", token, got, want)
		}
	}
}

func TestReviewCacheExpiresAfterItsLifetime(t *testing.T) {
	p := newProvider(internalconfig.SessionMemberGateConfig{Enabled: true})
	now := time.Unix(1_800_000_000, 0)
	p.nowFunc = func() time.Time { return now }
	key := sha256.Sum256([]byte("token"))
	p.store(key, &sdkaccess.Result{Provider: ProviderType, Principal: "ns/pod"})

	now = now.Add(reviewCacheTTL - time.Second)
	if _, ok := p.cached(key); !ok {
		t.Fatal("a review inside its lifetime is not reused")
	}
	now = now.Add(time.Second)
	if _, ok := p.cached(key); ok {
		t.Fatal("a review past its lifetime is still reused")
	}
	p.store(sha256.Sum256([]byte("other")), &sdkaccess.Result{})
	if _, ok := p.cache[key]; ok {
		t.Fatal("an expired review is kept after the next store")
	}
}

func TestMisconfiguredGateNamesTheMissingFields(t *testing.T) {
	t.Setenv("KUBERNETES_SERVICE_HOST", "")
	p := newProvider(internalconfig.SessionMemberGateConfig{Enabled: true})
	err := p.configError()
	if err == nil {
		t.Fatal("a gate without audience, namespace, ServiceAccount or API server is accepted")
	}
	for _, field := range []string{"audience", "namespace", "service-account", "api-server"} {
		if !strings.Contains(err.Error(), field) {
			t.Errorf("error %q does not name %s", err, field)
		}
	}
}
