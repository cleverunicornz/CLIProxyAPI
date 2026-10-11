package sessionmember

import (
	"encoding/base64"
	"strings"
	"testing"

	internalconfig "github.com/router-for-me/CLIProxyAPI/v8/internal/config"
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
