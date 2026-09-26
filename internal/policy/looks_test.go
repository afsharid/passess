package policy

import (
	"math"
	"strings"
	"testing"
)

func TestEntropy(t *testing.T) {
	for s, want := range map[string]float64{"": 0, "aaaa": 0, "ab": 1, "abcd": 2} {
		if got := Entropy(s); math.Abs(got-want) > 1e-9 {
			t.Errorf("Entropy(%q) = %v, want %v", s, got, want)
		}
	}
}

func TestLooksLikeSecret(t *testing.T) {
	// Token-shaped strings are built at run time so scanners skip this file.
	pat := "gh" + "p_" + strings.Repeat("A1b2C3d4E5", 3) + "f6G7h8"
	random := "Zq8Xw2Lm9Pv4Rt7YkB3nC6sD1fG5hJ0a"
	for v, want := range map[string]bool{
		pat:                                     true,
		"Bearer " + pat:                         true,
		"token " + random:                       true,
		random:                                  true,
		"postgres://app:passess-fake-pw@db/x":   true,
		"https://user:passess-fake-pw@h/x":      true,
		"postgres://app@db/x":                   false, // no password
		"https://mcp.example.com/mcp":           false,
		"${API_KEY}":                            false,
		"Bearer {{API_TOKEN}}":                  false,
		"$HOME/.config/some/long/path/file":     false,
		"/usr/local/bin/some-long-program-name": false,
		"debug":                                 false,
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa":        false, // long but not random
		"The quick brown fox jumps over it":     false,
		"sk-short":                              false, // a prefix, but too short
		"postgres://app:${DB_PASSWORD}@db/x":    false, // a reference, not a value
		"Bearer $API_TOKEN":                     false,
	} {
		if got := LooksLikeSecret(v); got != want {
			t.Errorf("LooksLikeSecret(%q) = %v, want %v", v, got, want)
		}
	}
}

func TestIsReference(t *testing.T) {
	for v, want := range map[string]bool{
		"${API_KEY}": true, "$API_KEY": true, "Bearer $TOKEN": true, "{{TOKEN}}": true,
		"{env:API_KEY}": true, "{file:~/.secrets/key}": true, "${env:API_KEY}": true,
		"p4ss$word": false, "$2a$10$abc": false, "plain": false, "": false,
	} {
		if got := IsReference(v); got != want {
			t.Errorf("IsReference(%q) = %v, want %v", v, got, want)
		}
	}
}

func TestSecretHeader(t *testing.T) {
	for _, c := range []struct {
		name, value string
		want        bool
	}{
		{"Authorization", "anything", true},
		{"cookie", "a=b", true},
		{"X-Api-Key", "short", true},
		{"X-Auth-Token", "short", true},
		{"X-Client", "passess-test", false},
		{"X-Custom", "Zq8Xw2Lm9Pv4Rt7YkB3nC6sD1fG5hJ0a", true},
		{"Accept", "application/json", false},
	} {
		if got := SecretHeader(c.name, c.value); got != c.want {
			t.Errorf("SecretHeader(%q, %q) = %v, want %v", c.name, c.value, got, c.want)
		}
	}
}

func TestLooksLikeSecretNamed(t *testing.T) {
	digests := "3f2a" + strings.Repeat("9c1e7b5d", 7) + "a1," + "7d04" + strings.Repeat("e6b2c8f0", 7) + "c3"
	pat := "gh" + "p_" + strings.Repeat("A1b2C3d4E5", 3) + "f6G7h8"
	random := "Zq8Xw2Lm9P" + "v4Rt7YkB3nC6sD1fG5hJ0a" // built at run time, like every token-shaped test value
	for _, c := range []struct {
		name, value string
		want        bool
	}{
		{"NODE_REPL_TRUSTED_BROWSER_CLIENT_SHA256S", digests, false}, // a list of digests
		{"GOOGLE_CLOUD_PROJECT", "gen-lang-client-0816463281", false},
		{"TESLA_OAUTH_CLIENT_ID", random, false},
		{"AWS_REGION", "eu-central-1", false},
		{"GITHUB_ID", pat, true}, // a token prefix still counts
		{"DB_PROJECT", "postgres://u:passess-fake-pw@db/x", true},
		{"API_KEY", random, true},
		{"CLIENT_SECRET", random, true},
	} {
		if got := LooksLikeSecretNamed(c.name, c.value); got != c.want {
			t.Errorf("LooksLikeSecretNamed(%s) = %v, want %v", c.name, got, c.want)
		}
	}
}
