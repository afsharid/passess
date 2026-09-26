package ref

import (
	"errors"
	"strings"
	"testing"
)

func TestParseValid(t *testing.T) {
	tests := []struct {
		in     string
		scheme string
		path   []string
		key    string
	}{
		{"op://Dev/GitHub PAT/credential", OnePassword, []string{"Dev", "GitHub PAT", "credential"}, ""},
		{"op://Dev/Stripe/live/secret key", OnePassword, []string{"Dev", "Stripe", "live", "secret key"}, ""},
		{"bws://3f2a1b4c-5d6e-4f70-8a9b-0c1d2e3f4a5b", BWS, []string{"3f2a1b4c-5d6e-4f70-8a9b-0c1d2e3f4a5b"}, ""},
		{"bws://dev-project/NVIDIA_API_KEY", BWS, []string{"dev-project", "NVIDIA_API_KEY"}, ""},
		{"bw://GitHub/password", Bitwarden, []string{"GitHub", "password"}, ""},
		{"vault://secret/myapp/dev#database_url", Vault, []string{"secret", "myapp", "dev"}, "database_url"},
		{"vault://kv/app#token", Vault, []string{"kv", "app"}, "token"},
		{"keychain://passess/bws", Keychain, []string{"passess", "bws"}, ""},
		{"env://OPENAI_API_KEY", Env, []string{"OPENAI_API_KEY"}, ""},
	}
	for _, tt := range tests {
		r, err := Parse(tt.in)
		if err != nil {
			t.Fatalf("Parse(%q): %v", tt.in, err)
		}
		if r.Scheme != tt.scheme || strings.Join(r.Path, "|") != strings.Join(tt.path, "|") || r.Key != tt.key {
			t.Fatalf("Parse(%q) = %+v", tt.in, r)
		}
		if r.String() != tt.in {
			t.Fatalf("String() = %q, want %q", r.String(), tt.in)
		}
	}
}

func TestParseInvalid(t *testing.T) {
	for _, in := range []string{
		"",
		"gh" + "p_notARealTokenButShapedLikeOne1234567890", // split so secret scanners skip the source
		"https://user:hunter2@example.com/path",
		"op://Dev/item",
		"op://Dev/item/a/b/c",
		"op://Dev//field",
		"bws://not-a-uuid",
		"bws://project/lower-case-key",
		"bws://a/b/c",
		"bw://only-item",
		"vault://secret/app",
		"vault://secret#key",
		"vault://secret/app#",
		"keychain://service",
		"env://1BAD",
		"env://A/B",
		"env://OK\n",
	} {
		_, err := Parse(in)
		if err == nil {
			t.Fatalf("Parse(%q) succeeded, want error", in)
		}
		if !errors.Is(err, ErrInvalid) {
			t.Fatalf("Parse(%q) error does not wrap ErrInvalid: %v", in, err)
		}
		if in != "" && strings.Contains(err.Error(), in) {
			t.Fatalf("error for %q echoes the input: %v", in, err)
		}
		for _, frag := range []string{"hunter2", "notARealToken", "only-item", "not-a-uuid"} {
			if strings.Contains(in, frag) && strings.Contains(err.Error(), frag) {
				t.Fatalf("error for %q echoes %q: %v", in, frag, err)
			}
		}
	}
}

func FuzzParse(f *testing.F) {
	for _, s := range []string{
		"op://a/b/c", "bws://p/K", "bw://i/f", "vault://m/p#k", "keychain://s/a", "env://X",
		"vault://m/p#k#k", "op://a/b/c/d", "://", "op://", "#", "bws://00000000-0000-0000-0000-000000000000",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		r, err := Parse(s)
		if err != nil {
			return
		}
		again, err := Parse(r.String())
		if err != nil {
			t.Fatalf("canonical form %q of %q does not parse: %v", r.String(), s, err)
		}
		if !again.Equal(r) {
			t.Fatalf("round trip changed %q: %+v != %+v", s, again, r)
		}
	})
}
