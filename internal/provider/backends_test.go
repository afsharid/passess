package provider

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"slices"
	"strings"
	"testing"

	"github.com/afsharid/passess/internal/secret"
)

func withLookPath(t *testing.T, found ...string) {
	t.Helper()
	old := lookPath
	lookPath = func(name string) (string, error) {
		if slices.Contains(found, name) {
			return "/usr/local/bin/" + name, nil
		}
		return "", exec.ErrNotFound
	}
	t.Cleanup(func() { lookPath = old })
}

const opValue = "passess-fake-op-0123456789abcdef"

func TestOnePassword(t *testing.T) {
	withLookPath(t, "op")
	env := map[string]string{"PATH": "/usr/bin", "HOME": "/Users/x", "OP_SERVICE_ACCOUNT_TOKEN": "passess-fake-sa-0123456789", "OTHER_TOKEN": "nope"}
	run := &fakeRunner{reply: func(c Cmd) (Result, error) {
		ref := c.Args[len(c.Args)-1]
		switch {
		case ref == "op://Dev/GitHub PAT/credential":
			return Result{Stdout: []byte(opValue)}, nil
		case strings.Contains(ref, "Locked"):
			return Result{Exit: 1, Stderr: []byte("[ERROR] 2026/09/26 authorization prompt dismissed, please try again")}, nil
		}
		return Result{Exit: 1, Stderr: []byte(`[ERROR] 2026/09/26 "Nope" isn't an item in the "Dev" vault. Specify the item with its UUID, name, or domain.`)}, nil
	}}
	p := OnePassword{Runner: run, Getenv: func(k string) string { return env[k] }, Account: "my.1password.com"}
	contract(t, p, mustRef(t, "op://Dev/GitHub PAT/credential"), opValue, mustRef(t, "op://Dev/Nope/credential"))
	c := run.calls[0]
	if !slices.Equal(c.Args, []string{"read", "--no-newline", "--account", "my.1password.com", "op://Dev/GitHub PAT/credential"}) {
		t.Fatalf("args = %q", c.Args)
	}
	if !slices.Contains(c.Env, "OP_SERVICE_ACCOUNT_TOKEN=passess-fake-sa-0123456789") || slices.Contains(c.Env, "OTHER_TOKEN=nope") {
		t.Fatalf("env = %q", c.Env)
	}
	if _, err := p.Resolve(context.Background(), mustRef(t, "op://Dev/Locked/credential")); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("locked: %v", err)
	}
	withLookPath(t)
	if err := p.Available(context.Background()); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("missing CLI: %v", err)
	}
}

const vaultToken = "passess-fake-vault-token-0123456789"

func fakeVault(t *testing.T) *httptest.Server {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Vault-Token") != vaultToken {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"errors":["permission denied"]}`))
			return
		}
		switch r.URL.Path {
		case "/v1/secret/data/myapp/dev": // KV v2
			if r.Header.Get("X-Vault-Namespace") != "team" {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			_, _ = w.Write([]byte(`{"data":{"data":{"database_url":"postgres://passess-fake-v2@db/app"},"metadata":{"version":3}}}`))
		case "/v1/kv/app": // KV v1
			_, _ = w.Write([]byte(`{"data":{"token":"passess-fake-v1-0123456789"}}`))
		default:
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"errors":[]}`))
		}
	}))
	t.Cleanup(ts.Close)
	return ts
}

func TestVault(t *testing.T) {
	ts := fakeVault(t)
	token := func(context.Context) (secret.Value, error) { return secret.FromString(vaultToken), nil }
	v2 := &Vault{Address: ts.URL, Namespace: "team", Token: token}
	contract(t, v2, mustRef(t, "vault://secret/myapp/dev#database_url"), "postgres://passess-fake-v2@db/app", mustRef(t, "vault://secret/myapp/dev#missing_key"))
	v1 := &Vault{Address: ts.URL, Token: token}
	contract(t, v1, mustRef(t, "vault://kv/app#token"), "passess-fake-v1-0123456789", mustRef(t, "vault://kv/nothing#token"))

	bad := &Vault{Address: ts.URL, Token: func(context.Context) (secret.Value, error) { return secret.FromString("wrong"), nil }}
	_, err := bad.Resolve(context.Background(), mustRef(t, "vault://kv/app#token"))
	if !errors.Is(err, ErrUnavailable) || strings.Contains(err.Error(), "wrong") {
		t.Fatalf("denied: %v", err)
	}
	if err := (&Vault{Getenv: func(string) string { return "" }}).Available(context.Background()); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("no address: %v", err)
	}
}

func TestVaultTokenSources(t *testing.T) {
	ts := fakeVault(t)
	home := t.TempDir()
	if err := os.WriteFile(home+"/.vault-token", []byte(vaultToken+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	orig := accountHome
	accountHome = func() string { return home }
	t.Cleanup(func() { accountHome = orig })
	// The caller's $HOME points elsewhere; the account's file is the one read.
	env := map[string]string{"HOME": t.TempDir(), "VAULT_ADDR": ts.URL}
	v := &Vault{Getenv: func(k string) string { return env[k] }}
	if _, err := v.Resolve(context.Background(), mustRef(t, "vault://kv/app#token")); err != nil {
		t.Fatalf("~/.vault-token: %v", err)
	}
	env["VAULT_TOKEN"] = vaultToken
	env["HOME"] = t.TempDir()
	v = &Vault{Getenv: func(k string) string { return env[k] }}
	if _, err := v.Resolve(context.Background(), mustRef(t, "vault://kv/app#token")); err != nil {
		t.Fatalf("VAULT_TOKEN: %v", err)
	}
}

// TestVaultLive runs against a real Vault or OpenBao dev server:
//
//	docker run -d --rm --name passess-openbao -p 127.0.0.1:18200:8200 \
//	  -e BAO_DEV_ROOT_TOKEN_ID=passess-fake-root quay.io/openbao/openbao server -dev -dev-listen-address=0.0.0.0:8200
//	PASSESS_LIVE_VAULT_ADDR=http://127.0.0.1:18200 PASSESS_LIVE_VAULT_TOKEN=passess-fake-root go test ./internal/provider -run TestVaultLive
func TestVaultLive(t *testing.T) {
	addr, tok := os.Getenv("PASSESS_LIVE_VAULT_ADDR"), os.Getenv("PASSESS_LIVE_VAULT_TOKEN")
	if addr == "" || tok == "" {
		t.Skip("set PASSESS_LIVE_VAULT_ADDR and PASSESS_LIVE_VAULT_TOKEN to run against a dev server")
	}
	call := func(method, path, body string) {
		t.Helper()
		req, _ := http.NewRequest(method, addr+path, strings.NewReader(body))
		req.Header.Set("X-Vault-Token", tok)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode >= 300 {
			t.Fatalf("%s %s: %d", method, path, resp.StatusCode)
		}
	}
	call("POST", "/v1/secret/data/passess-live", `{"data":{"canary":"passess-fake-live-v2-0123456789"}}`)
	call("POST", "/v1/sys/mounts/passess-kv1", `{"type":"kv","options":{"version":"1"}}`)
	t.Cleanup(func() { call("DELETE", "/v1/sys/mounts/passess-kv1", "") })
	call("POST", "/v1/passess-kv1/app", `{"canary":"passess-fake-live-v1-0123456789"}`)

	v := &Vault{Address: addr, Token: func(context.Context) (secret.Value, error) { return secret.FromString(tok), nil }}
	contract(t, v, mustRef(t, "vault://secret/passess-live#canary"), "passess-fake-live-v2-0123456789", mustRef(t, "vault://secret/passess-live#nope"))
	contract(t, v, mustRef(t, "vault://passess-kv1/app#canary"), "passess-fake-live-v1-0123456789", mustRef(t, "vault://passess-kv1/absent#canary"))
}

const bwValue = "passess-fake-bw-0123456789abcdef"

func TestBitwarden(t *testing.T) {
	withLookPath(t, "bw")
	session := "passess-fake-session-0123456789"
	run := &fakeRunner{reply: func(c Cmd) (Result, error) {
		if !slices.Contains(c.Env, "BW_SESSION="+session) || slices.Contains(c.Args, session) {
			t.Fatal("the session must travel in the environment only")
		}
		switch strings.Join(c.Args, " ") {
		case "get password GitHub":
			return Result{Stdout: []byte(bwValue + "\n")}, nil
		case "get item Stripe":
			return Result{Stdout: []byte(`{"name":"Stripe","fields":[{"name":"api_key","value":"passess-fake-stripe-0123456789"}]}`)}, nil
		case "get item Multi":
			return Result{Stdout: []byte(`{"name":"Multi","fields":[{"name":"other","value":"passess-fake-other-0123456789"},{"name":"flag","value":null},{"name":"api_key","value":"passess-fake-multi-0123456789"}]}`)}, nil
		case "get password Twins":
			return Result{Exit: 1, Stderr: []byte("More than one result was found.")}, nil
		case "get password Locked":
			return Result{Exit: 1, Stderr: []byte("Vault is locked.")}, nil
		}
		return Result{Exit: 1, Stderr: []byte("Not found.")}, nil
	}}
	p := Bitwarden{Runner: run, Getenv: func(k string) string { return map[string]string{"PATH": "/usr/bin"}[k] },
		Session: func(context.Context) (secret.Value, error) { return secret.FromString(session), nil }}
	contract(t, p, mustRef(t, "bw://GitHub/password"), bwValue, mustRef(t, "bw://Nope/password"))
	v, err := p.Resolve(context.Background(), mustRef(t, "bw://Stripe/api_key"))
	if err != nil || string(v.Bytes()) != "passess-fake-stripe-0123456789" {
		t.Fatalf("custom field: %v", err)
	}
	// Among other fields, a null one included, only the one asked for.
	v, err = p.Resolve(context.Background(), mustRef(t, "bw://Multi/api_key"))
	if err != nil || string(v.Bytes()) != "passess-fake-multi-0123456789" {
		t.Fatalf("custom field among others: %v", err)
	}
	if _, err := p.Resolve(context.Background(), mustRef(t, "bw://Multi/flag")); err == nil {
		t.Fatal("a null field resolved")
	}
	if _, err := p.Resolve(context.Background(), mustRef(t, "bw://Twins/password")); err == nil || !strings.Contains(err.Error(), "item id") {
		t.Fatalf("ambiguous: %v", err)
	}
	if _, err := p.Resolve(context.Background(), mustRef(t, "bw://Locked/password")); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("locked: %v", err)
	}
	locked := Bitwarden{Runner: run, Getenv: func(string) string { return "" }}
	if err := locked.Available(context.Background()); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("no session: %v", err)
	}
}

// A token passess holds itself goes only to the address in its own config;
// the caller's VAULT_ADDR cannot aim it elsewhere. Every address must be
// https, or plain http to this machine.
func TestVaultAddressRules(t *testing.T) {
	token := func(context.Context) (secret.Value, error) { return secret.FromString(vaultToken), nil }
	ctx := context.Background()
	env := func(addr string) func(string) string {
		return func(k string) string {
			if k == "VAULT_ADDR" {
				return addr
			}
			return ""
		}
	}
	if err := (&Vault{Token: token, Getenv: env("https://vault.example")}).Available(ctx); !errors.Is(err, ErrUnavailable) ||
		!strings.Contains(err.Error(), "backends.vault.address") {
		t.Fatalf("config token sent to VAULT_ADDR: %v", err)
	}
	for addr, ok := range map[string]bool{
		"https://vault.example": true,
		"http://127.0.0.1:8200": true,
		"http://localhost:8200": true,
		"http://vault.example":  false,
		"ftp://vault.example":   false,
		"vault.example":         false,
	} {
		_, err := (&Vault{Address: addr, Token: token}).address()
		if (err == nil) != ok {
			t.Errorf("address %q: err=%v, want ok=%v", addr, err, ok)
		}
	}
}

// A redirect to another server is refused: Go would carry X-Vault-Token along.
func TestVaultRefusesCrossHostRedirect(t *testing.T) {
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Vault-Token") != "" {
			t.Error("the token reached the redirect target")
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(other.Close)
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	t.Cleanup(origin.Close)
	token := func(context.Context) (secret.Value, error) { return secret.FromString(vaultToken), nil }
	_, err := (&Vault{Address: origin.URL, Token: token}).Resolve(context.Background(), mustRef(t, "vault://kv/app#token"))
	if err == nil || !strings.Contains(err.Error(), "another server") {
		t.Fatalf("Resolve = %v, want the redirect refused", err)
	}
}
