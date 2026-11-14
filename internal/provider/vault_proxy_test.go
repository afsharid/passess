package provider

import (
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The Vault token and the value Vault returns cross this client, so it must
// not take a proxy from the caller's environment, with or without ca_cert.
func TestVaultClientIgnoresTheCallersProxy(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:9")
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:9")
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	t.Cleanup(ts.Close)
	ca := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ts.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, v := range map[string]*Vault{
		"system roots": {},
		"own ca_cert":  {CACert: ca},
	} {
		t.Run(name, func(t *testing.T) {
			client, err := v.client()
			if err != nil {
				t.Fatal(err)
			}
			tr := client.Transport.(*http.Transport)
			if tr.Proxy != nil {
				t.Fatal("the vault client's transport reads a proxy from the environment")
			}
		})
	}
}

// A relative ca_cert would be read from the working directory of whoever
// resolves, so a repository could choose the CA roots the vault token is
// checked against. It is refused, whether or not such a file exists there.
func TestVaultClientRefusesARelativeCACert(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	if err := os.WriteFile(filepath.Join(dir, "ca.pem"), []byte("passess-fake-not-a-cert"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"ca.pem", "./ca.pem", "../ca.pem", "~/ca.pem"} {
		_, err := (&Vault{CACert: p}).client()
		if !errors.Is(err, ErrUnavailable) || !strings.Contains(err.Error(), "absolute") {
			t.Errorf("ca_cert %q: %v", p, err)
		}
	}
	// Control: an absolute path still loads.
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	t.Cleanup(ts.Close)
	ca := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ts.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := (&Vault{CACert: ca}).client(); err != nil {
		t.Errorf("absolute ca_cert: %v", err)
	}
}
