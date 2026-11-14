package provider

import (
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
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
