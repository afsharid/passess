package mcpbridge

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

// A redirect from the configured server to another one is not followed, and
// the other server never receives the secret header.
func TestClientKeepsSecretHeadersToTheirOrigin(t *testing.T) {
	var leaked atomic.Bool
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			leaked.Store(true)
		}
	}))
	t.Cleanup(other.Close)
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	t.Cleanup(origin.Close)

	client, err := newClient(origin.URL+"/mcp", http.Header{"Authorization": {"Bearer passess-fake-token"}})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client.Post(origin.URL+"/mcp", "application/json", nil)
	if err == nil {
		_ = resp.Body.Close()
		t.Fatal("the cross-origin redirect was followed")
	}
	if leaked.Load() {
		t.Fatal("the other server received the secret header")
	}

	// A request to the configured origin itself still carries the header.
	var got string
	same := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { got = r.Header.Get("Authorization") }))
	t.Cleanup(same.Close)
	client, _ = newClient(same.URL+"/mcp", http.Header{"Authorization": {"Bearer passess-fake-token"}})
	resp, err = client.Post(same.URL+"/mcp", "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if got != "Bearer passess-fake-token" {
		t.Fatalf("origin request header = %q", got)
	}
}
