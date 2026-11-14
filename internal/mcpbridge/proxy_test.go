package mcpbridge

import (
	"net/http"
	"testing"
)

// The bridge carries the remote server's credentials, so it must not take a
// proxy from the caller's environment.
func TestNewClientIgnoresTheCallersProxy(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:9")
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:9")
	client, err := newClient("https://mcp.example.com/mcp", "", http.Header{"Authorization": {"Bearer " + token}})
	if err != nil {
		t.Fatal(err)
	}
	ht, ok := client.Transport.(headerTransport)
	if !ok {
		t.Fatalf("transport is %T", client.Transport)
	}
	tr, ok := ht.base.(*http.Transport)
	if !ok {
		t.Fatalf("base is %T", ht.base)
	}
	if tr.Proxy != nil {
		t.Fatal("the bridge's transport reads a proxy from the environment")
	}
}
