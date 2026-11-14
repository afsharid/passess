package cli

import (
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

// The caller names a proxy in the environment; passess http must still dial
// the host itself, or the proxy reads the secret.
func TestHTTPIgnoresTheCallersProxy(t *testing.T) {
	proxy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = proxy.Close() }()
	var hits atomic.Int32
	go func() {
		for {
			c, err := proxy.Accept()
			if err != nil {
				return
			}
			hits.Add(1)
			_ = c.Close()
		}
	}()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	httpSetup(t, srv)
	httpTransport = nil // the default one, as in a real run
	t.Setenv("HTTPS_PROXY", "http://"+proxy.Addr().String())
	t.Setenv("ALL_PROXY", "http://"+proxy.Addr().String())

	run(t, "http", "-s", "X", "-H", "Authorization: Bearer {{X}}", srv.URL+"/user")
	if n := hits.Load(); n != 0 {
		t.Fatalf("passess http sent the request to the caller's proxy %d time(s)", n)
	}
}
