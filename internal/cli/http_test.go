package cli

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/afsharid/passess/internal/config"
)

// httpSetup writes a config whose secret X may go to the test server alone,
// Y names no hosts, and points passess http at the server's certificate.
func httpSetup(t *testing.T, srv *httptest.Server) {
	t.Helper()
	dir := setupDir(t)
	host := strings.TrimPrefix(srv.URL, "https://")
	body := `version = 1
[secrets.X]
ref   = "env://PASSESS_TEST_X_TOKEN"
hosts = ["` + host + `"]
[secrets.Y]
ref = "env://PASSESS_TEST_Y_TOKEN"
`
	if err := os.WriteFile(filepath.Join(dir, "config.toml"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	old := httpTransport
	httpTransport = srv.Client().Transport
	t.Cleanup(func() { httpTransport = old })
}

func TestHTTPSendsTheSecretToItsHostOnly(t *testing.T) {
	var got atomic.Value
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.Store(r.Header.Get("Authorization"))
		w.Header().Set("X-Echo", r.Header.Get("Authorization"))
		_, _ = w.Write([]byte("you sent " + r.Header.Get("Authorization") + "\n"))
	}))
	defer srv.Close()
	httpSetup(t, srv)

	out, errOut, code := run(t, "http", "-s", "X", "-H", "Authorization: Bearer {{X}}", "-i", srv.URL+"/user")
	if code != 0 {
		t.Fatalf("exit %d, %s", code, errOut)
	}
	if got.Load() != "Bearer "+execValue {
		t.Fatalf("the server got %q", got.Load())
	}
	if strings.Contains(out, execValue) || !strings.Contains(out, "you sent Bearer [REDACTED:X]") ||
		!strings.Contains(out, "X-Echo: Bearer [REDACTED:X]") || !strings.Contains(out, "200 OK") {
		t.Fatalf("output:\n%s", out)
	}
}

func TestHTTPRefusals(t *testing.T) {
	contacted := atomic.Int32{}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		contacted.Add(1)
		if r.URL.Path == "/missing" {
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	httpSetup(t, srv)

	for _, c := range []struct {
		args []string
		code int
		want string
	}{
		{[]string{"-s", "X", "https://example.com/"}, ExitNoPerm, "its hosts are"},
		{[]string{"-s", "Y", srv.URL + "/"}, ExitNoPerm, "names no hosts"},
		{[]string{"-s", "X", "http://example.com/"}, ExitNoPerm, "only https"},
		{[]string{"-s", "X", "-H", "Authorization: {{Z}}", srv.URL + "/"}, ExitUsage, "{{Z}} names a secret not given"},
		{[]string{"-s", "ALIAS=X", srv.URL + "/"}, ExitUsage, "names secrets by NAME"},
		// A placeholder in the host is checked as "x" and sent as the value.
		{[]string{"-s", "X", "https://{{X}}." + strings.TrimPrefix(srv.URL, "https://") + "/"}, ExitUsage, "scheme or host"},
		{[]string{"-s", "X", "https://u:{{X}}@" + strings.TrimPrefix(srv.URL, "https://") + "/"}, ExitUsage, "scheme or host"},
	} {
		_, errOut, code := run(t, append([]string{"http"}, c.args...)...)
		if code != c.code || !strings.Contains(errOut, c.want) {
			t.Errorf("passess http %v: exit %d, %q", c.args, code, errOut)
		}
	}
	if contacted.Load() != 0 {
		t.Fatalf("a refused request reached the server %d times", contacted.Load())
	}
	if _, errOut, code := run(t, "http", "-s", "X", srv.URL+"/q?t={{X}}"); code != 0 {
		t.Fatalf("a placeholder in the query: exit %d, %q", code, errOut)
	}
	if _, errOut, code := run(t, "http", "-s", "X", srv.URL+"/missing"); code != ExitHTTPError || !strings.Contains(errOut, "404") {
		t.Fatalf("a 404: exit %d, %q", code, errOut)
	}
}

// A redirect is followed only to a host the secret may go to.
func TestHTTPRedirectsStayOnTheSecretsHosts(t *testing.T) {
	var elsewhere atomic.Value
	other := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		elsewhere.Store(r.Header.Get("Authorization"))
	}))
	defer other.Close()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/away":
			http.Redirect(w, r, other.URL+"/", http.StatusFound)
		case "/here":
			http.Redirect(w, r, "/done", http.StatusFound)
		default:
			_, _ = w.Write([]byte("done\n"))
		}
	}))
	defer srv.Close()
	httpSetup(t, srv)

	if out, errOut, code := run(t, "http", "-s", "X", "-H", "Authorization: {{X}}", srv.URL+"/here"); code != 0 || out != "done\n" {
		t.Fatalf("a redirect on the same host: exit %d, %q, %q", code, out, errOut)
	}
	_, errOut, code := run(t, "http", "-s", "X", "-H", "Authorization: {{X}}", srv.URL+"/away")
	if code != ExitNoPerm || !strings.Contains(errOut, "refusing to follow a redirect") || strings.Contains(errOut, execValue) {
		t.Fatalf("a redirect elsewhere: exit %d, %q", code, errOut)
	}
	if elsewhere.Load() != nil {
		t.Fatal("the other host was contacted")
	}
}

func TestHostAllowed(t *testing.T) {
	s := config.Secret{Name: "T", Hosts: []string{"api.github.com", "*.example.com", "localhost:8080"}}
	for raw, ok := range map[string]bool{
		"https://api.github.com/user":      true,
		"https://API.GitHub.com/x":         true,
		"https://api.github.com:8443/":     false,
		"http://api.github.com/":           false,
		"https://a.example.com/":           true,
		"https://a.b.example.com/":         true,
		"https://example.com/":             false,
		"https://evil-example.com/":        false,
		"http://localhost:8080/":           true,
		"http://localhost/":                false,
		"https://api.github.com.evil.com/": false,
	} {
		u, _ := url.Parse(raw)
		if got := hostAllowed(u, s) == ""; got != ok {
			t.Errorf("%s: allowed %v, want %v", raw, got, ok)
		}
	}
}
