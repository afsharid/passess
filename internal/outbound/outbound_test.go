package outbound

import (
	"cmp"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// selfSignedPEM makes a certificate for 127.0.0.1 that signs itself.
func selfSignedPEM(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "passess-fake-ca"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestTransportIgnoresProxyEnvironment(t *testing.T) {
	for _, k := range []string{"HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY", "https_proxy", "http_proxy"} {
		t.Setenv(k, "http://127.0.0.1:9")
	}
	t.Setenv("NO_PROXY", "")
	// Go skips the proxy for loopback hosts, so a nil Proxy is the check.
	if Transport().Proxy != nil {
		t.Fatal("the transport reads a proxy from the environment")
	}
}

func TestTransportDoesNotDialCallersProxy(t *testing.T) {
	proxy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = proxy.Close() }()
	hits := make(chan struct{}, 4)
	go func() {
		for {
			c, err := proxy.Accept()
			if err != nil {
				return
			}
			hits <- struct{}{}
			_ = c.Close()
		}
	}()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	t.Setenv("HTTPS_PROXY", "http://"+proxy.Addr().String())
	t.Setenv("HTTP_PROXY", "http://"+proxy.Addr().String())
	tr := Transport()
	tr.TLSClientConfig.RootCAs = x509.NewCertPool()
	tr.TLSClientConfig.RootCAs.AddCert(srv.Certificate())
	resp, err := (&http.Client{Transport: tr}).Get(srv.URL)
	if err != nil {
		t.Fatalf("direct request failed: %v", err)
	}
	_ = resp.Body.Close()
	select {
	case <-hits:
		t.Fatal("the request went to the caller's proxy")
	default:
	}
}

// A CA named by SSL_CERT_FILE must not make a certificate trusted, and the
// variables must be back after the load. Go reads SSL_CERT_FILE only on Linux,
// so on other systems this test passes without the fix and proves nothing.
func TestLoadRootsIgnoresCertEnvironment(t *testing.T) {
	onlyLinux(t)
	file := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(file, selfSignedPEM(t), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SSL_CERT_FILE", file)
	t.Setenv("SSL_CERT_DIR", filepath.Dir(file))

	pool := loadRoots()
	block, _ := pem.Decode(selfSignedPEM(t))
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	_, verr := cert.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}})
	if verr == nil {
		t.Fatal("a certificate named only by SSL_CERT_FILE is trusted")
	}
	if os.Getenv("SSL_CERT_FILE") != file || os.Getenv("SSL_CERT_DIR") != filepath.Dir(file) {
		t.Fatal("the certificate variables were not restored")
	}
}

func TestLoadRootsLeavesUnsetVariablesUnset(t *testing.T) {
	onlyLinux(t)
	t.Setenv("SSL_CERT_FILE", "x")
	_ = os.Unsetenv("SSL_CERT_FILE")
	_ = os.Unsetenv("SSL_CERT_DIR")
	loadRoots()
	if _, ok := os.LookupEnv("SSL_CERT_FILE"); ok {
		t.Fatal("SSL_CERT_FILE was set by the load")
	}
	if _, ok := os.LookupEnv("SSL_CERT_DIR"); ok {
		t.Fatal("SSL_CERT_DIR was set by the load")
	}
}

// onlyLinux skips a test that checks the SSL_CERT_FILE fix. Go uses the
// platform verifier elsewhere and ignores the variable, so a pass there is
// not evidence.
func onlyLinux(t *testing.T) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("Go reads SSL_CERT_FILE only on Linux; this check does not discriminate on " + runtime.GOOS)
	}
}

// A server signed only by a CA in SSL_CERT_FILE must fail the handshake.
func TestTransportRejectsServerSignedByCertEnvironmentCA(t *testing.T) {
	onlyLinux(t)
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "passess-fake-ca"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "passess-fake-leaf"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{leafDER}, PrivateKey: leafKey}}}
	srv.StartTLS()
	defer srv.Close()

	file := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(file, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SSL_CERT_FILE", file)
	// Load the roots again under this variable, as a first load would.
	rootsOnce = sync.Once{}
	t.Cleanup(func() { rootsOnce = sync.Once{} })

	client := &http.Client{Transport: Transport()}
	resp, err := client.Get(srv.URL)
	if err == nil {
		_ = resp.Body.Close()
		t.Fatal("the request to a server signed only by the SSL_CERT_FILE CA succeeded")
	}
	var unknown x509.UnknownAuthorityError
	if !errors.As(err, &unknown) {
		t.Fatalf("want a certificate error, got %v", err)
	}
}

// Every client that carries a secret takes its transport from this package,
// because the roots fix works only when this package loads the roots first.
// A new non-test file that builds its own client, or uses the default one,
// fails here. Add a file to the allowlist only after reading outbound.go.
func TestNoHTTPClientOutsideOutbound(t *testing.T) {
	root := filepath.Join("..", "..")
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			if rel == "internal/outbound" || rel == ".git" || rel == ".claude" || rel == "vendor" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(rel, ".go") || strings.HasSuffix(rel, "_test.go") {
			return nil
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, v := range outboundViolations(rel, src) {
			t.Errorf("%s: %s", rel, v)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// Files that build a client and take its transport from outbound.Transport().
var allowClient = map[string]bool{
	"internal/provider/vault.go":   true,
	"internal/cli/http.go":         true,
	"internal/mcpbridge/bridge.go": true,
}

// Names of net/http that a file outside this package must not reach. Client
// is allowed only in allowClient files, and only beside outbound.Transport().
var bannedHTTP = map[string]bool{
	"Transport": true, "DefaultClient": true, "DefaultTransport": true,
	"Get": true, "Post": true, "Head": true, "PostForm": true,
}

// MCP SDK transports that dial with their own client unless given one.
var sdkTransports = map[string]bool{"StreamableClientTransport": true, "SSEClientTransport": true}

// outboundViolations lists what src breaks of the outbound rule. It parses
// src and resolves the local names of net/http, crypto/tls and the outbound
// package, so an alias, a dot import, a type use or new(http.Client) counts
// as the literal does.
func outboundViolations(rel string, src []byte) []string {
	f, err := parser.ParseFile(token.NewFileSet(), rel, src, parser.SkipObjectResolution)
	if err != nil {
		return []string{"does not parse: " + err.Error()}
	}
	var out []string
	var httpName, tlsName, outboundName string
	dotHTTP := false
	for _, im := range f.Imports {
		path, _ := strconv.Unquote(im.Path.Value)
		name := ""
		if im.Name != nil {
			name = im.Name.Name
		}
		switch {
		case path == "net/http":
			if name == "." {
				dotHTTP = true
			} else if name != "_" {
				httpName = cmp.Or(name, "http")
			}
		case path == "crypto/tls":
			tlsName = cmp.Or(name, "tls")
		case path == "net/http/httputil":
			out = append(out, "imports net/http/httputil; build the client on outbound.Transport()")
		case strings.HasSuffix(path, "/internal/outbound"):
			outboundName = cmp.Or(name, "outbound")
		}
	}
	allowed := allowClient[rel]
	usesOutbound := false
	check := func(pkg, name string) {
		switch {
		case pkg == httpName && httpName != "" || pkg == "" && dotHTTP:
			ref := "http." + name
			switch {
			case bannedHTTP[name]:
				out = append(out, "uses "+ref+"; build the client on outbound.Transport()")
			case name == "Client" && !allowed:
				out = append(out, "uses "+ref+"; add the file to the allowlist after it uses outbound.Transport()")
			}
		case pkg == tlsName && tlsName != "" && (name == "Dial" || name == "DialWithDialer" || name == "Client"):
			out = append(out, "uses tls."+name+"; build the client on outbound.Transport()")
		case pkg == outboundName && outboundName != "" && name == "Transport":
			usesOutbound = true
		}
	}
	usesHTTPClient := false
	ast.Inspect(f, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.SelectorExpr:
			if x, ok := n.X.(*ast.Ident); ok {
				check(x.Name, n.Sel.Name)
				if x.Name == httpName && httpName != "" && n.Sel.Name == "Client" {
					usesHTTPClient = true
				}
			}
			if sdkTransports[n.Sel.Name] && rel != "internal/mcpbridge/bridge.go" {
				out = append(out, "uses "+n.Sel.Name+"; it dials with its own client outside the bridge")
			}
		case *ast.Ident:
			if dotHTTP && n.Name == "Client" {
				usesHTTPClient = true
			}
			if dotHTTP && (bannedHTTP[n.Name] || n.Name == "Client") {
				check("", n.Name)
			}
		}
		return true
	})
	if allowed && usesHTTPClient && !usesOutbound {
		out = append(out, "uses http.Client without outbound.Transport()")
	}
	return out
}

func TestOutboundViolationsVariants(t *testing.T) {
	const other = "internal/zz/zz.go"
	hdr := "package zz\n"
	cases := []struct {
		name, rel, src string
		want           bool
	}{
		{"literal", other, hdr + "import \"net/http\"\nvar _ = &http.Client{}\n", true},
		{"zero value", other, hdr + "import \"net/http\"\nvar _ http.Client\n", true},
		{"new", other, hdr + "import \"net/http\"\nvar _ = new(http.Client)\n", true},
		{"pointer type", other, hdr + "import \"net/http\"\nvar _ *http.Client\n", true},
		{"alias", other, hdr + "import h \"net/http\"\nvar _ = &h.Client{}\n", true},
		{"alias default transport", other, hdr + "import h \"net/http\"\nvar _ = h.DefaultTransport\n", true},
		{"alias get", other, hdr + "import h \"net/http\"\nfunc f() { _, _ = h.Get(\"x\") }\n", true},
		{"dot import client", other, hdr + "import . \"net/http\"\nvar _ = &Client{}\n", true},
		{"dot import get", other, hdr + "import . \"net/http\"\nfunc f() { _, _ = Get(\"x\") }\n", true},
		{"default client", other, hdr + "import \"net/http\"\nvar _ = http.DefaultClient\n", true},
		{"post form", other, hdr + "import \"net/http\"\nfunc f() { _, _ = http.PostForm(\"x\", nil) }\n", true},
		{"transport struct", other, hdr + "import \"net/http\"\nvar _ = &http.Transport{}\n", true},
		{"transport zero value", other, hdr + "import \"net/http\"\nvar _ http.Transport\n", true},
		{"sdk transport without client", other, hdr + "import \"example.test/sdk/mcp\"\nvar _ = &mcp.StreamableClientTransport{Endpoint: \"x\"}\n", true},
		{"sse transport", other, hdr + "import \"example.test/sdk/mcp\"\nvar _ = &mcp.SSEClientTransport{}\n", true},
		{"allowlisted without outbound", "internal/cli/http.go", hdr + "import \"net/http\"\nvar _ = &http.Client{}\n", true},
		{"allowlisted aliased outbound", "internal/cli/http.go", hdr + "import (\n\t\"net/http\"\n\to \"github.com/afsharid/passess/internal/outbound\"\n)\nvar _ = &http.Client{Transport: o.Transport()}\n", false},
		{"allowlisted with outbound", "internal/cli/http.go", hdr + "import (\n\t\"net/http\"\n\t\"github.com/afsharid/passess/internal/outbound\"\n)\nvar _ = &http.Client{Transport: outbound.Transport()}\n", false},
		{"allowlisted default transport", "internal/cli/http.go", hdr + "import (\n\t\"net/http\"\n\t\"github.com/afsharid/passess/internal/outbound\"\n)\nvar _ = outbound.Transport\nvar _ = http.DefaultTransport\n", true},
		{"bridge sdk transport", "internal/mcpbridge/bridge.go", hdr + "import (\n\t\"net/http\"\n\t\"example.test/sdk/mcp\"\n\t\"github.com/afsharid/passess/internal/outbound\"\n)\nvar _ = &http.Client{Transport: outbound.Transport()}\nvar _ = &mcp.StreamableClientTransport{}\n", false},
		{"types only", other, hdr + "import \"net/http\"\nvar _ http.RoundTripper\nvar _ = http.MethodGet\nvar _ = http.Header{}\nfunc f(r *http.Request) {}\n", false},
		{"no net/http", other, hdr + "type T struct{}\nfunc (T) Get() {}\nvar _ = T{}\n", false},
		{"local Client without import", other, hdr + "type http struct{ Client int }\nvar x http\nvar _ = x.Client\n", false},
		{"tls dial", other, hdr + "import \"crypto/tls\"\nfunc f() { _, _ = tls.Dial(\"tcp\", \"x\", nil) }\n", true},
		{"httputil", other, hdr + "import \"net/http/httputil\"\nvar _ = httputil.NewSingleHostReverseProxy\n", true},
	}
	for _, c := range cases {
		got := outboundViolations(c.rel, []byte(c.src))
		if (len(got) > 0) != c.want {
			t.Errorf("%s: want violation=%v, got %v", c.name, c.want, got)
		}
	}
}
