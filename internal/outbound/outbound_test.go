package outbound

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
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
	banned := regexp.MustCompile(`http\.DefaultTransport|http\.DefaultClient|http\.(Get|Post|Head|PostForm)\(|&?http\.Transport\{|tls\.Dial|tls\.Client\(|net/http/httputil`)
	client := regexp.MustCompile(`http\.Client\{`)
	// Files that build a client and take its transport from outbound.Transport().
	allowClient := map[string]bool{
		"internal/provider/vault.go":   true,
		"internal/cli/http.go":         true,
		"internal/mcpbridge/bridge.go": true,
	}
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
		if m := banned.Find(src); m != nil {
			t.Errorf("%s uses %q; build the client on outbound.Transport()", rel, m)
		}
		if client.Match(src) {
			if !allowClient[rel] {
				t.Errorf("%s builds an http.Client; add it to the allowlist after it uses outbound.Transport()", rel)
			} else if !strings.Contains(string(src), "outbound.Transport()") {
				t.Errorf("%s builds an http.Client without outbound.Transport()", rel)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
