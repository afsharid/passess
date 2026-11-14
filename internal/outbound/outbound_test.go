package outbound

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
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
// variables must be back after the load.
func TestLoadRootsIgnoresCertEnvironment(t *testing.T) {
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
