// Package outbound builds the HTTP transport every passess client uses for a
// request that carries a secret.
package outbound

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"os"
	"sync"
)

// certEnv are the variables Go reads, on Linux, to replace the system root
// certificates.
var certEnv = []string{"SSL_CERT_FILE", "SSL_CERT_DIR"}

var (
	rootsOnce sync.Once
	roots     *x509.CertPool
)

// Transport returns a new transport that ignores the caller's proxy variables
// (HTTPS_PROXY, ALL_PROXY, ...) and trusts the system root certificates, not
// the ones SSL_CERT_FILE or SSL_CERT_DIR name. The caller owns both settings,
// and a proxy that terminates TLS with a CA it chose reads the secret in
// clear. A caller that needs another CA names it in the config (vault
// ca_cert).
func Transport() *http.Transport {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.Proxy = nil
	tr.TLSClientConfig = &tls.Config{RootCAs: systemRoots(), MinVersion: tls.VersionTLS12}
	return tr
}

// systemRoots loads the system roots once. If it cannot load them, the pool is
// empty and every handshake fails, which is safer than falling back to the
// caller's variables.
func systemRoots() *x509.CertPool {
	rootsOnce.Do(func() { roots = loadRoots() })
	return roots
}

// loadRoots reads the system roots with the certificate variables unset, then
// puts them back so a child process still inherits them. Go caches the first
// load for the process, so this assumes it is the first x509 system-root load
// in the process: every TLS client that carries a secret takes its transport
// from this package, so nothing else loads the roots before it.
func loadRoots() *x509.CertPool {
	type saved struct {
		key, val string
		set      bool
	}
	var old []saved
	for _, k := range certEnv {
		v, ok := os.LookupEnv(k)
		old = append(old, saved{k, v, ok})
		_ = os.Unsetenv(k)
	}
	defer func() {
		for _, s := range old {
			if s.set {
				_ = os.Setenv(s.key, s.val)
			}
		}
	}()
	pool, err := x509.SystemCertPool()
	if err != nil {
		return x509.NewCertPool()
	}
	return pool
}
