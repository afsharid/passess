package provider

import (
	"cmp"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/afsharid/passess/internal/ref"
	"github.com/afsharid/passess/internal/secret"
)

// Vault resolves vault://<mount>/<path>#<key> against HashiCorp Vault or
// OpenBao over HTTP. KV version 2 is tried first, then version 1.
type Vault struct {
	Address   string // backends.vault.address, else VAULT_ADDR / BAO_ADDR
	Namespace string
	CACert    string // PEM file; system roots when empty
	Getenv    func(string) string
	// Token returns the token; when nil, VAULT_TOKEN, BAO_TOKEN or ~/.vault-token.
	Token  func(ctx context.Context) (secret.Value, error)
	Client *http.Client

	token secret.Value
}

func (*Vault) Scheme() string { return ref.Vault }

func (v *Vault) getenv(k string) string {
	if v.Getenv != nil {
		return v.Getenv(k)
	}
	return os.Getenv(k)
}

// address returns where the token may be sent. A token passess holds itself
// (backends.vault.token) goes only to backends.vault.address: passess runs in
// its caller's environment, and the caller's VAULT_ADDR must not aim a
// credential passess keeps at a server of the caller's choosing. A token the
// caller supplies (VAULT_TOKEN, BAO_TOKEN, ~/.vault-token) may go where the
// caller says, as it does for the vault CLI.
func (v *Vault) address() (string, error) {
	var a string
	switch {
	case v.Address != "":
		a = v.Address
	case v.Token != nil:
		return "", fmt.Errorf("%w: backends.vault.token needs backends.vault.address; passess does not send its own token to VAULT_ADDR", ErrUnavailable)
	default:
		a = cmp.Or(v.getenv("VAULT_ADDR"), v.getenv("BAO_ADDR"))
	}
	if a == "" {
		return "", fmt.Errorf("%w: no vault address; set backends.vault.address or VAULT_ADDR", ErrUnavailable)
	}
	a = strings.TrimRight(a, "/")
	u, err := url.Parse(a)
	if err != nil || u.Host == "" {
		return "", fmt.Errorf("%w: the vault address is not a URL", ErrUnavailable)
	}
	if u.Scheme != "https" && (u.Scheme != "http" || !isLoopback(u.Hostname())) {
		return "", fmt.Errorf("%w: the vault address must use https (plain http only to this machine): the token would travel in clear", ErrUnavailable)
	}
	return a, nil
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func (v *Vault) accessToken(ctx context.Context) (secret.Value, error) {
	if !v.token.Empty() {
		return v.token, nil
	}
	switch {
	case v.Token != nil:
		t, err := v.Token(ctx)
		if err != nil {
			return secret.Value{}, fmt.Errorf("%w: vault token: %w", ErrUnavailable, err)
		}
		v.token = t
	case v.getenv("VAULT_TOKEN") != "":
		v.token = secret.FromString(v.getenv("VAULT_TOKEN"))
	case v.getenv("BAO_TOKEN") != "":
		v.token = secret.FromString(v.getenv("BAO_TOKEN"))
	default:
		// The account's own file, not one the caller's $HOME points at.
		data, err := os.ReadFile(filepath.Join(cmp.Or(accountHome(), v.getenv("HOME")), ".vault-token"))
		if err != nil {
			return secret.Value{}, fmt.Errorf("%w: no vault token; set backends.vault.token, VAULT_TOKEN, or run `vault login`", ErrUnavailable)
		}
		v.token = valueFrom([]byte(strings.TrimSpace(string(data))))
		clear(data)
	}
	return v.token, nil
}

func (v *Vault) client() (*http.Client, error) {
	if v.Client != nil {
		return v.Client, nil
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	if v.CACert != "" {
		pem, err := os.ReadFile(v.CACert)
		if err != nil {
			return nil, fmt.Errorf("%w: backends.vault.ca_cert: %w", ErrUnavailable, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("%w: backends.vault.ca_cert holds no PEM certificate", ErrUnavailable)
		}
		tr.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	}
	v.Client = &http.Client{Transport: tr, Timeout: 15 * time.Second, CheckRedirect: sameHostRedirect}
	return v.Client, nil
}

// sameHostRedirect refuses a redirect to another host or scheme: Go keeps
// X-Vault-Token on every hop, so following one would hand the token to
// whichever server the redirect names.
func sameHostRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= 5 {
		return errors.New("too many redirects")
	}
	if first := via[0].URL; req.URL.Host != first.Host || req.URL.Scheme != first.Scheme {
		return fmt.Errorf("vault redirected to another server; set backends.vault.address to it directly")
	}
	return nil
}

func (v *Vault) Available(ctx context.Context) error {
	if _, err := v.address(); err != nil {
		return err
	}
	_, err := v.accessToken(ctx)
	return err
}

func (v *Vault) Resolve(ctx context.Context, r ref.Ref) (secret.Value, error) {
	addr, err := v.address()
	if err != nil {
		return secret.Value{}, &Error{r, err}
	}
	mount, path := r.Path[0], strings.Join(r.Path[1:], "/")
	// KV v2 keeps data under <mount>/data/<path> and nests it one level deeper.
	fields, err := v.get(ctx, addr+"/v1/"+escape(mount)+"/data/"+escape(path), true)
	if errors.Is(err, ErrNotFound) {
		fields, err = v.get(ctx, addr+"/v1/"+escape(mount)+"/"+escape(path), false)
	}
	if err != nil {
		return secret.Value{}, &Error{r, err}
	}
	val, ok := fields[r.Key]
	if !ok {
		return secret.Value{}, &Error{r, ErrNotFound}
	}
	s, ok := val.(string)
	if !ok {
		return secret.Value{}, &Error{r, fmt.Errorf("vault key %s is not a string", r.Key)}
	}
	if s == "" {
		return secret.Value{}, &Error{r, ErrNotFound}
	}
	return secret.FromString(s), nil
}

func escape(p string) string {
	parts := strings.Split(p, "/")
	for i, s := range parts {
		parts[i] = url.PathEscape(s)
	}
	return strings.Join(parts, "/")
}

func (v *Vault) get(ctx context.Context, u string, kv2 bool) (map[string]any, error) {
	tok, err := v.accessToken(ctx)
	if err != nil {
		return nil, err
	}
	client, err := v.client()
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Vault-Token", string(tok.Bytes()))
	req.Header.Set("X-Vault-Request", "true")
	if v.Namespace != "" {
		req.Header.Set("X-Vault-Namespace", v.Namespace)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: vault unreachable: %w", ErrUnavailable, sanitizeURLError(err))
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, fmt.Errorf("%w: reading vault reply: %w", ErrUnavailable, err)
	}
	defer clear(body)
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound:
		return nil, ErrNotFound
	case http.StatusForbidden, http.StatusUnauthorized:
		return nil, fmt.Errorf("%w: vault denied the request (%d): token invalid, expired or without a policy for this path", ErrUnavailable, resp.StatusCode)
	default:
		return nil, fmt.Errorf("vault returned %d", resp.StatusCode)
	}
	var doc struct {
		Data map[string]any `json:"data"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, errors.New("vault returned a reply passess cannot read")
	}
	if !kv2 {
		return doc.Data, nil
	}
	inner, ok := doc.Data["data"].(map[string]any)
	if !ok {
		return nil, ErrNotFound // a v1 mount answering the v2 path, or a deleted version
	}
	return inner, nil
}

// sanitizeURLError drops the URL from a transport error; it can carry a path
// the user would rather not see in logs.
func sanitizeURLError(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		return ue.Err
	}
	return err
}
