package provider

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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

func (v *Vault) address() string {
	for _, a := range []string{v.Address, v.getenv("VAULT_ADDR"), v.getenv("BAO_ADDR")} {
		if a != "" {
			return strings.TrimRight(a, "/")
		}
	}
	return ""
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
		data, err := os.ReadFile(filepath.Join(v.getenv("HOME"), ".vault-token"))
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
	v.Client = &http.Client{Transport: tr, Timeout: 15 * time.Second}
	return v.Client, nil
}

func (v *Vault) Available(ctx context.Context) error {
	if v.address() == "" {
		return fmt.Errorf("%w: no vault address; set backends.vault.address or VAULT_ADDR", ErrUnavailable)
	}
	_, err := v.accessToken(ctx)
	return err
}

func (v *Vault) Resolve(ctx context.Context, r ref.Ref) (secret.Value, error) {
	addr := v.address()
	if addr == "" {
		return secret.Value{}, &Error{r, fmt.Errorf("%w: no vault address; set backends.vault.address or VAULT_ADDR", ErrUnavailable)}
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
