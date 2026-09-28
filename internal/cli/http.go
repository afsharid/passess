package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/afsharid/passess/internal/config"
	"github.com/afsharid/passess/internal/redact"
)

func init() {
	commands["http"] = command{"send an HTTP request with secrets in it, only to the hosts each secret names", runHTTP}
}

// ExitHTTPError is what `passess http` returns for a 4xx or 5xx answer, as
// curl --fail does.
const ExitHTTPError = 22

// httpTransport is the transport passess http uses; tests replace it.
var httpTransport http.RoundTripper = http.DefaultTransport

var placeholder = regexp.MustCompile(`\{\{([A-Za-z_][A-Za-z0-9_]*)\}\}`)

type headerFlags []string

func (h *headerFlags) String() string { return "" }

func (h *headerFlags) Set(v string) error {
	name, _, ok := strings.Cut(v, ":")
	if !ok || strings.TrimSpace(name) == "" || strings.ContainsAny(name, " \t") {
		return fmt.Errorf("%q is not 'Name: value'", v)
	}
	*h = append(*h, v)
	return nil
}

// runHTTP sends one request itself, so a secret never reaches a child
// process, and only to a host every secret in it names in its hosts list.
// That is what curl through exec cannot promise: there the agent picks the
// URL, and the value goes wherever it points.
func runHTTP(st *Streams, args []string) int {
	fs := flag.NewFlagSet("http", flag.ContinueOnError)
	fs.SetOutput(st.Stderr)
	var wanted secretFlags
	fs.Var(&wanted, "s", "secret the request uses: NAME or NAME,NAME (repeatable); {{NAME}} stands for it")
	method := fs.String("X", "", "request method (GET, or POST when -d is given)")
	var headers headerFlags
	fs.Var(&headers, "H", "request header 'Name: value' (repeatable); {{NAME}} stands for a secret")
	data := fs.String("d", "", "request body, or @FILE to read it from a file; {{NAME}} stands for a secret")
	include := fs.Bool("i", false, "print the response status and headers before the body")
	output := fs.String("o", "", "write the body to FILE instead of stdout")
	maxTime := fs.Duration("max-time", time.Minute, "give up after this long")
	fs.Usage = func() {
		fmt.Fprintln(st.Stderr, "Usage: passess http -s NAME [-X METHOD] [-H 'Name: value']... [-d DATA|@FILE] [-i] [-o FILE] URL")
		fmt.Fprintln(st.Stderr, "Each secret goes only to the hosts its `hosts` list in the config names.")
		fs.PrintDefaults()
	}
	pos, err := parseAnywhere(fs, args)
	if err != nil {
		return ExitUsage
	}
	if len(pos) != 1 || len(wanted) == 0 {
		fs.Usage()
		return ExitUsage
	}
	names := wanted.names()
	for _, w := range wanted {
		if w.env != w.name {
			return failf(st, ExitUsage, "-s %s=%s: passess http names secrets by NAME and uses them as {{NAME}}", w.env, w.name)
		}
	}
	body := *data
	if strings.HasPrefix(body, "@") {
		b, err := os.ReadFile(body[1:])
		if err != nil {
			return failf(st, ExitUsage, "%v", err)
		}
		body = string(b)
	}
	// Every placeholder must name a secret given with -s, before anything is resolved.
	for _, text := range append([]string{pos[0], body}, headers...) {
		for _, m := range placeholder.FindAllStringSubmatch(text, -1) {
			if !contains(names, m[1]) {
				return failf(st, ExitUsage, "{{%s}} names a secret not given with -s", m[1])
			}
		}
	}

	u, _, code := loadConfig(st)
	if code != 0 {
		return code
	}
	target, err := url.Parse(placeholder.ReplaceAllString(pos[0], "x"))
	if err != nil || target.Host == "" {
		return failf(st, ExitUsage, "%q is not an absolute URL", pos[0])
	}
	// The host is checked with "x" in place of each placeholder; a value
	// expanded into the scheme or host would then go somewhere unchecked.
	if placeholder.MatchString(urlOrigin(pos[0])) {
		return failf(st, ExitUsage, "a {{NAME}} placeholder cannot be part of the URL's scheme or host; put it in the path, the query, a header or the body")
	}
	for _, n := range names {
		s, ok := u.Secrets[n]
		if !ok {
			return failf(st, ExitConfig, "%s is not defined; ask the user to run `passess add %s --ref <reference>`", n, n)
		}
		if why := hostAllowed(target, s); why != "" {
			return failf(st, ExitNoPerm, "refusing to send %s to %s: %s", n, target.Host, why)
		}
	}
	self, err := os.Executable()
	if err != nil {
		self = "passess"
	}
	if code := askApproval(st, u, names, []string{self, "http", target.Host}); code != 0 {
		return code
	}

	res, zero := newResolver(st, u)
	defer zero()
	values := map[string]string{}
	var named []redact.Secret
	for _, n := range names {
		v, err := res.Secret(context.Background(), u.Secrets[n])
		if err != nil {
			return failf(st, resolveExitCode(err), "%v", err)
		}
		values[n] = string(v.Bytes())
		named = append(named, redact.Secret{Name: n, Value: v})
	}
	rd, _, err := redact.New(named, redact.Options{})
	if err != nil {
		return failf(st, ExitConfig, "%v", err)
	}
	defer rd.Zero()
	expand := func(s string) string {
		return placeholder.ReplaceAllStringFunc(s, func(m string) string { return values[m[2:len(m)-2]] })
	}

	verb := *method
	if verb == "" {
		verb = http.MethodGet
		if *data != "" {
			verb = http.MethodPost
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), *maxTime)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, verb, expand(pos[0]), strings.NewReader(expand(body)))
	if err != nil {
		return failf(st, ExitUsage, "%s", rd.Redact([]byte(err.Error())))
	}
	if req.URL.Scheme != target.Scheme || req.URL.Host != target.Host {
		return failf(st, ExitUsage, "the URL's host changed once the secrets were put in; refusing to send")
	}
	for _, h := range headers {
		k, v, _ := strings.Cut(h, ":")
		req.Header.Add(strings.TrimSpace(k), expand(strings.TrimSpace(v)))
	}
	client := &http.Client{Transport: httpTransport, CheckRedirect: func(next *http.Request, via []*http.Request) error {
		if len(via) >= 5 {
			return errors.New("more than 5 redirects")
		}
		for _, n := range names {
			if why := hostAllowed(next.URL, u.Secrets[n]); why != "" {
				return fmt.Errorf("refusing to follow a redirect to %s with %s: %s", next.URL.Host, n, why)
			}
		}
		return nil
	}}
	resp, err := client.Do(req)
	if err != nil {
		code := ExitUnavailable
		if strings.Contains(err.Error(), "refusing to follow") {
			code = ExitNoPerm
		}
		return failf(st, code, "%s", rd.Redact([]byte(err.Error())))
	}
	defer func() { _ = resp.Body.Close() }()

	out := st.Stdout
	if *output != "" {
		f, err := os.OpenFile(*output, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
		if err != nil {
			return failf(st, ExitSoftware, "%v", err)
		}
		defer f.Close()
		out = f
	}
	w := rd.NewWriter(out)
	if *include {
		fmt.Fprintf(w, "%s %s\n", resp.Proto, resp.Status)
		keys := make([]string, 0, len(resp.Header))
		for k := range resp.Header {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			for _, v := range resp.Header[k] {
				fmt.Fprintf(w, "%s: %s\n", k, v)
			}
		}
		fmt.Fprintln(w)
	}
	_, err = io.Copy(w, resp.Body)
	if cerr := w.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return failf(st, ExitUnavailable, "reading the response: %s", rd.Redact([]byte(err.Error())))
	}
	if resp.StatusCode >= 400 {
		fmt.Fprintf(st.Stderr, "passess http: %s %s\n", resp.Proto, resp.Status)
		return ExitHTTPError
	}
	return ExitOK
}

// hostAllowed says why s may not go to u, or "". https only, except to this
// machine; the host must match an entry of s.Hosts, where *.example.com
// matches its subdomains and an entry without a port only the scheme's own.
// urlOrigin is raw's scheme and authority, "scheme://user@host:port": all of
// it up to the first /, ? or # after "://", or all of raw without "://".
func urlOrigin(raw string) string {
	i := strings.Index(raw, "://")
	if i < 0 {
		return raw
	}
	rest := raw[i+3:]
	if j := strings.IndexAny(rest, "/?#"); j >= 0 {
		rest = rest[:j]
	}
	return raw[:i+3] + rest
}

func hostAllowed(u *url.URL, s config.Secret) string {
	if len(s.Hosts) == 0 {
		return fmt.Sprintf("it names no hosts; add hosts = [\"%s\"] to secrets.%s in the config if it belongs there", u.Hostname(), s.Name)
	}
	host := strings.ToLower(u.Hostname())
	local := host == "localhost" || net.ParseIP(host) != nil && net.ParseIP(host).IsLoopback()
	switch {
	case u.Scheme == "https":
	case u.Scheme == "http" && local:
	default:
		return "only https goes out, plain http to this machine alone"
	}
	defaultPort := map[string]string{"https": "443", "http": "80"}[u.Scheme]
	port := u.Port()
	if port == "" {
		port = defaultPort
	}
	for _, h := range s.Hosts {
		pattern, want := strings.ToLower(h), defaultPort
		if p, pp, err := net.SplitHostPort(pattern); err == nil {
			pattern, want = p, pp
		}
		if want != port {
			continue
		}
		if suffix, ok := strings.CutPrefix(pattern, "*."); ok {
			if strings.HasSuffix(host, "."+suffix) {
				return ""
			}
		} else if host == pattern {
			return ""
		}
	}
	return fmt.Sprintf("its hosts are %s", strings.Join(s.Hosts, ", "))
}
