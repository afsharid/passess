package cli

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/term"

	"github.com/afsharid/passess/internal/config"
	"github.com/afsharid/passess/internal/provider"
	"github.com/afsharid/passess/internal/ref"
	"github.com/afsharid/passess/internal/secret"
)

func init() {
	commands["backend"] = command{"a backend's settings and its own credential: `backend bws` takes the machine token on stdin; `backend --json` shows them", runBackend}
}

// defaultBWSToken is where passess looks for the bws machine token when the
// config names no other place: what `passess backend bws` writes.
var defaultBWSToken = ref.Ref{Scheme: ref.Keychain, Path: []string{"passess", "bws"}}

// defaultVaultToken and defaultBWSession are where `backend vault --token`
// and `backend bw --session` keep those credentials.
var (
	defaultVaultToken = ref.Ref{Scheme: ref.Keychain, Path: []string{"passess", "vault"}}
	defaultBWSession  = ref.Ref{Scheme: ref.Keychain, Path: []string{"passess", "bw-session"}}
)

// backendRunner runs security(1) for backend; tests keep it off the real keychain.
var backendRunner provider.Runner = provider.ExecRunner{}

const backendUsage = `Usage:
  passess backend --json                      the backends' settings (references, never values)
  passess backend bws                         the machine token on stdin, or typed at the prompt
  passess backend bws --server-url URL        a self-hosted Bitwarden server ("" for bitwarden.com)
  passess backend op --account ACCOUNT        the 1Password account op uses ("" for its default)
  passess backend vault [--address URL] [--namespace NS] [--ca-cert PATH] [--token]
                                              --token: the token on stdin, kept in the keychain
  passess backend bw --session                the unlocked session key on stdin, kept in the keychain`

// runBackend sets what each backend needs, so no one edits the config for
// it. Credentials go to the keychain on security(1)'s stdin, and the config
// names where they are; a missing config is started.
func runBackend(st *Streams, args []string) int {
	if len(args) == 1 && args[0] == "--json" {
		return showBackends(st)
	}
	if len(args) == 0 {
		fmt.Fprintln(st.Stderr, backendUsage)
		return ExitUsage
	}
	switch args[0] {
	case "bws":
		if len(args) == 1 {
			return storeBWSToken(st)
		}
	case "op", "vault", "bw":
	default:
		fmt.Fprintln(st.Stderr, backendUsage)
		return ExitUsage
	}
	return setBackend(st, args[0], args[1:])
}

// backendView is what `backend --json` prints: settings and where each
// credential lives.
type backendView struct {
	OP struct {
		Account string `json:"account"`
	} `json:"op"`
	Vault struct {
		Address   string `json:"address"`
		Namespace string `json:"namespace"`
		CACert    string `json:"ca_cert"`
		Token     string `json:"token"` // a reference
	} `json:"vault"`
	BW struct {
		Session string `json:"session"` // a reference
	} `json:"bw"`
	BWS struct {
		ServerURL   string `json:"server_url"`
		AccessToken string `json:"access_token"` // a reference
	} `json:"bws"`
}

func showBackends(st *Streams) int {
	path, err := config.UserPath(st.Getenv)
	if err != nil {
		return failf(st, ExitConfig, "%v", err)
	}
	var v backendView
	u, err := config.LoadUser(path)
	switch {
	case errors.Is(err, config.ErrNoConfig):
		return writeJSON(st, v)
	case err != nil:
		return failf(st, ExitConfig, "%v", err)
	}
	refString := func(r *ref.Ref) string {
		if r == nil {
			return ""
		}
		return r.String()
	}
	b := u.Backends
	v.OP.Account = b.OP.Account
	v.Vault.Address, v.Vault.Namespace, v.Vault.CACert, v.Vault.Token = b.Vault.Address, b.Vault.Namespace, b.Vault.CACert, refString(b.Vault.Token)
	v.BW.Session = refString(b.BW.Session)
	v.BWS.ServerURL, v.BWS.AccessToken = b.BWS.ServerURL, refString(b.BWS.AccessToken)
	return writeJSON(st, v)
}

// setBackend writes the flags given for one backend into [backends.NAME].
func setBackend(st *Streams, backend string, args []string) int {
	fs := flag.NewFlagSet("backend "+backend, flag.ContinueOnError)
	fs.SetOutput(st.Stderr)
	strs := map[string]*string{}
	var stdinCred *bool // the one credential this backend takes on stdin
	var credKey string
	var credRef ref.Ref
	switch backend {
	case "bws":
		strs["server_url"] = fs.String("server-url", "", "a self-hosted Bitwarden server URL; empty for bitwarden.com")
	case "op":
		strs["account"] = fs.String("account", "", "the 1Password account op uses (sign-in address, email or ID); empty for its default")
	case "vault":
		strs["address"] = fs.String("address", "", "the Vault or OpenBao address, https://…; empty: VAULT_ADDR")
		strs["namespace"] = fs.String("namespace", "", "the Vault namespace; empty for none")
		strs["ca_cert"] = fs.String("ca-cert", "", "a CA certificate file for the server; empty for the system's")
		stdinCred, credKey, credRef = fs.Bool("token", false, "read the Vault token from stdin and keep it in the keychain"), "token", defaultVaultToken
	case "bw":
		stdinCred, credKey, credRef = fs.Bool("session", false, "read the unlocked session key (bw unlock --raw) from stdin and keep it in the keychain"), "session", defaultBWSession
	}
	fs.Usage = func() { fmt.Fprintln(st.Stderr, backendUsage) }
	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}
	if fs.NArg() > 0 {
		return failf(st, ExitUsage, "unexpected argument %q", fs.Arg(0))
	}
	given := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { given[strings.ReplaceAll(f.Name, "-", "_")] = true })
	if len(given) == 0 {
		fmt.Fprintln(st.Stderr, backendUsage)
		return ExitUsage
	}
	var fields []config.Field
	for _, key := range sortedKeys(strs) {
		if !given[key] {
			continue
		}
		v := strings.TrimSpace(*strs[key])
		if strings.ContainsAny(v, "\n\r\x00") {
			return failf(st, ExitUsage, "--%s must be one line", strings.ReplaceAll(key, "_", "-"))
		}
		if (key == "address" || key == "server_url") && v != "" {
			if u, err := url.Parse(v); err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
				return failf(st, ExitUsage, "--%s takes an http(s) URL", strings.ReplaceAll(key, "_", "-"))
			}
		}
		var lit *string // empty: back to the default, no key
		if v != "" {
			q := tomlString(v)
			lit = &q
		}
		fields = append(fields, config.Field{Key: key, Value: lit})
	}
	if code := refuseUnderAgent(st, "backend", "sets how passess reaches your vault"); code != 0 {
		return code
	}
	if code := startUserConfig(st); code != 0 {
		return code
	}
	if stdinCred != nil && *stdinCred {
		u, err := loadUserConfig(st)
		if err != nil {
			return failf(st, ExitConfig, "%v", err)
		}
		cur := map[string]*ref.Ref{"token": u.Backends.Vault.Token, "session": u.Backends.BW.Session}[credKey]
		if cur != nil && cur.String() != credRef.String() {
			return failf(st, ExitConfig, "backends.%s.%s reads it from %s; store it there, or take that key out to use %s", backend, credKey, cur, credRef.String())
		}
		cred, err := readSecretLine(st, backend+" "+credKey)
		if err != nil {
			return failf(st, ExitUsage, "%v", err)
		}
		defer cred.Zero()
		// The keychain first: a stored credential the config does not name yet
		// is harmless; a config naming an empty item fails every resolve.
		kc := provider.Keychain{Runner: backendRunner, Getenv: st.Getenv}
		if err := kc.Store(context.Background(), credRef.Path[0], credRef.Path[1], cred); err != nil {
			return failf(st, ExitUnavailable, "storing the %s %s failed: %v", backend, credKey, err)
		}
		q := tomlString(credRef.String())
		fields = append(fields, config.Field{Key: credKey, Value: &q})
	}
	path, code := editUserConfig(st, func(data []byte) ([]byte, error) {
		return config.SetTableFields(data, []string{"backends", backend}, fields, true)
	})
	if code != 0 {
		return code
	}
	fmt.Fprintf(st.Stdout, "updated backends.%s in %s\n", backend, path)
	return ExitOK
}

// startUserConfig writes a config with only its version when there is none,
// so a first setting has a file to go in.
func startUserConfig(st *Streams) int {
	path, err := config.UserPath(st.Getenv)
	if err != nil {
		return failf(st, ExitConfig, "%v", err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		return 0
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return failf(st, ExitConfig, "%v", err)
	}
	if err := writeFileAtomic(path, []byte("version = 1\n"), 0o600); err != nil {
		return failf(st, ExitConfig, "%v", err)
	}
	fmt.Fprintf(st.Stdout, "passess: started %s\n", path)
	return 0
}

func loadUserConfig(st *Streams) (*config.User, error) {
	path, err := config.UserPath(st.Getenv)
	if err != nil {
		return nil, err
	}
	return config.LoadUser(path)
}

// storeBWSToken stores the bws machine token, so a new machine is set up
// without editing a file: the token goes to the keychain on security(1)'s
// stdin, and a missing config is started. The token opens the vault, so this
// is the user's to run, as add and set are.
func storeBWSToken(st *Streams) int {
	if code := refuseUnderAgent(st, "backend", "stores the token that opens your vault"); code != 0 {
		return code
	}
	path, err := config.UserPath(st.Getenv)
	if err != nil {
		return failf(st, ExitConfig, "%v", err)
	}
	u, err := config.LoadUser(path)
	switch {
	case errors.Is(err, config.ErrNoConfig):
		u = nil
	case err != nil:
		return failf(st, ExitConfig, "%v", err)
	case u.Backends.BWS.AccessToken != nil && u.Backends.BWS.AccessToken.String() != defaultBWSToken.String():
		return failf(st, ExitConfig, "%s reads the bws token from %s; store it there, or take backends.bws.access_token out to use %s",
			path, u.Backends.BWS.AccessToken, defaultBWSToken.String())
	}

	token, err := readToken(st)
	if err != nil {
		return failf(st, ExitUsage, "%v", err)
	}
	defer token.Zero()
	// The config first: a token stored with no config to read it is a
	// half-done setup; an empty config without a token is just a start.
	if u == nil {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return failf(st, ExitConfig, "%v", err)
		}
		if err := writeFileAtomic(path, []byte("version = 1\n"), 0o600); err != nil {
			return failf(st, ExitConfig, "%v", err)
		}
		fmt.Fprintf(st.Stdout, "passess: started %s\n", path)
	}
	kc := provider.Keychain{Runner: backendRunner, Getenv: st.Getenv}
	if err := kc.Store(context.Background(), defaultBWSToken.Path[0], defaultBWSToken.Path[1], token); err != nil {
		return failf(st, ExitUnavailable, "storing the bws token failed: %v", err)
	}
	fmt.Fprintf(st.Stdout, "passess: the bws machine token is in %s; `passess discover` lists the vault's secrets\n", defaultBWSToken.String())
	return ExitOK
}

// readToken reads the bws machine token: typed without echo at a terminal,
// else stdin.
func readToken(st *Streams) (secret.Value, error) {
	return readSecretLine(st, "bws machine token")
}

// readSecretLine reads one line, what: typed without echo at a terminal, else
// stdin.
func readSecretLine(st *Streams, what string) (secret.Value, error) {
	var raw []byte
	if f, ok := st.Stdin.(*os.File); ok && term.IsTerminal(int(f.Fd())) {
		fmt.Fprintf(st.Stderr, "%s (not shown): ", what)
		b, err := term.ReadPassword(int(f.Fd()))
		fmt.Fprintln(st.Stderr)
		if err != nil {
			return secret.Value{}, err
		}
		raw = b
	} else {
		b, err := io.ReadAll(io.LimitReader(st.Stdin, 8192))
		if err != nil {
			return secret.Value{}, err
		}
		raw = b
	}
	defer clear(raw)
	t := bytes.TrimSpace(raw)
	if len(t) == 0 || bytes.ContainsAny(t, "\n\r") {
		return secret.Value{}, fmt.Errorf("give the %s on one line", what)
	}
	return secret.New(t), nil
}
