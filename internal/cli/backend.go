package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/term"

	"github.com/afsharid/passess/internal/config"
	"github.com/afsharid/passess/internal/provider"
	"github.com/afsharid/passess/internal/ref"
	"github.com/afsharid/passess/internal/secret"
)

func init() {
	commands["backend"] = command{"store a backend's own credential in the keychain: `backend bws` takes the machine token on stdin", runBackend}
}

// defaultBWSToken is where passess looks for the bws machine token when the
// config names no other place: what `passess backend bws` writes.
var defaultBWSToken = ref.Ref{Scheme: ref.Keychain, Path: []string{"passess", "bws"}}

// backendRunner runs security(1) for backend; tests keep it off the real keychain.
var backendRunner provider.Runner = provider.ExecRunner{}

// runBackend stores the bws machine token, so a new machine is set up
// without editing a file: the token goes to the keychain on security(1)'s
// stdin, and a missing config is started. The token opens the vault, so this
// is the user's to run, as add and set are.
func runBackend(st *Streams, args []string) int {
	if len(args) != 1 || args[0] != "bws" {
		fmt.Fprintln(st.Stderr, "Usage: passess backend bws   (the machine token on stdin, or typed at the prompt)")
		return ExitUsage
	}
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

// readToken reads one line: typed without echo at a terminal, else stdin.
func readToken(st *Streams) (secret.Value, error) {
	var raw []byte
	if f, ok := st.Stdin.(*os.File); ok && term.IsTerminal(int(f.Fd())) {
		fmt.Fprint(st.Stderr, "bws machine token (not shown): ")
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
		return secret.Value{}, errors.New("give the bws machine token on one line")
	}
	return secret.New(t), nil
}
