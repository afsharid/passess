package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/afsharid/passess/internal/config"
	"github.com/afsharid/passess/internal/policy"
	"github.com/afsharid/passess/internal/provider"
	"github.com/afsharid/passess/internal/ref"
	"github.com/afsharid/passess/internal/resolve"
	"github.com/afsharid/passess/internal/secret"
)

// failf prints a passess message on stderr and returns code.
func failf(st *Streams, code int, format string, args ...any) int {
	fmt.Fprintf(st.Stderr, "passess: "+format+"\n", args...)
	return code
}

// loadConfig reads the user config and, if the working directory is inside a
// project, the project file.
func loadConfig(st *Streams) (*config.User, *config.Project, int) {
	path, err := config.UserPath(st.Getenv)
	if err != nil {
		return nil, nil, failf(st, ExitConfig, "%v", err)
	}
	u, err := config.LoadUser(path)
	if err != nil {
		return nil, nil, failf(st, ExitConfig, "%v", err)
	}
	wd, err := os.Getwd()
	if err != nil {
		return u, nil, 0
	}
	pf := config.FindProject(wd)
	if pf == "" {
		return u, nil, 0
	}
	p, err := config.LoadProject(pf)
	if err != nil {
		return nil, nil, failf(st, ExitConfig, "%v", err)
	}
	return u, p, 0
}

// newResolver wires the providers the user config can use. The returned
// function zeroes every value any of them holds.
func newResolver(st *Streams, u *config.User) (*resolve.Resolver, func()) {
	run := provider.ExecRunner{}
	env := provider.Env{}
	keychain := provider.Keychain{Runner: run, Getenv: st.Getenv}
	bws := &provider.BWS{Runner: run, Getenv: st.Getenv, ServerURL: u.Backends.BWS.ServerURL}

	op := provider.OnePassword{Runner: run, Getenv: st.Getenv, Account: u.Backends.OP.Account}
	vault := &provider.Vault{Address: u.Backends.Vault.Address, Namespace: u.Backends.Vault.Namespace,
		CACert: u.Backends.Vault.CACert, Getenv: st.Getenv}
	bw := provider.Bitwarden{Runner: run, Getenv: st.Getenv}

	// Backend credentials come from providers that need no credential of their own.
	boot := resolve.New(env, keychain)
	from := func(name string, r *ref.Ref) func(context.Context) (secret.Value, error) {
		if r == nil {
			return nil
		}
		return func(ctx context.Context) (secret.Value, error) {
			return boot.Secret(ctx, config.Secret{Name: name, Refs: []ref.Ref{*r}})
		}
	}
	bws.Token = from("backends.bws.access_token", u.Backends.BWS.AccessToken)
	if bws.Token == nil && st.Getenv("BWS_ACCESS_TOKEN") != "" {
		bws.Token = func(context.Context) (secret.Value, error) {
			return secret.FromString(st.Getenv("BWS_ACCESS_TOKEN")), nil
		}
	}
	vault.Token = from("backends.vault.token", u.Backends.Vault.Token)
	bw.Session = from("backends.bw.session", u.Backends.BW.Session)

	r := resolve.New(env, keychain, bws, op, vault, bw)
	return r, func() { r.Zero(); boot.Zero(); bws.Zero() }
}

// resolveExitCode maps a resolution failure to an exit code.
func resolveExitCode(err error) int {
	if errors.Is(err, provider.ErrUnavailable) {
		return ExitUnavailable
	}
	return ExitConfig
}

// childEnv is environ without anything that looks like a credential, names a
// configured secret or is the source of an env:// reference, plus the
// injected values.
func childEnv(environ []string, u *config.User, inject map[string]secret.Value) []string {
	drop := map[string]bool{}
	for name, s := range u.Secrets {
		drop[name] = true
		for _, r := range s.Refs {
			if r.Scheme == ref.Env {
				drop[r.Path[0]] = true
			}
		}
	}
	env := make([]string, 0, len(environ)+len(inject))
	for _, kv := range environ {
		name, _, _ := strings.Cut(kv, "=")
		if _, ok := inject[name]; ok || drop[name] || policy.Sensitive(name) {
			continue
		}
		env = append(env, kv)
	}
	names := make([]string, 0, len(inject))
	for n := range inject {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		env = append(env, n+"="+string(inject[n].Bytes()))
	}
	return env
}
