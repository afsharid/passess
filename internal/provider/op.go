package provider

import (
	"context"
	"fmt"
	"strings"

	"github.com/afsharid/passess/internal/ref"
	"github.com/afsharid/passess/internal/secret"
)

// OnePassword resolves op://vault/item/[section/]field with `op read`. The CLI
// talks to the 1Password desktop app, so its biometric unlock applies; a
// service account works through OP_SERVICE_ACCOUNT_TOKEN.
type OnePassword struct {
	Runner  Runner
	Getenv  func(string) string
	Account string // backends.op.account, passed as --account
}

func (OnePassword) Scheme() string { return ref.OnePassword }

func (o OnePassword) Available(ctx context.Context) error {
	if _, err := lookPath("op"); err != nil {
		return fmt.Errorf("%w: op (1Password CLI) is not installed", ErrUnavailable)
	}
	return nil
}

func (o OnePassword) env() []string {
	getenv := o.Getenv
	if getenv == nil {
		getenv = OSGetenv
	}
	env := BaseEnv(getenv)
	for _, k := range []string{"OP_SERVICE_ACCOUNT_TOKEN", "OP_ACCOUNT", "OP_CONNECT_HOST", "OP_CONNECT_TOKEN", "OP_BIOMETRIC_UNLOCK_ENABLED"} {
		if v := getenv(k); v != "" {
			env = append(env, k+"="+v)
		}
	}
	return env
}

func (o OnePassword) Resolve(ctx context.Context, r ref.Ref) (secret.Value, error) {
	args := []string{"read", "--no-newline"}
	if o.Account != "" {
		args = append(args, "--account", o.Account)
	}
	args = append(args, r.String())
	res, err := o.Runner.Run(ctx, Cmd{Name: "op", Args: args, Env: o.env()})
	if err != nil {
		return secret.Value{}, &Error{r, err}
	}
	if res.Exit != 0 {
		clear(res.Stdout)
		return secret.Value{}, &Error{r, classifyOP(res.Stderr, res.Exit)}
	}
	v := valueFrom(res.Stdout)
	if v.Empty() {
		return secret.Value{}, &Error{r, ErrNotFound}
	}
	return v, nil
}

func classifyOP(stderr []byte, exit int) error {
	msg := strings.ToLower(string(stderr))
	switch {
	case strings.Contains(msg, "isn't an item") || strings.Contains(msg, "isn't a vault") || strings.Contains(msg, "could not find") ||
		strings.Contains(msg, "no item") || strings.Contains(msg, "isn't a field") || strings.Contains(msg, "does not have a field"):
		return ErrNotFound
	case strings.Contains(msg, "not signed in") || strings.Contains(msg, "sign in") || strings.Contains(msg, "authorization") ||
		strings.Contains(msg, "dismissed") || strings.Contains(msg, "connect to the 1password app") || strings.Contains(msg, "locked"):
		return fmt.Errorf("%w: 1Password is locked or not signed in: %s", ErrUnavailable, CLIMessage(stderr))
	}
	return fmt.Errorf("op exited %d: %s", exit, CLIMessage(stderr))
}
