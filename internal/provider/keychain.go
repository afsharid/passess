package provider

import (
	"context"
	"fmt"
	"runtime"

	"github.com/afsharid/passess/internal/ref"
	"github.com/afsharid/passess/internal/secret"
)

// Keychain resolves keychain://<service>/<account> from the OS keychain: the
// macOS login keychain through security(1), or the Secret Service on Linux
// through secret-tool(1).
type Keychain struct {
	Runner Runner
	Getenv func(string) string
	GOOS   string // runtime.GOOS when empty
}

func (Keychain) Scheme() string { return ref.Keychain }

func (k Keychain) goos() string {
	if k.GOOS != "" {
		return k.GOOS
	}
	return runtime.GOOS
}

func (k Keychain) tool() (string, error) {
	switch k.goos() {
	case "darwin":
		return "security", nil
	case "linux":
		return "secret-tool", nil
	}
	return "", fmt.Errorf("%w: keychain:// is supported on macOS and Linux only", ErrUnavailable)
}

func (k Keychain) Available(ctx context.Context) error {
	_, err := k.tool()
	return err
}

func (k Keychain) Resolve(ctx context.Context, r ref.Ref) (secret.Value, error) {
	tool, err := k.tool()
	if err != nil {
		return secret.Value{}, &Error{r, err}
	}
	service, account := r.Path[0], r.Path[1]
	args := []string{"find-generic-password", "-s", service, "-a", account, "-w"}
	if tool == "secret-tool" {
		args = []string{"lookup", "service", service, "account", account}
	}
	getenv := k.Getenv
	if getenv == nil {
		getenv = OSGetenv
	}
	res, err := k.Runner.Run(ctx, Cmd{Name: tool, Args: args, Env: BaseEnv(getenv)})
	if err != nil {
		return secret.Value{}, &Error{r, err}
	}
	// security(1) exits 44 for a missing item; secret-tool exits 1 with no output.
	if (tool == "security" && res.Exit == 44) || (tool == "secret-tool" && res.Exit == 1 && len(res.Stdout) == 0) {
		clear(res.Stdout)
		return secret.Value{}, &Error{r, ErrNotFound}
	}
	if res.Exit != 0 {
		clear(res.Stdout)
		return secret.Value{}, &Error{r, fmt.Errorf("%s exited %d: %s", tool, res.Exit, CLIMessage(res.Stderr))}
	}
	v := valueFrom(trimNewline(res.Stdout))
	clear(res.Stdout)
	if v.Empty() {
		return secret.Value{}, &Error{r, ErrNotFound}
	}
	return v, nil
}
