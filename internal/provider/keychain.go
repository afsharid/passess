package provider

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"regexp"
	"runtime"
	"strings"

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

// Store writes value under service/account, replacing an existing item, and
// reads it back to confirm. The value reaches security(1) on stdin through its
// interactive mode (secret-tool reads stdin anyway), so it never appears on a
// command line.
// keychainName is what Store accepts as a service or an account: they reach
// security(1)'s interactive parser as quoted words, and this set needs no
// quoting at all, whoever calls Store next.
var keychainName = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)

func (k Keychain) Store(ctx context.Context, service, account string, value secret.Value) error {
	if bytes.ContainsAny(value.Bytes(), "\n\r\x00") {
		return errors.New("a value with line breaks cannot be stored in the keychain this way")
	}
	if !keychainName.MatchString(service) || !keychainName.MatchString(account) {
		return errors.New("keychain service and account names may hold only letters, digits, dot, underscore and hyphen")
	}
	tool, err := k.tool()
	if err != nil {
		return err
	}
	getenv := k.Getenv
	if getenv == nil {
		getenv = OSGetenv
	}
	var cmd Cmd
	switch tool {
	case "security":
		q := func(s string) string { return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s) + `"` }
		line := []byte("add-generic-password -U -s " + q(service) + " -a " + q(account) + " -l " + q("passess "+account) + " -w ")
		line = append(line, q(string(value.Bytes()))...)
		line = append(line, '\n')
		defer clear(line)
		cmd = Cmd{Name: "security", Args: []string{"-i"}, Env: BaseEnv(getenv), Stdin: line}
	case "secret-tool":
		cmd = Cmd{Name: "secret-tool", Args: []string{"store", "--label", "passess " + account, "service", service, "account", account},
			Env: BaseEnv(getenv), Stdin: value.Bytes()}
	}
	res, err := k.Runner.Run(ctx, cmd)
	if err != nil {
		return err
	}
	if res.Exit != 0 || len(bytes.TrimSpace(res.Stderr)) > 0 {
		return fmt.Errorf("%s could not store the item: %s", tool, CLIMessage(res.Stderr))
	}
	back, err := k.Resolve(ctx, ref.Ref{Scheme: ref.Keychain, Path: []string{service, account}})
	if err != nil {
		return fmt.Errorf("stored, but reading it back failed: %w", err)
	}
	defer back.Zero()
	if !bytes.Equal(back.Bytes(), value.Bytes()) {
		return errors.New("stored, but the keychain returned a different value")
	}
	return nil
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
