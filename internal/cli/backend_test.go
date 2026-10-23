package cli

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/afsharid/passess/internal/provider"
)

const backendToken = "0.fake-machine-token-for-tests"

// keychainFake is a keychain that holds what it was given.
type keychainFake struct {
	t      *testing.T
	stored *string
}

func (f keychainFake) Run(_ context.Context, c provider.Cmd) (provider.Result, error) {
	switch {
	case len(c.Args) == 1 && c.Args[0] == "-i": // security -i: the add command on stdin, never in argv
		line := string(c.Stdin)
		if !strings.Contains(line, `-s "passess" -a "bws"`) {
			f.t.Errorf("stored under the wrong item: %q", line)
		}
		*f.stored = backendToken
		return provider.Result{}, nil
	case len(c.Args) > 0 && c.Args[0] == "find-generic-password":
		return provider.Result{Stdout: []byte(*f.stored + "\n")}, nil
	case len(c.Args) > 0 && c.Args[0] == "store": // secret-tool
		*f.stored = string(c.Stdin)
		return provider.Result{}, nil
	case len(c.Args) > 0 && c.Args[0] == "lookup":
		return provider.Result{Stdout: []byte(*f.stored)}, nil
	}
	f.t.Fatalf("unexpected command %v", c.Args)
	return provider.Result{}, nil
}

func TestBackendBWS(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("keychain:// is macOS and Linux")
	}
	noHarness(t)
	dir := t.TempDir()
	cfg := filepath.Join(dir, "passess", "config.toml")
	t.Setenv("PASSESS_CONFIG", cfg)
	var stored string
	saved := backendRunner
	t.Cleanup(func() { backendRunner = saved })
	backendRunner = keychainFake{t, &stored}

	run := func(stdin string, args ...string) (string, string, int) {
		t.Helper()
		var out, errb strings.Builder
		code := Main(args, strings.NewReader(stdin), &out, &errb)
		return out.String(), errb.String(), code
	}
	if _, errOut, code := run("\n", "backend", "bws"); code != ExitUsage || !strings.Contains(errOut, "one line") {
		t.Fatalf("an empty token: exit %d, %q", code, errOut)
	}
	out, errOut, code := run(backendToken+"\n", "backend", "bws")
	if code != 0 || stored != backendToken || strings.Contains(out+errOut, backendToken) {
		t.Fatalf("store: exit %d, %q %q", code, out, errOut)
	}
	if data, err := os.ReadFile(cfg); err != nil || string(data) != "version = 1\n" {
		t.Fatalf("a missing config is started: %q, %v", data, err)
	}

	// A config that reads the token from elsewhere is not quietly ignored.
	if err := os.WriteFile(cfg, []byte("version = 1\n[backends.bws]\naccess_token = \"keychain://other/bws\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, errOut, code := run(backendToken, "backend", "bws"); code != ExitConfig || !strings.Contains(errOut, "keychain://other/bws") {
		t.Fatalf("a token kept elsewhere: exit %d, %q", code, errOut)
	}

	// Under a coding agent it is refused: the token opens the vault.
	t.Setenv("CLAUDECODE", "1")
	if _, _, code := run(backendToken, "backend", "bws"); code != ExitNoPerm {
		t.Fatalf("under an agent: exit %d", code)
	}
}

// itemKeychainFake records which keychain item each value went to, and
// fails a test that finds the value in argv.
type itemKeychainFake struct {
	t     *testing.T
	items map[string]string // "service/account" → value
}

func (f itemKeychainFake) Run(_ context.Context, c provider.Cmd) (provider.Result, error) {
	for _, a := range c.Args {
		if strings.Contains(a, backendToken) {
			f.t.Fatalf("the value is in argv: %v", c.Args)
		}
	}
	switch {
	case len(c.Args) == 1 && c.Args[0] == "-i":
		line := string(c.Stdin)
		for _, item := range []string{"passess/vault", "passess/bw-session"} {
			svc, acct, _ := strings.Cut(item, "/")
			if strings.Contains(line, `-s "`+svc+`" -a "`+acct+`"`) {
				f.items[item] = backendToken
				return provider.Result{}, nil
			}
		}
		f.t.Errorf("stored under an unexpected item: %q", line)
		return provider.Result{}, nil
	case len(c.Args) >= 5 && c.Args[0] == "find-generic-password": // the read-back after storing
		return provider.Result{Stdout: []byte(f.items[c.Args[2]+"/"+c.Args[4]] + "\n")}, nil
	case len(c.Args) > 0 && c.Args[0] == "store": // secret-tool: attributes in argv, value on stdin
		f.items[c.Args[len(c.Args)-3]+"/"+c.Args[len(c.Args)-1]] = string(c.Stdin)
		return provider.Result{}, nil
	}
	f.t.Fatalf("unexpected command %v", c.Args)
	return provider.Result{}, nil
}

// Each backend's settings are set without editing the config: into
// [backends.NAME], a credential into the keychain with the config naming it,
// and an empty value back to the default.
func TestBackendSettings(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("the fake speaks security(1)")
	}
	noHarness(t)
	cfg := filepath.Join(t.TempDir(), "passess", "config.toml")
	t.Setenv("PASSESS_CONFIG", cfg)
	saved := backendRunner
	t.Cleanup(func() { backendRunner = saved })
	kc := itemKeychainFake{t, map[string]string{}}
	backendRunner = kc
	run := func(stdin string, args ...string) (string, string, int) {
		t.Helper()
		var out, errb strings.Builder
		code := Main(args, strings.NewReader(stdin), &out, &errb)
		return out.String(), errb.String(), code
	}
	mustRun := func(stdin string, args ...string) {
		t.Helper()
		if out, errOut, code := run(stdin, args...); code != 0 {
			t.Fatalf("%v: exit %d, %q %q", args, code, out, errOut)
		}
	}
	if out, _, code := run("", "backend", "--json"); code != 0 || !strings.Contains(out, `"account": ""`) {
		t.Fatalf("no config yet: exit %d, %s", code, out)
	}
	mustRun("", "backend", "op", "--account", "my.1password.com")
	mustRun("", "backend", "vault", "--address", "https://vault.example.com:8200", "--namespace", "team")
	mustRun(backendToken+"\n", "backend", "vault", "--token")
	mustRun(backendToken+"\n", "backend", "bw", "--session")
	mustRun("", "backend", "bws", "--server-url", "https://vault.bitwarden.eu")
	if kc.items["passess/vault"] != backendToken || kc.items["passess/bw-session"] != backendToken {
		t.Fatalf("keychain: %v", kc.items)
	}
	data, _ := os.ReadFile(cfg)
	for _, want := range []string{
		"[backends.op]\naccount = \"my.1password.com\"\n",
		"[backends.vault]\naddress = \"https://vault.example.com:8200\"\nnamespace = \"team\"\ntoken = \"keychain://passess/vault\"\n",
		"[backends.bw]\nsession = \"keychain://passess/bw-session\"\n",
		"[backends.bws]\nserver_url = \"https://vault.bitwarden.eu\"\n",
	} {
		if !strings.Contains(string(data), want) {
			t.Fatalf("config lacks %q:\n%s", want, data)
		}
	}
	if strings.Contains(string(data), backendToken) {
		t.Fatal("a credential value is in the config")
	}
	out, _, _ := run("", "backend", "--json")
	if !strings.Contains(out, `"token": "keychain://passess/vault"`) || strings.Contains(out, backendToken) {
		t.Fatalf("--json: %s", out)
	}
	// An empty value goes back to the default.
	mustRun("", "backend", "op", "--account", "")
	if data, _ := os.ReadFile(cfg); strings.Contains(string(data), "my.1password.com") {
		t.Fatalf("the account stayed:\n%s", data)
	}
	if _, errOut, code := run("", "backend", "vault", "--address", "vault.example.com"); code != ExitUsage || !strings.Contains(errOut, "URL") {
		t.Fatalf("a bare host: exit %d, %q", code, errOut)
	}
	if _, _, code := run("", "backend", "op"); code != ExitUsage {
		t.Fatalf("no flags: exit %d", code)
	}
	t.Setenv("CLAUDECODE", "1")
	if _, _, code := run("", "backend", "op", "--account", "x"); code != ExitNoPerm {
		t.Fatalf("under an agent: exit %d", code)
	}
	if _, _, code := run("", "backend", "--json"); code != 0 {
		t.Fatalf("--json under an agent: exit %d", code)
	}
}

// addKeychainFake is a keychain for add --value-stdin: the value arrives on
// security(1)'s stdin, under service passess and the secret's name.
type addKeychainFake struct {
	t      *testing.T
	stored *string
}

func (f addKeychainFake) Run(_ context.Context, c provider.Cmd) (provider.Result, error) {
	for _, a := range c.Args {
		if strings.Contains(a, backendToken) {
			f.t.Fatalf("the value is in argv: %v", c.Args)
		}
	}
	switch {
	case len(c.Args) == 1 && c.Args[0] == "-i":
		line := string(c.Stdin)
		if !strings.Contains(line, `-s "passess" -a "NEW_KEY"`) || !strings.Contains(line, `"`+backendToken+`"`) {
			f.t.Errorf("stored the wrong item: %q", line)
		}
		*f.stored = backendToken
		return provider.Result{}, nil
	case len(c.Args) > 0 && c.Args[0] == "find-generic-password":
		return provider.Result{Stdout: []byte(*f.stored + "\n")}, nil
	case len(c.Args) > 0 && c.Args[0] == "store":
		*f.stored = string(c.Stdin)
		return provider.Result{}, nil
	case len(c.Args) > 0 && c.Args[0] == "lookup":
		return provider.Result{Stdout: []byte(*f.stored)}, nil
	}
	f.t.Fatalf("unexpected command %v", c.Args)
	return provider.Result{}, nil
}

func TestAddKeychainValueStdin(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("keychain:// is macOS and Linux")
	}
	noHarness(t)
	dir := writeConfig(t, "version = 1\n")
	var stored string
	saved := addRunner
	t.Cleanup(func() { addRunner = saved })
	addRunner = addKeychainFake{t, &stored}
	run := func(stdin string, args ...string) (string, string, int) {
		t.Helper()
		var out, errb strings.Builder
		code := Main(args, strings.NewReader(stdin), &out, &errb)
		return out.String(), errb.String(), code
	}

	if _, errOut, code := run(backendToken, "add", "NEW_KEY", "--ref", "env://X", "--value-stdin"); code != ExitUsage || !strings.Contains(errOut, "--keychain") {
		t.Fatalf("--value-stdin without --keychain: exit %d, %q", code, errOut)
	}
	if _, errOut, code := run("\n", "add", "NEW_KEY", "--keychain", "--value-stdin"); code != ExitUsage || !strings.Contains(errOut, "one line") {
		t.Fatalf("an empty value: exit %d, %q", code, errOut)
	}
	out, errOut, code := run(backendToken+"\n", "add", "NEW_KEY", "--keychain", "--value-stdin", "--allow", "gh", "--clients", "none")
	if code != 0 || stored != backendToken || strings.Contains(out+errOut, backendToken) {
		t.Fatalf("add: exit %d, %q %q", code, out, errOut)
	}
	data, _ := os.ReadFile(filepath.Join(dir, "config.toml"))
	if !strings.Contains(string(data), "[secrets.NEW_KEY]\nref = \"keychain://passess/NEW_KEY\"\nallow = [\"gh\"]\nclients = []\n") ||
		strings.Contains(string(data), backendToken) {
		t.Fatalf("config:\n%s", data)
	}

	// An agent piping a value in is refused before stdin is read.
	stored = ""
	t.Setenv("CLAUDECODE", "1")
	if _, _, code := run(backendToken, "add", "OTHER", "--keychain", "--value-stdin"); code != ExitNoPerm || stored != "" {
		t.Fatalf("under an agent: exit %d, stored %q", code, stored)
	}
}
