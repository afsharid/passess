package provider

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/afsharid/passess/internal/ref"
	"github.com/afsharid/passess/internal/secret"
)

const fakeValue = "passess-fake-keychain-0123456789"

// fakeRunner answers by command line.
type fakeRunner struct {
	calls []Cmd
	reply func(c Cmd) (Result, error)
}

func (f *fakeRunner) Run(_ context.Context, c Cmd) (Result, error) {
	f.calls = append(f.calls, c)
	return f.reply(c)
}

func mustRef(t *testing.T, s string) ref.Ref {
	t.Helper()
	r, err := ref.Parse(s)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// contract checks what every provider must do: resolve the known reference to
// its value, report a missing one as ErrNotFound, and never put a value in an
// error.
func contract(t *testing.T, p Provider, found ref.Ref, want string, missing ref.Ref) {
	t.Helper()
	ctx := context.Background()
	if err := p.Available(ctx); err != nil {
		t.Fatalf("Available: %v", err)
	}
	v, err := p.Resolve(ctx, found)
	if err != nil {
		t.Fatalf("Resolve(%s): %v", found, err)
	}
	if string(v.Bytes()) != want {
		t.Fatalf("Resolve(%s) returned the wrong value", found)
	}
	_, err = p.Resolve(ctx, missing)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("Resolve(%s) = %v, want ErrNotFound", missing, err)
	}
	var perr *Error
	if !errors.As(err, &perr) || !perr.Ref.Equal(missing) {
		t.Fatalf("error does not name the reference: %v", err)
	}
	if strings.Contains(err.Error(), want) {
		t.Fatalf("error contains a value: %v", err)
	}
}

func TestEnvContract(t *testing.T) {
	env := map[string]string{"PASSESS_TEST_TOKEN": fakeValue, "EMPTY": ""}
	p := Env{Lookup: func(k string) (string, bool) { v, ok := env[k]; return v, ok }}
	contract(t, p, mustRef(t, "env://PASSESS_TEST_TOKEN"), fakeValue, mustRef(t, "env://NOT_SET"))
	if _, err := p.Resolve(context.Background(), mustRef(t, "env://EMPTY")); !errors.Is(err, ErrNotFound) {
		t.Fatalf("empty variable must count as not found, got %v", err)
	}
}

func keychainFake() *fakeRunner {
	return &fakeRunner{reply: func(c Cmd) (Result, error) {
		switch {
		case c.Name == "security" && slices.Contains(c.Args, "passess") && slices.Contains(c.Args, "bws"):
			return Result{Stdout: []byte(fakeValue + "\n")}, nil
		case c.Name == "security":
			return Result{Exit: 44, Stderr: []byte("security: SecKeychainSearchCopyNext: The specified item could not be found in the keychain.")}, nil
		case c.Name == "secret-tool" && slices.Contains(c.Args, "passess") && slices.Contains(c.Args, "bws"):
			return Result{Stdout: []byte(fakeValue)}, nil
		case c.Name == "secret-tool":
			return Result{Exit: 1}, nil
		}
		return Result{}, fmt.Errorf("unexpected command %s", c.Name)
	}}
}

func TestKeychainContract(t *testing.T) {
	getenv := func(k string) string {
		return map[string]string{"PATH": "/usr/bin", "HOME": "/Users/x", "SECRET_TOKEN": "nope"}[k]
	}
	for _, goos := range []string{"darwin", "linux"} {
		t.Run(goos, func(t *testing.T) {
			run := keychainFake()
			p := Keychain{Runner: run, Getenv: getenv, GOOS: goos}
			contract(t, p, mustRef(t, "keychain://passess/bws"), fakeValue, mustRef(t, "keychain://passess/missing"))
			c := run.calls[0]
			if goos == "darwin" && !slices.Equal(c.Args, []string{"find-generic-password", "-s", "passess", "-a", "bws", "-w"}) {
				t.Fatalf("security args = %q", c.Args)
			}
			if goos == "linux" && !slices.Equal(c.Args, []string{"lookup", "service", "passess", "account", "bws"}) {
				t.Fatalf("secret-tool args = %q", c.Args)
			}
			for _, kv := range c.Env {
				if strings.HasPrefix(kv, "SECRET_TOKEN=") {
					t.Fatal("backend CLI must not inherit unrelated variables")
				}
			}
		})
	}
	if err := (Keychain{GOOS: "windows"}).Available(context.Background()); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("windows: %v", err)
	}
}

func TestKeychainFailureIsSanitized(t *testing.T) {
	run := &fakeRunner{reply: func(Cmd) (Result, error) {
		return Result{Exit: 51, Stderr: []byte("security: failed with token passess-fake-echoed-credential-0123456789 attached\n")}, nil
	}}
	_, err := Keychain{Runner: run, GOOS: "darwin"}.Resolve(context.Background(), mustRef(t, "keychain://passess/bws"))
	if err == nil || errors.Is(err, ErrNotFound) {
		t.Fatalf("want a plain failure, got %v", err)
	}
	if strings.Contains(err.Error(), "passess-fake-echoed") {
		t.Fatalf("CLI output leaked into the error: %v", err)
	}
	if !strings.Contains(err.Error(), "exited 51") {
		t.Fatalf("error lacks the exit status: %v", err)
	}
}

// TestKeychainLive writes a random canary into the real login keychain,
// resolves it through security(1) and deletes it. Opt in with
// PASSESS_LIVE_KEYCHAIN=1 on macOS.
func TestKeychainLive(t *testing.T) {
	if os.Getenv("PASSESS_LIVE_KEYCHAIN") != "1" || runtime.GOOS != "darwin" {
		t.Skip("set PASSESS_LIVE_KEYCHAIN=1 on macOS to run")
	}
	raw := make([]byte, 16)
	_, _ = rand.Read(raw)
	canary := "passess-fake-canary-" + hex.EncodeToString(raw)
	account := "canary-" + hex.EncodeToString(raw[:4])
	add := exec.Command("security", "add-generic-password", "-s", "passess-test", "-a", account, "-w", canary)
	if out, err := add.CombinedOutput(); err != nil {
		t.Fatalf("add: %v %s", err, out)
	}
	t.Cleanup(func() {
		_ = exec.Command("security", "delete-generic-password", "-s", "passess-test", "-a", account).Run()
	})

	p := Keychain{Runner: ExecRunner{}}
	contract(t, p, mustRef(t, "keychain://passess-test/"+account), canary, mustRef(t, "keychain://passess-test/absent-"+account))

	// Store goes through stdin; quotes, backslashes and spaces must survive.
	stored := `passess-fake "quoted" \back\slash ` + hex.EncodeToString(raw[4:8])
	storeAcct := "store-" + hex.EncodeToString(raw[:4])
	t.Cleanup(func() {
		_ = exec.Command("security", "delete-generic-password", "-s", "passess-test", "-a", storeAcct).Run()
	})
	if err := p.Store(context.Background(), "passess-test", storeAcct, secret.FromString(stored)); err != nil {
		t.Fatalf("Store: %v", err)
	}
	v, err := p.Resolve(context.Background(), mustRef(t, "keychain://passess-test/"+storeAcct))
	if err != nil || string(v.Bytes()) != stored {
		t.Fatalf("stored value did not round-trip: %v", err)
	}
}

func TestKeychainStoreKeepsValueOffArgv(t *testing.T) {
	var got Cmd
	run := &fakeRunner{reply: func(c Cmd) (Result, error) {
		if c.Args[0] == "-i" {
			got = c
			got.Stdin = bytes.Clone(c.Stdin) // Store clears its buffer afterwards
			return Result{}, nil
		}
		return Result{Stdout: []byte(fakeValue + "\n")}, nil
	}}
	p := Keychain{Runner: run, GOOS: "darwin"}
	if err := p.Store(context.Background(), "passess", "demo", secret.FromString(fakeValue)); err != nil {
		t.Fatal(err)
	}
	for _, a := range got.Args {
		if strings.Contains(a, fakeValue) {
			t.Fatal("the value reached argv")
		}
	}
	if !strings.Contains(string(got.Stdin), `-w "`+fakeValue+`"`) {
		t.Fatalf("stdin = %q", got.Stdin)
	}
	// Only names that need no quoting reach security(1)'s parser.
	for _, bad := range []string{`with "quote`, "with space", `back\slash`, "", "tab\there"} {
		if err := p.Store(context.Background(), "passess", bad, secret.FromString(fakeValue)); err == nil {
			t.Fatalf("stored under account %q", bad)
		}
	}
	if err := p.Store(context.Background(), "passess", "bad/name", secret.FromString(fakeValue)); err == nil {
		t.Fatal("a slash in the account was accepted")
	}
	if err := p.Store(context.Background(), "passess", "demo", secret.FromString("two\nlines-passess-fake")); err == nil {
		t.Fatal("a multi-line value was accepted")
	}
}
