package cli

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/afsharid/passess/internal/config"
	"github.com/afsharid/passess/internal/ref"
)

func init() {
	commands["add"] = command{"define a secret by reference, or store one in the OS keychain", runAdd}
}

type listFlag []string

func (l *listFlag) String() string { return strings.Join(*l, ",") }
func (l *listFlag) Set(v string) error {
	for _, p := range strings.Split(v, ",") {
		if p = strings.TrimSpace(p); p != "" {
			*l = append(*l, p)
		}
	}
	return nil
}

func runAdd(st *Streams, args []string) int {
	fs := flag.NewFlagSet("add", flag.ContinueOnError)
	fs.SetOutput(st.Stderr)
	var refs, allow listFlag
	fs.Var(&refs, "ref", "reference such as op://vault/item/field (repeatable: candidates in order)")
	fs.Var(&allow, "allow", "programs that may receive it, comma-separated")
	note := fs.String("note", "", "free-text note")
	keychain := fs.Bool("keychain", false, "prompt for the value in this terminal and store it in the OS keychain")
	clients := fs.String("clients", "all", "coding agents it is connected to: IDs comma-separated (claude-code,codex), all, or none")
	approve := fs.Bool("approve", false, "every new program and caller waits for your Allow")
	fs.Usage = func() {
		fmt.Fprintln(st.Stderr, "Usage: passess add NAME --ref REFERENCE [--allow gh,git] [--clients claude-code,codex] [--approve] [--note TEXT]")
		fmt.Fprintln(st.Stderr, "       passess add NAME --keychain [--allow …]   (you type the value; it never passes through passess)")
		fs.PrintDefaults()
	}
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		fs.Usage()
		return ExitUsage
	}
	name := args[0]
	if err := fs.Parse(args[1:]); err != nil || fs.NArg() > 0 {
		fs.Usage()
		return ExitUsage
	}
	if !envNameRe.MatchString(name) {
		return failf(st, ExitUsage, "%q is not a valid secret name (use letters, digits and _)", name)
	}
	if *keychain == (len(refs) > 0) {
		return failf(st, ExitUsage, "give either --ref or --keychain")
	}
	for _, r := range refs {
		if _, err := ref.Parse(r); err != nil {
			return failf(st, ExitUsage, "--ref: %v", err)
		}
	}
	for _, a := range allow {
		if strings.ContainsAny(a, "/ \t") {
			return failf(st, ExitUsage, "--allow takes program names, not paths")
		}
	}
	if strings.ContainsAny(*note, "\n\r\x00") {
		return failf(st, ExitUsage, "--note must be one line")
	}
	clientsLit, err := clientsLiteral(*clients)
	if err != nil {
		return failf(st, ExitUsage, "%v", err)
	}
	if code := refuseUnderAgent(st, "add", whoUses); code != 0 {
		return code
	}

	path, err := config.UserPath(st.Getenv)
	if err != nil {
		return failf(st, ExitConfig, "%v", err)
	}
	// read returns the config as it is, refusing a name or reference already
	// taken. It runs before the keychain prompt, to fail fast, and again under
	// the lock, since the file may have changed while the user typed.
	read := func() ([]byte, int) {
		before, err := os.ReadFile(path)
		switch {
		case errors.Is(err, os.ErrNotExist):
			return nil, 0
		case err != nil:
			return nil, failf(st, ExitConfig, "%v", err)
		}
		u, err := config.ParseUser(path, before)
		if err != nil {
			return nil, failf(st, ExitConfig, "%v", err)
		}
		if _, ok := u.Secrets[name]; ok {
			return nil, failf(st, ExitConfig, "%s is already defined; edit it in %s", name, path)
		}
		// A second name for a reference another secret already has would
		// start with an allow list and approval setting of its own choosing.
		if other, r := sameReference(u, refs); other != "" {
			return nil, failf(st, ExitConfig, "%s is already the reference of secrets.%s; to give it to another program, change that secret's allow list in %s", r, other, path)
		}
		return before, 0
	}
	if _, code := read(); code != 0 {
		return code
	}

	if *keychain {
		r, code := storeInKeychain(st, name)
		if code != 0 {
			return code
		}
		refs = listFlag{r}
	}

	unlock, err := lockConfig(path)
	if err != nil {
		return failf(st, ExitConfig, "locking %s: %v", path, err)
	}
	defer unlock()
	before, code := read()
	if code != 0 {
		return code
	}

	block := secretBlock(name, refs, allow, *note)
	if clientsLit != nil {
		block = append(block, "clients = "+*clientsLit+"\n"...)
	}
	if *approve {
		block = append(block, "approve = true\n"...)
	}
	after := before
	if len(after) == 0 {
		after = []byte("version = 1\n")
	}
	if !strings.HasSuffix(string(after), "\n") {
		after = append(after, '\n')
	}
	after = append(after, block...)

	if err := writeFileAtomic(path, after, 0o600); err != nil {
		return failf(st, ExitConfig, "%v", err)
	}
	if _, err := config.LoadUser(path); err != nil {
		_ = writeFileAtomic(path, before, 0o600) // put the file back as it was
		return failf(st, ExitSoftware, "the new entry did not validate, config left unchanged: %v", err)
	}
	fmt.Fprintf(st.Stdout, "added %s to %s\n", name, path)
	return ExitOK
}

// secretBlock renders a [secrets.NAME] table.
func secretBlock(name string, refs, allow []string, note string) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "\n[secrets.%s]\n", name)
	if len(refs) == 1 {
		fmt.Fprintf(&b, "ref = %s\n", tomlString(refs[0]))
	} else {
		quoted := make([]string, len(refs))
		for i, r := range refs {
			quoted[i] = tomlString(r)
		}
		fmt.Fprintf(&b, "ref = [%s]\n", strings.Join(quoted, ", "))
	}
	if len(allow) > 0 {
		quoted := make([]string, len(allow))
		for i, a := range allow {
			quoted[i] = tomlString(a)
		}
		fmt.Fprintf(&b, "allow = [%s]\n", strings.Join(quoted, ", "))
	}
	if note != "" {
		fmt.Fprintf(&b, "note = %s\n", tomlString(note))
	}
	return []byte(b.String())
}

// tomlString quotes s as a TOML basic string. Callers have rejected control
// characters already.
func tomlString(s string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s) + `"`
}

// keychainPrompt is the OS command that asks for a value in the terminal and
// stores it as service "passess", account; nil where there is none. The value
// is typed into that tool, so it never passes through passess or its argv.
func keychainPrompt(account string) []string {
	switch runtime.GOOS {
	case "darwin":
		return []string{"security", "add-generic-password", "-U", "-s", keychainService, "-a", account, "-l", "passess " + account, "-w"}
	case "linux":
		return []string{"secret-tool", "store", "--label", "passess " + account, "service", keychainService, "account", account}
	}
	return nil
}

// shellLine renders argv for a person to paste into a shell.
func shellLine(argv []string) string {
	out := make([]string, len(argv))
	for i, a := range argv {
		if a == "" || strings.ContainsAny(a, " \t'\"$`\\!*?[]{}()<>|&;#~") {
			a = "'" + strings.ReplaceAll(a, "'", `'\''`) + "'"
		}
		out[i] = a
	}
	return strings.Join(out, " ")
}

// storeInKeychain lets the user type the value straight into the OS keychain
// tool; passess never sees it.
func storeInKeychain(st *Streams, name string) (string, int) {
	if len(callerAgents(st.Getenv, selfChain())) > 0 || !isTerminal(st.Stdin) {
		return "", failf(st, ExitNoPerm, "--keychain needs you at a terminal: values should not pass through an agent. Run `passess add %s --keychain` yourself.", name)
	}
	argv := keychainPrompt(name)
	if argv == nil {
		return "", failf(st, ExitUnavailable, "--keychain is supported on macOS and Linux only")
	}
	fmt.Fprintf(st.Stderr, "Type the value for %s (it is stored in the OS keychain as service %q, account %q):\n", name, keychainService, name)
	cmd := exec.Command(argv[0], argv[1:]...) //nolint:gosec // fixed program, arguments are names
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		return "", failf(st, ExitUnavailable, "storing %s in the keychain failed: %v", name, err)
	}
	return "keychain://passess/" + name, 0
}

// writeFileAtomic replaces path with data via a temporary file in the same directory.
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }() // no-op once renamed
	if err := tmp.Chmod(perm); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// sameReference returns a secret that already uses one of refs, and that
// reference, or "".
func sameReference(u *config.User, refs []string) (secret, reference string) {
	for _, raw := range refs {
		r, err := ref.Parse(raw)
		if err != nil {
			continue
		}
		want := r.String()
		for name, s := range u.Secrets {
			for _, have := range s.Refs {
				if have.String() == want {
					return name, want
				}
			}
		}
	}
	return "", ""
}
