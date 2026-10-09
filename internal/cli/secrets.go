package cli

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/afsharid/passess/internal/config"
	"github.com/afsharid/passess/internal/detect"
	"github.com/afsharid/passess/internal/harness"
)

func init() {
	commands["set"] = command{"change who may use a secret: the coding agents it is connected to, approvals, its note", runSet}
	commands["remove"] = command{"remove a secret from passess (the vault keeps it)", runRemove}
}

// clientsLiteral reads --clients: "all" (nil: every coding agent), "none" or
// agent IDs. It returns the TOML array to write, in the order of
// detect.Agents.
func clientsLiteral(v string) (*string, error) {
	switch strings.TrimSpace(v) {
	case "all":
		return nil, nil
	case "none":
		lit := "[]"
		return &lit, nil
	}
	var picked []string
	for _, c := range strings.Split(v, ",") {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		if !detect.IsAgent(c) {
			ids := make([]string, len(detect.Agents))
			for i, a := range detect.Agents {
				ids[i] = a.ID
			}
			return nil, fmt.Errorf("--clients: %q is not a coding agent passess knows (%s), all or none", c, strings.Join(ids, ", "))
		}
		picked = append(picked, c)
	}
	if len(picked) == 0 {
		return nil, errors.New("--clients: name the coding agents, or say all or none")
	}
	var quoted []string
	for _, a := range detect.Agents {
		if slices.Contains(picked, a.ID) {
			quoted = append(quoted, tomlString(a.ID))
		}
	}
	lit := "[" + strings.Join(quoted, ", ") + "]"
	return &lit, nil
}

// whoUses is what add, set and remove do, for their refusals.
const whoUses = "decides who may use which secret"

// lockConfig holds the user config's lock until the returned function runs,
// so that changes from Passess.app and a terminal queue up instead of one
// overwriting the other. The lock is a file of its own: the config is
// replaced by rename, and a lock on the old file would not hold the new one.
func lockConfig(path string) (func(), error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(filepath.Dir(path), "."+filepath.Base(path)+".lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil { //nolint:gosec // G115: a descriptor fits in int
		_ = f.Close()
		return nil, err
	}
	return func() { _ = f.Close() }, nil // closing releases the lock
}

// editUserConfig rewrites the user config with edit, under its lock and after
// a backup, and keeps the result only if it loads.
func editUserConfig(st *Streams, edit func([]byte) ([]byte, error)) (string, int) {
	path, err := config.UserPath(st.Getenv)
	if err != nil {
		return "", failf(st, ExitConfig, "%v", err)
	}
	unlock, err := lockConfig(path)
	if err != nil {
		return "", failf(st, ExitConfig, "locking %s: %v", path, err)
	}
	defer unlock()
	before, err := os.ReadFile(path)
	if err != nil {
		return "", failf(st, ExitConfig, "%v", err)
	}
	if _, err := config.ParseUser(path, before); err != nil {
		return "", failf(st, ExitConfig, "%v", err)
	}
	after, err := edit(before)
	if err != nil {
		return "", failf(st, ExitConfig, "%v", err)
	}
	if _, err := config.ParseUser(path, after); err != nil {
		return "", failf(st, ExitConfig, "the change would leave the config invalid, so it was not made: %v", err)
	}
	if _, err := harness.Backup(filepath.Join(stateDir(st.Getenv), "backups"), []string{path}, time.Now()); err != nil {
		return "", failf(st, ExitSoftware, "backing up %s failed, so it was not changed: %v", path, err)
	}
	if err := writeFileAtomic(path, after, 0o600); err != nil {
		return "", failf(st, ExitConfig, "%v", err)
	}
	return path, 0
}

func runSet(st *Streams, args []string) int {
	fs := flag.NewFlagSet("set", flag.ContinueOnError)
	fs.SetOutput(st.Stderr)
	clients := fs.String("clients", "", "coding agents it is connected to: IDs comma-separated (claude-code,codex), all, or none")
	approve := fs.String("approve", "", "true: every new program and caller waits for your Allow; false: no approval")
	note := fs.String("note", "", "free-text note (an empty value removes it)")
	fs.Usage = func() {
		fmt.Fprintln(st.Stderr, "Usage: passess set NAME [--clients claude-code,codex|all|none] [--approve true|false] [--note TEXT]")
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
	given := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { given[f.Name] = true })
	if len(given) == 0 {
		fs.Usage()
		return ExitUsage
	}
	var fields []config.Field
	if given["clients"] {
		lit, err := clientsLiteral(*clients)
		if err != nil {
			return failf(st, ExitUsage, "%v", err)
		}
		fields = append(fields, config.Field{Key: "clients", Value: lit})
	}
	if given["approve"] {
		on, err := strconv.ParseBool(*approve)
		if err != nil {
			return failf(st, ExitUsage, "--approve takes true or false")
		}
		var lit *string // false is the default: no key
		if on {
			t := "true"
			lit = &t
		}
		fields = append(fields, config.Field{Key: "approve", Value: lit})
	}
	if given["note"] {
		if strings.ContainsAny(*note, "\n\r\x00") {
			return failf(st, ExitUsage, "--note must be one line")
		}
		var lit *string
		if *note != "" {
			q := tomlString(*note)
			lit = &q
		}
		fields = append(fields, config.Field{Key: "note", Value: lit})
	}
	if code := refuseUnderAgent(st, "set", whoUses); code != 0 {
		return code
	}
	path, code := editUserConfig(st, func(data []byte) ([]byte, error) {
		if u, err := config.ParseUser("", data); err == nil {
			if _, ok := u.Secrets[name]; !ok {
				return nil, fmt.Errorf("%s is not defined; add it first", name)
			}
		}
		return config.SetSecretFields(data, name, fields)
	})
	if code != 0 {
		return code
	}
	fmt.Fprintf(st.Stdout, "updated %s in %s\n", name, path)
	return ExitOK
}

func runRemove(st *Streams, args []string) int {
	if len(args) != 1 || strings.HasPrefix(args[0], "-") {
		fmt.Fprintln(st.Stderr, "Usage: passess remove NAME   (passess forgets the reference; the vault keeps the secret)")
		return ExitUsage
	}
	name := args[0]
	if code := refuseUnderAgent(st, "remove", whoUses); code != 0 {
		return code
	}
	path, code := editUserConfig(st, func(data []byte) ([]byte, error) {
		u, err := config.ParseUser("", data)
		if err != nil {
			return nil, err
		}
		if _, ok := u.Secrets[name]; !ok {
			return nil, fmt.Errorf("%s is not defined", name)
		}
		var users []string
		for _, p := range sortedKeys(u.Profiles) {
			if contains(u.Profiles[p].Secrets, name) {
				users = append(users, "profile "+p)
			}
		}
		for _, m := range sortedKeys(u.MCP) {
			if contains(u.MCP[m].Secrets(), name) {
				users = append(users, "MCP server "+m)
			}
		}
		if len(users) > 0 {
			return nil, fmt.Errorf("%s is used by %s; take it out of those first", name, strings.Join(users, ", "))
		}
		return config.RemoveSecret(data, name)
	})
	if code != 0 {
		return code
	}
	fmt.Fprintf(st.Stdout, "removed %s from %s; the vault still holds it\n", name, path)
	return ExitOK
}
