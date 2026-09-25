// Package policy decides which programs may receive which secrets.
//
// Shells, interpreters and encoders get no secret unless its allow list names
// them (ADR 4), because they turn "print the value transformed" into a one-liner
// the redactor cannot recognize. The check is about the program that would
// actually run: symlinks are resolved, a script is judged by its interpreter,
// and a byte-identical copy of a denied interpreter counts as that interpreter.
package policy

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// denied lists program families that get no secrets by default.
var denied = map[string]bool{}

func init() {
	for _, f := range strings.Fields(`
		sh bash zsh fish dash ksh mksh csh tcsh ash busybox pwsh powershell nu elvish xonsh
		python pypy node nodejs deno bun perl ruby irb php lua luajit tclsh wish expect
		awk gawk mawk nawk osascript jshell rscript julia
		env printenv base64 base32 xxd od hexdump rev tr jq`) {
		denied[f] = true
	}
}

var versionSuffix = regexp.MustCompile(`[-_]?[0-9][0-9.]*$`)

// Family normalizes a program name: lower case, trailing version stripped, so
// python3.14, python3 and python are one family.
func Family(name string) string {
	f := strings.ToLower(filepath.Base(name))
	f = strings.TrimSuffix(f, ".exe")
	if denied[f] {
		return f // base64 is a name, not "base" version 64
	}
	if stripped := versionSuffix.ReplaceAllString(f, ""); stripped != "" {
		f = stripped
	}
	return f
}

// Denied reports whether a family is on the default deny list.
func Denied(family string) bool { return denied[family] }

// Program is what a command line would really execute.
type Program struct {
	Typed    string   // argv[0] as given
	Path     string   // resolved absolute path
	Name     string   // basename of Path
	Families []string // Name's family plus any it counts as
	Why      map[string]string
}

// ErrNotFound means argv[0] could not be found or is not executable.
var ErrNotFound = errors.New("command not found")

// Inspect resolves argv0 with lookPath and works out what it is.
func Inspect(argv0 string, lookPath func(string) (string, error)) (Program, error) {
	path, err := lookPath(argv0)
	if err != nil {
		return Program{}, fmt.Errorf("%w: %s", ErrNotFound, argv0)
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return Program{}, fmt.Errorf("%w: %s", ErrNotFound, argv0)
	}
	if abs, err := filepath.Abs(resolved); err == nil {
		resolved = abs
	}
	p := Program{Typed: argv0, Path: resolved, Name: filepath.Base(resolved), Why: map[string]string{}}
	add := func(f, why string) {
		for _, have := range p.Families {
			if have == f {
				return
			}
		}
		p.Families = append(p.Families, f)
		if why != "" {
			p.Why[f] = why
		}
	}
	add(Family(p.Name), "")
	if typed := Family(argv0); typed != Family(p.Name) {
		add(typed, "")
	}
	for _, interp := range shebang(resolved) {
		add(Family(interp), fmt.Sprintf("runs under %s", interp))
	}
	if f, orig := copyOf(resolved, lookPath); f != "" {
		add(f, fmt.Sprintf("is a copy of %s", orig))
	}
	return p, nil
}

// shebang returns the interpreter named on a script's #! line. For
// "#!/usr/bin/env X" that is X: env only launches it there.
func shebang(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	line, _ := bufio.NewReader(io.LimitReader(f, 512)).ReadString('\n')
	if !strings.HasPrefix(line, "#!") {
		return nil
	}
	fields := strings.Fields(strings.TrimPrefix(line, "#!"))
	if len(fields) == 0 {
		return nil
	}
	interp := filepath.Base(fields[0])
	if interp == "env" {
		for _, arg := range fields[1:] {
			if strings.HasPrefix(arg, "-") || strings.Contains(arg, "=") {
				continue
			}
			return []string{filepath.Base(arg)}
		}
	}
	return []string{interp}
}

// copyOf reports whether path is the same file as, or byte-identical to, a
// denied interpreter found on PATH.
func copyOf(path string, lookPath func(string) (string, error)) (family, original string) {
	st, err := os.Stat(path)
	if err != nil || !st.Mode().IsRegular() {
		return "", ""
	}
	var sum []byte
	for f := range denied {
		orig, err := lookPath(f)
		if err != nil {
			continue
		}
		if resolved, err := filepath.EvalSymlinks(orig); err == nil {
			orig = resolved
		}
		if orig == path {
			continue // it is the interpreter itself; its name already says so
		}
		ost, err := os.Stat(orig)
		if err != nil || ost.Size() != st.Size() {
			continue
		}
		if os.SameFile(st, ost) {
			return f, orig
		}
		if sum == nil {
			sum = hashFile(path)
		}
		if sum != nil && bytes.Equal(sum, hashFile(orig)) {
			return f, orig
		}
	}
	return "", ""
}

func hashFile(path string) []byte {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return nil
	}
	return h.Sum(nil)
}

// Effective combines the user's allow list with a project's narrowing. Nil
// means "any program the default policy does not deny"; an empty non-nil
// slice means nothing is allowed.
func Effective(user, project []string) []string {
	if len(project) == 0 {
		return user
	}
	if len(user) == 0 {
		return project
	}
	both := []string{}
	for _, p := range project {
		for _, u := range user {
			if Family(p) == Family(u) {
				both = append(both, p)
				break
			}
		}
	}
	return both
}

// sensitive matches names that end in a credential word. Names that merely
// point at one (TOKEN_FILE, GOOGLE_APPLICATION_CREDENTIALS) are left alone.
var sensitive = regexp.MustCompile(`(?i)(^|_)(api_?key|token|secret|password|passwd|private_key|access_key|secret_key|secret_key_base)s?$`)

// Bootstrap names the variables backends read their own credentials from;
// passess may read them but never passes them on.
var Bootstrap = map[string]bool{
	"BWS_ACCESS_TOKEN": true, "BW_SESSION": true, "BW_CLIENTSECRET": true,
	"OP_SERVICE_ACCOUNT_TOKEN": true, "OP_CONNECT_TOKEN": true, "VAULT_TOKEN": true, "BAO_TOKEN": true,
}

// Sensitive reports whether an inherited environment variable looks like it
// carries a credential. Such variables are dropped from a child's environment
// unless passess itself injects them.
func Sensitive(name string) bool { return Bootstrap[name] || sensitive.MatchString(name) }

// Decision is the outcome of Check.
type Decision struct {
	Allowed bool
	Family  string // the family that decided a refusal
	Reason  string
}

// Check decides whether secret may be handed to p under allow (see Effective).
func Check(secret string, p Program, allow []string) Decision {
	allowed := map[string]bool{}
	for _, a := range allow {
		allowed[Family(a)] = true
	}
	for _, f := range p.Families {
		if !Denied(f) || allowed[f] {
			continue
		}
		who := p.Typed
		if how := p.Why[f]; how != "" {
			who = fmt.Sprintf("%s (which %s)", p.Typed, how)
		}
		return Decision{Family: f, Reason: fmt.Sprintf(
			"%s can print or transform its environment, so it gets no secrets unless allowed", who)}
	}
	if allow != nil && !allowed[Family(p.Name)] {
		return Decision{Family: Family(p.Name), Reason: fmt.Sprintf(
			"%s is not in the allow list of %s (%s)", p.Name, secret, strings.Join(allow, ", "))}
	}
	return Decision{Allowed: true}
}
