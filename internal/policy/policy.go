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
	"slices"
	"strings"
)

// denied lists the families that get no secrets by default.
var denied = map[string]bool{}

// aliases folds names into one family. Every shell is "sh": /bin/sh is dash on
// Debian, bash on Fedora and busybox on Alpine, and allowing "sh" means allowing
// a shell, whichever one it turns out to be.
var aliases = map[string]string{}

// lookups are the names searched on PATH to recognize renamed copies: every
// denied family and every alias of one, built in init so that no denied
// interpreter can be missing from it, plus names a family goes by on PATH.
var lookups []string

// pathNames are names on PATH that are neither a family nor an alias.
var pathNames = strings.Fields(`python3 Rscript`)

func init() {
	for _, f := range strings.Fields(`sh python node deno bun perl ruby php lua tclsh wish expect
		awk osascript jshell rscript julia env printenv base64 base32 xxd od hexdump rev tr jq busybox toybox`) {
		denied[f] = true
	}
	for family, names := range map[string]string{
		"sh":     "bash zsh dash ksh mksh ash csh tcsh fish pwsh powershell nu elvish xonsh",
		"python": "pypy ipython",
		"node":   "nodejs",
		"ruby":   "irb",
		"lua":    "luajit",
		"awk":    "gawk mawk nawk",
	} {
		for _, n := range strings.Fields(names) {
			aliases[n] = family
		}
	}
	seen := map[string]bool{}
	for _, set := range [][]string{pathNames, keys(denied), keys(aliases)} {
		for _, n := range set {
			if !seen[n] {
				seen[n] = true
				lookups = append(lookups, n)
			}
		}
	}
}

// keys returns m's keys in order, so that lookups does not change from run to run.
func keys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

var versionSuffix = regexp.MustCompile(`[-_]?[0-9][0-9.]*$`)

// Family normalizes a program name: lower case, trailing version stripped and
// aliases folded, so python3.14 is python and dash is sh.
func Family(name string) string {
	f := strings.ToLower(filepath.Base(name))
	f = strings.TrimSuffix(f, ".exe")
	if a, ok := aliases[f]; ok {
		return a
	}
	if denied[f] {
		return f // base64 is a name, not "base" version 64
	}
	if stripped := versionSuffix.ReplaceAllString(f, ""); stripped != "" {
		f = stripped
	}
	if a, ok := aliases[f]; ok {
		return a
	}
	return f
}

// multiCall reports whether a family is a multi-call binary whose applet is
// chosen by argv[0].
func multiCall(family string) bool { return family == "busybox" || family == "toybox" }

// Denied reports whether a family is on the default deny list.
func Denied(family string) bool { return denied[family] }

// Program is what a command line would really execute.
type Program struct {
	Typed    string   // argv[0] as given
	Path     string   // resolved absolute path
	Name     string   // basename of Path
	Families []string // Name's family plus any it counts as
	runs     string   // the family the program runs as; see label
	Why      map[string]string

	stamp   fileStamp // the file Inspect judged; see Unchanged
	interps []stamped // the interpreters its #! lines lead to; see Unchanged
}

// stamped is a file Inspect read besides the program itself. written is the
// path the #! line led to, before links were followed: Unchanged resolves it
// again, since a link repointed after the check sends the kernel elsewhere.
// A path that led nowhere is kept with an empty path.
type stamped struct {
	written string
	path    string
	stamp   fileStamp
}

// label is the name a refusal gives for p and the family its allow-list entry
// must match: the applet a multi-call binary runs as, else the file's own.
func (p Program) label() (name, family string) {
	if p.runs == "" {
		return p.Name, Family(p.Name)
	}
	if p.runs == Family(p.Name) {
		return p.Name, p.runs
	}
	return p.runs, p.runs
}

// RunsAs is the family the program runs as: the applet for a multi-call
// binary, else the family of the file's own name. An approval and the audit
// log name a program by it.
func (p Program) RunsAs() string {
	_, family := p.label()
	return family
}

// ErrNotFound means argv[0] could not be found or is not executable.
var ErrNotFound = errors.New("command not found")

// Inspect resolves argv0 with lookPath and works out what it is. A relative
// interpreter on a #! line is taken from the process's working directory.
func Inspect(argv0 string, lookPath func(string) (string, error)) (Program, error) {
	return InspectIn(argv0, "", lookPath)
}

// InspectIn is Inspect for a program that runs in dir: a relative interpreter
// on a #! line is taken from there, as the kernel does. An empty dir means the
// process's working directory.
func InspectIn(argv0, dir string, lookPath func(string) (string, error)) (Program, error) {
	if dir == "" {
		dir = "."
	}
	if abs, err := filepath.Abs(dir); err == nil {
		dir = abs
	}
	in := &inspection{dir: dir, lookPath: lookPath}
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
	// Stamp first: a change while the content below is read shows up later.
	stamp, err := stampOf(resolved)
	if err != nil {
		return Program{}, fmt.Errorf("%w: %s", ErrNotFound, argv0)
	}
	p := Program{Typed: argv0, Path: resolved, Name: filepath.Base(resolved), Why: map[string]string{}, stamp: stamp}
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
	typed, own := Family(argv0), Family(p.Name)
	if multiCall(own) && !multiCall(typed) && in.systemApplet(filepath.Base(argv0), resolved) {
		own = typed // busybox runs the applet argv[0] names, for a name the system installs it under
	}
	p.runs = own
	add(own, "")
	if typed != own {
		add(typed, "")
	}
	p.interpreters(in, resolved, add, 0)
	if f, orig := in.copyOf(resolved); f != "" {
		add(f, fmt.Sprintf("is a copy of %s", orig))
	}
	return p, nil
}

// inspection holds what one Inspect call looks up more than once: the
// directory relative paths start from, and the installed interpreters a file
// is compared with.
type inspection struct {
	dir      string
	lookPath func(string) (string, error)
	refs     []installedFile
	refsDone bool
}

// installedFile is an installed interpreter a file may be a copy of.
type installedFile struct {
	family string
	path   string
	info   os.FileInfo
	sum    []byte // of the content, read when a file of the same size asks
}

// abs makes a path from a #! line absolute against the run directory.
func (in *inspection) abs(p string) string {
	if !filepath.IsAbs(p) {
		p = filepath.Join(in.dir, p)
	}
	return p
}

// maxShebangDepth bounds how many #! hops Inspect follows: a script whose
// interpreter is a script whose interpreter is a script. Linux follows five.
const maxShebangDepth = 5

// interpreters adds the family of every interpreter the #! line of path leads
// to. It judges the file the line names, not the name: a copy or a link of a
// shell under another name is that shell, and a script named there is judged
// by its own #! line in turn. The files are stamped for Unchanged.
func (p *Program) interpreters(in *inspection, path string, add func(f, why string), depth int) {
	line, viaEnv := shebang(path)
	for _, interp := range line {
		name := filepath.Base(interp)
		add(Family(name), fmt.Sprintf("runs under %s", name))
		target := interp
		if viaEnv && !strings.Contains(interp, "/") {
			t, err := in.lookPath(interp) // env searches PATH for it
			if err != nil {
				continue
			}
			target = t
		}
		target = in.abs(target)
		resolved, err := filepath.EvalSymlinks(target)
		if err != nil {
			p.interps = append(p.interps, stamped{written: target}) // Unchanged notices it appearing
			continue
		}
		if abs, err := filepath.Abs(resolved); err == nil {
			resolved = abs
		}
		if resolved == path {
			continue
		}
		if stamp, err := stampOf(resolved); err == nil {
			p.interps = append(p.interps, stamped{target, resolved, stamp})
		}
		// A multi-call binary the system installs under the name the #! line
		// wrote runs that applet: /bin/cat that is busybox is cat. Under any
		// other name it stays the multi-call binary.
		if rf := Family(filepath.Base(resolved)); rf != Family(name) && (!multiCall(rf) || !in.systemApplet(name, resolved)) {
			add(rf, fmt.Sprintf("runs under %s", name))
		}
		if !in.systemInterpreter(resolved) {
			if f, orig := in.copyOf(resolved); f != "" {
				add(f, fmt.Sprintf("runs under %s, a copy of %s", name, orig))
			}
		}
		if depth < maxShebangDepth {
			p.interpreters(in, resolved, add, depth+1)
		}
	}
}

// systemApplet reports whether the system installs the file at resolved under
// name, as it does each applet of a multi-call binary.
func (in *inspection) systemApplet(name, resolved string) bool {
	st, err := os.Stat(resolved)
	return err == nil && installedAs(name, st)
}

// systemInterpreter reports whether path is a denied interpreter the system
// itself installs under its own name, such as /bin/sh. Its family is already
// on the program, and it is no copy of another, so comparing its content is
// left out.
func (in *inspection) systemInterpreter(path string) bool {
	name := filepath.Base(path)
	if !Denied(Family(name)) {
		return false
	}
	st, err := os.Stat(path)
	return err == nil && installedAs(name, st)
}

// shebang returns the interpreters named on a script's #! line, as written.
// For "#!/usr/bin/env X" that is X: env only launches it there, and it reports
// true because env searches PATH for a name without a slash. A name written
// straight on the line is opened by the kernel relative to the run directory.
// When env's options are not understood the line names env itself, which is
// denied.
func shebang(path string) ([]string, bool) {
	f, err := os.Open(path)
	if err != nil {
		return nil, false
	}
	defer f.Close()
	line, _ := bufio.NewReader(io.LimitReader(f, 512)).ReadString('\n')
	if !strings.HasPrefix(line, "#!") {
		return nil, false
	}
	fields := strings.Fields(strings.TrimPrefix(line, "#!"))
	if len(fields) == 0 {
		return nil, false
	}
	if filepath.Base(fields[0]) == "env" {
		if cmd, ok := envCommand(fields[1:]); ok {
			return cmd, true
		}
	}
	return []string{fields[0]}, false
}

// envCommand finds the command env would run for args, as written; with -P
// that is one path per directory it would search. It knows which options take
// a value (-u, -P, -C and the string after -S, glued or not), so that
// "env -u FOO sh" names sh and not FOO. It reports false for anything it does
// not understand, or when it finds no command: the caller then judges env.
func envCommand(args []string) ([]string, bool) {
	var altPath []string // -P: env looks here instead of on PATH
	chdir := false       // -C: the command starts in another directory
	for len(args) > 0 {
		arg := args[0]
		args = args[1:]
		if arg == "--" {
			if len(args) == 0 {
				return nil, false
			}
			arg, args = args[0], args[1:]
		} else if strings.HasPrefix(arg, "-") && arg != "-" {
			// value returns an option's argument: glued to it, or the next word.
			value := func(glued string) (string, bool) {
				if glued != "" {
					return glued, true
				}
				if len(args) == 0 {
					return "", false
				}
				v := args[0]
				args = args[1:]
				return v, true
			}
			if long, isLong := strings.CutPrefix(arg, "--"); isLong {
				name, glued, hasValue := strings.Cut(long, "=")
				switch name {
				case "ignore-environment", "null", "debug":
					if hasValue {
						return nil, false
					}
				case "unset", "chdir", "split-string":
					v, ok := value(glued)
					if !ok || (hasValue && glued == "") {
						return nil, false
					}
					switch name {
					case "chdir":
						chdir = true
					case "split-string":
						rest, ok := splitString(v)
						if !ok {
							return nil, false
						}
						args = append(rest, args...)
					}
				default:
					return nil, false
				}
				continue
			}
			for i, c := range arg[1:] {
				if c == 'i' || c == '0' || c == 'v' {
					continue
				}
				if c != 'u' && c != 'P' && c != 'C' && c != 'S' {
					return nil, false
				}
				v, ok := value(arg[1+i+1:])
				if !ok {
					return nil, false
				}
				switch c {
				case 'P':
					altPath = filepath.SplitList(v)
				case 'C':
					chdir = true
				case 'S':
					rest, ok := splitString(v)
					if !ok {
						return nil, false
					}
					args = append(rest, args...)
				}
				break
			}
			continue
		}
		if strings.Contains(arg, "=") {
			continue // NAME=value sets a variable
		}
		if !strings.Contains(arg, "/") {
			if altPath == nil {
				return []string{arg}, true
			}
			var out []string
			for _, d := range altPath {
				if d == "" {
					d = "."
				}
				out = append(out, d+"/"+arg)
			}
			return out, len(out) > 0
		}
		if chdir && !filepath.IsAbs(arg) {
			return nil, false // relative to a directory this does not know
		}
		return []string{arg}, true
	}
	return nil, false
}

// splitString splits the string of env -S into words. Quotes, escapes and
// variables are not understood: it reports false for them.
func splitString(s string) ([]string, bool) {
	if strings.ContainsAny(s, "\"'\\$#") {
		return nil, false
	}
	return strings.Fields(s), true
}

// referenceDirs are searched for the real interpreters whatever PATH says.
// The caller chooses PATH, and a PATH that finds no sh would otherwise leave
// nothing to compare a renamed copy of sh against.
var referenceDirs = []string{"/bin", "/usr/bin", "/usr/local/bin", "/opt/homebrew/bin", "/sbin", "/usr/sbin",
	"/home/linuxbrew/.linuxbrew/bin"}

// references lists where name is installed: on the caller's PATH and in dirs
// (the existing ones of referenceDirs), each resolved through symlinks,
// without repeats.
func references(name string, dirs []string, lookPath func(string) (string, error)) []string {
	var out []string
	add := func(p string) {
		if resolved, err := filepath.EvalSymlinks(p); err == nil {
			p = resolved
		}
		if !slices.Contains(out, p) {
			out = append(out, p)
		}
	}
	if p, err := lookPath(name); err == nil {
		add(p)
	}
	for _, d := range dirs {
		p := filepath.Join(d, name)
		if st, err := os.Stat(p); err == nil && st.Mode().IsRegular() {
			add(p)
		}
	}
	return out
}

// installedAs reports whether the system installs st under name: an entry in
// referenceDirs by that name is st itself. Only the system writes there, so
// a file the caller copied or renamed does not pass.
func installedAs(name string, st os.FileInfo) bool {
	for _, d := range referenceDirs {
		if rst, err := os.Stat(filepath.Join(d, name)); err == nil && os.SameFile(st, rst) {
			return true
		}
	}
	return false
}

// index lists the installed interpreters once per Inspect call.
func (in *inspection) index() []installedFile {
	if in.refsDone {
		return in.refs
	}
	in.refsDone = true
	var dirs []string // one stat each: a missing directory costs the same for every name
	for _, d := range referenceDirs {
		if _, err := os.Stat(d); err == nil {
			dirs = append(dirs, d)
		}
	}
	for _, name := range lookups {
		for _, orig := range references(name, dirs, in.lookPath) {
			if ost, err := os.Stat(orig); err == nil {
				in.refs = append(in.refs, installedFile{family: Family(name), path: orig, info: ost})
			}
		}
	}
	return in.refs
}

// copyOf reports whether path is the same file as, or byte-identical to, a
// denied interpreter found on PATH or in referenceDirs.
//
// A multi-call binary the system installs under many names (uutils
// coreutils: sleep, ls and base32 are one file) runs the applet its name
// says, so the system's own sleep is not a copy of base32. That holds only
// for one file the system links under both names: a byte-identical copy, or
// a link under a name the system does not install it as, still counts.
func (in *inspection) copyOf(path string) (family, original string) {
	st, err := os.Stat(path)
	if err != nil || !st.Mode().IsRegular() {
		return "", ""
	}
	system := installedAs(filepath.Base(path), st)
	var sum []byte
	refs := in.index()
	for i := range refs {
		r := &refs[i]
		if r.path == path || r.info.Size() != st.Size() {
			continue // the first is the interpreter itself; its name already says so
		}
		if os.SameFile(st, r.info) {
			if system && installedAs(filepath.Base(r.path), r.info) {
				continue // one multi-call binary under two system names
			}
			return r.family, r.path
		}
		if sum == nil {
			sum = hashFile(path)
		}
		if r.sum == nil {
			r.sum = hashFile(r.path)
		}
		if sum != nil && bytes.Equal(sum, r.sum) {
			return r.family, r.path
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
// slice means nothing is allowed, and a project cannot widen that: only a
// nil side gives way to the other, an empty one intersects to nothing.
//
// With no list of the user's own, the project's list stands in for it, but
// Check reads a listed family as allowed even when the default policy denies
// it. A project is never the user's word, so denied families drop out of its
// list: it cannot hand a shell, an interpreter or an encoder a secret.
func Effective(user, project []string) []string {
	if user == nil && project != nil {
		kept := []string{}
		for _, p := range project {
			if !Denied(Family(p)) {
				kept = append(kept, p)
			}
		}
		return kept
	}
	return Combine(user, project)
}

// Combine intersects two allow lists the user wrote, such as a secret's and a
// profile's, by family. Nil gives way to the other list. It does not filter
// denied families: the user may allow them. A project's list goes through
// Effective instead.
func Combine(user, other []string) []string {
	if other == nil {
		return user
	}
	if user == nil {
		return other
	}
	both := []string{}
	for _, p := range other {
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

// CheckConfigured judges a program the user configured themselves, such as an
// MCP server's command: no agent chose it, so the default refusal of shells and
// interpreters does not apply (npx and uvx are how most servers start), but an
// explicit allow list on the secret still does.
func CheckConfigured(secret string, p Program, allow []string) Decision {
	if allow == nil {
		return Decision{Allowed: true}
	}
	for _, a := range allow {
		if reserved(a) {
			continue
		}
		for _, f := range p.Families {
			if Family(a) == f {
				return Decision{Allowed: true}
			}
		}
	}
	name, family := p.label()
	return Decision{Family: family, Reason: fmt.Sprintf(
		"%s is not in the allow list of %s (%s)", name, secret, strings.Join(allow, ", "))}
}

// ReservedFamily is not a program: in an allow list it lets `passess helper`
// print the secret for a harness's key-helper setting. It never authorizes a
// program, whatever that program is called, or naming a binary
// "passess-helper" would turn the opt-in into an exec target.
const ReservedFamily = "passess-helper"

func reserved(a string) bool { return a == ReservedFamily || Family(a) == ReservedFamily }

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
		if !reserved(a) {
			allowed[Family(a)] = true
		}
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
	if name, family := p.label(); allow != nil && !allowed[family] {
		return Decision{Family: family, Reason: fmt.Sprintf(
			"%s is not in the allow list of %s (%s)", name, secret, strings.Join(allow, ", "))}
	}
	return Decision{Allowed: true}
}
