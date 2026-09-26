// Package hook turns a harness hook event into a decision: refuse the few
// actions that put secret values into an agent's context, and say what to do
// instead. Hooks are a second line of defense (the first is that values never
// reach the agent's environment or files), so the policy is deny-only and
// fails open: anything it cannot parse or does not recognize is allowed.
package hook

import (
	"fmt"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"mvdan.cc/sh/v3/syntax"

	"github.com/afsharid/passess/internal/policy"
	"github.com/afsharid/passess/internal/redact"
	"github.com/afsharid/passess/internal/scan"
	"github.com/afsharid/passess/internal/secret"
)

// Kind is what an event is about, after normalization.
type Kind string

const (
	Shell  Kind = "shell"  // a shell command is about to run
	Read   Kind = "read"   // a file is about to be read
	Write  Kind = "write"  // a file is about to be written
	Prompt Kind = "prompt" // the user submitted a prompt
	Result Kind = "result" // a tool returned output
	Start  Kind = "start"  // a session started
	Other  Kind = "other"
)

// Event is a harness hook event in harness-neutral form.
type Event struct {
	Name     string // the harness's own event name, echoed in replies
	Kind     Kind
	Tool     string   // the harness's tool name, for messages
	Command  string   // Shell
	Paths    []string // Read, Write
	Text     string   // Prompt text, or Result output as text
	Response any      // Result output as the harness shaped it (decoded JSON)
	CWD      string
}

// Verdict is what the policy decided.
type Verdict struct {
	Deny     bool
	Reason   string // for the model, or for the user when a prompt is blocked
	Context  string // to add at session start
	Output   string // Result text with credentials redacted
	Response any    // Result Response with credentials redacted, same shape
	Changed  bool   // the output differs from the event's
}

// Env is what the policy knows about this machine. Secrets are configured
// names only; the hook never resolves a value.
type Env struct {
	Home       string
	Getenv     func(string) string
	Environ    []string // KEY=value pairs of the harness's environment
	Secrets    []string
	ConfigDirs []string // where passess config lives: the default place and the one in use
	StateDir   string   // passess's state, backups included
	// Rules and Known are loaded only for prompts and results; callers
	// memoize them, since a result is redacted string by string.
	Rules func() *scan.Rules
	Known func() *redact.Redactor // credential values in the harness's environment
}

// Decide applies the policy to one event.
func Decide(ev Event, env Env) Verdict {
	switch ev.Kind {
	case Shell:
		if r := checkShell(ev.Command, ev.CWD, env); r != "" {
			return Verdict{Deny: true, Reason: r}
		}
	case Read:
		for _, p := range ev.Paths {
			if why := deniedPath(p, ev.CWD, env); why != "" {
				return Verdict{Deny: true, Reason: readReason(p, why)}
			}
		}
	case Write:
		for _, p := range ev.Paths {
			if inConfig(abs(p, ev.CWD, env.Home), env) {
				return Verdict{Deny: true, Reason: "passess: " + p + " is the passess config, which decides which program receives which secret. " +
					"Changes to it are the user's to make: tell them what you need and let them run `passess add` or edit it themselves."}
			}
		}
	case Prompt:
		if r := pasted(ev.Text, env); r != "" {
			return Verdict{Deny: true, Reason: r}
		}
	case Result:
		if ev.Response != nil {
			if out, changed := redactValue(ev.Response, env); changed {
				return Verdict{Response: out, Changed: true}
			}
			break
		}
		if out, changed := redactOutput(ev.Text, env); changed {
			return Verdict{Output: out, Changed: true}
		}
	case Start:
		return Verdict{Context: startContext(env)}
	}
	return Verdict{}
}

const useInstead = "Run the command that needs a secret with `passess exec -s NAME -- command`; `passess list` shows the names."

// --- files ---

var (
	envFile     = regexp.MustCompile(`^\.env(rc|\..+)?$`)
	envTemplate = regexp.MustCompile(`(?i)\.(example|sample|template|dist|defaults?|schema)$`)
	keyFile     = regexp.MustCompile(`(?i)\.(pem|key|p12|pfx|jks|keystore)$`)
	sshKey      = regexp.MustCompile(`^id_(rsa|dsa|ecdsa|ed25519)(_sk)?$`)
)

// credentialPaths are files under HOME that hold credentials by design or
// harness configs that can hold them in clear.
var credentialPaths = func() []string {
	out := []string{".claude.json", ".codex/config.toml", ".kiro/crew"}
	for _, c := range scan.CredentialFiles {
		out = append(out, c.Path)
	}
	return out
}()

func abs(p, cwd, home string) string {
	switch {
	case p == "~":
		p = home
	case strings.HasPrefix(p, "~/"):
		p = filepath.Join(home, p[2:])
	case !filepath.IsAbs(p) && cwd != "":
		p = filepath.Join(cwd, p)
	}
	return filepath.Clean(p)
}

func inConfig(p string, env Env) bool {
	for _, d := range env.ConfigDirs {
		if d != "" && within(p, d) {
			return true
		}
	}
	return false
}

func within(p, dir string) bool {
	rel, err := filepath.Rel(dir, p)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, "../")
}

// deniedPath says why reading p would expose credentials, or "".
func deniedPath(p, cwd string, env Env) string {
	full := abs(p, cwd, env.Home)
	base := filepath.Base(full)
	switch {
	case envFile.MatchString(strings.TrimRight(base, "*")) && !envTemplate.MatchString(base):
		return "holds secret values"
	case sshKey.MatchString(base) || keyFile.MatchString(base):
		return "is a private key"
	case env.StateDir != "" && within(full, env.StateDir):
		return "is passess's own state; its backups keep the values they replaced"
	}
	for _, c := range credentialPaths {
		if within(full, filepath.Join(env.Home, c)) {
			return "holds credentials"
		}
	}
	return ""
}

func readReason(p, why string) string {
	return fmt.Sprintf("passess: %s %s; reading it puts them into this conversation. %s", p, why, useInstead)
}

// --- shell ---

// Commands that print file contents, by their first argument onward.
var readers = map[string]bool{
	"cat": true, "head": true, "tail": true, "less": true, "more": true, "bat": true, "nl": true, "tac": true,
	"grep": true, "egrep": true, "fgrep": true, "rg": true, "ag": true, "awk": true, "gawk": true, "sed": true,
	"cut": true, "sort": true, "uniq": true, "strings": true, "xxd": true, "od": true, "hexdump": true,
	"base64": true, "base32": true, "jq": true, "yq": true, "diff": true, "cmp": true, "source": true, ".": true,
	"column": true, "fold": true, "pr": true,
}

// Commands whose last argument is a destination: only the others are read.
var copiers = map[string]bool{"cp": true, "scp": true, "rsync": true, "install": true}

// Programs that run the rest of their arguments as a command.
var wrappers = map[string]bool{"sudo": true, "command": true, "builtin": true, "exec": true, "nohup": true,
	"nice": true, "time": true, "doas": true, "caffeinate": true, "stdbuf": true, "timeout": true}

func checkShell(cmd, cwd string, env Env) string {
	file, err := syntax.NewParser(syntax.Variant(syntax.LangBash)).Parse(strings.NewReader(cmd), "")
	if err != nil {
		return "" // not ours to judge; the harness runs what it can
	}
	var reason string
	syntax.Walk(file, func(node syntax.Node) bool {
		if reason != "" {
			return false
		}
		switch n := node.(type) {
		case *syntax.ParamExp:
			if n.Param != nil {
				reason = checkParam(n.Param.Value, env)
			}
		case *syntax.Redirect:
			if n.Op == syntax.RdrIn || n.Op == syntax.RdrInOut {
				if p, ok := literal(n.Word); ok {
					if why := deniedPath(p, cwd, env); why != "" {
						reason = readReason(p, why)
					}
				}
			}
		case *syntax.CallExpr:
			var args []string
			for _, w := range n.Args {
				s, _ := literal(w) // a non-literal word stays "" and matches nothing
				args = append(args, s)
			}
			reason = checkCall(args, cwd, env)
		case *syntax.DeclClause: // export, declare, typeset, local, readonly
			reason = checkDecl(n, env)
		}
		return true
	})
	return reason
}

// checkDecl refuses the forms that print variables: export -p, bare
// declare -x, declare -p NAME for a credential.
func checkDecl(n *syntax.DeclClause, env Env) string {
	if n.Variant == nil {
		return ""
	}
	var flags, names []string
	for _, a := range n.Args {
		switch {
		case a.Naked && a.Name != nil:
			names = append(names, a.Name.Value)
		case a.Naked && a.Value != nil:
			if f, ok := literal(a.Value); ok && strings.HasPrefix(f, "-") {
				flags = append(flags, f)
			}
		default:
			return "" // an assignment: nothing is printed
		}
	}
	cmd := strings.TrimSpace(n.Variant.Value + " " + strings.Join(flags, " "))
	if len(names) == 0 && n.Variant.Value != "local" && n.Variant.Value != "readonly" {
		return fmt.Sprintf("passess: `%s` would print every exported variable, credentials included, into this conversation. "+
			"Print only what you need, such as `printenv PATH`. %s", cmd, useInstead)
	}
	for _, name := range names {
		if slices.Contains(flags, "-p") && (policy.Sensitive(name) || slices.Contains(env.Secrets, name)) {
			return fmt.Sprintf("passess: `%s %s` prints a secret value into this conversation. %s", cmd, name, useInstead)
		}
	}
	return ""
}

// literal is a word's value when it has no expansion in it.
func literal(w *syntax.Word) (string, bool) {
	if w == nil {
		return "", false
	}
	var b strings.Builder
	for _, part := range w.Parts {
		switch p := part.(type) {
		case *syntax.Lit:
			b.WriteString(p.Value)
		case *syntax.SglQuoted:
			b.WriteString(p.Value)
		case *syntax.DblQuoted:
			for _, q := range p.Parts {
				lit, ok := q.(*syntax.Lit)
				if !ok {
					return "", false
				}
				b.WriteString(lit.Value)
			}
		default:
			return "", false
		}
	}
	return b.String(), true
}

func checkParam(name string, env Env) string {
	configured := slices.Contains(env.Secrets, name)
	set := env.Getenv != nil && env.Getenv(name) != ""
	if exposed := policy.Sensitive(name) && set; !configured && !exposed {
		return ""
	}
	return fmt.Sprintf("passess: $%s would put a credential into the command line and this conversation. "+
		"Run the program through passess, which hands the value to it alone: `passess exec -s %s -- program args` "+
		"(without $%s). For an HTTP header, let curl expand it: `passess exec -s %s -- curl --variable %%%s --expand-header 'Authorization: Bearer {{%s}}' URL`.",
		name, name, name, name, name, name)
}

func checkCall(args []string, cwd string, env Env) string {
	for len(args) > 0 && wrappers[filepath.Base(args[0])] {
		args = skipOptions(args[1:])
	}
	if len(args) == 0 || args[0] == "" {
		return ""
	}
	name := filepath.Base(args[0])
	sub := func(i int) string {
		if i < len(args) {
			return args[i]
		}
		return ""
	}
	has := func(flags ...string) bool {
		for _, a := range args[1:] {
			for _, f := range flags {
				if a == f || strings.HasPrefix(a, f+"=") {
					return true
				}
			}
		}
		return false
	}
	dump := func(what string) string {
		return fmt.Sprintf("passess: `%s` would print every variable in this environment, credentials included, into this conversation. "+
			"Print only what you need, such as `printenv PATH`. %s", what, useInstead)
	}
	vault := func(what string) string {
		return fmt.Sprintf("passess: `%s` prints a secret value into this conversation. %s", what, useInstead)
	}
	switch name {
	case "sh", "bash", "zsh", "dash", "ksh":
		for i, a := range args[1:] {
			// -c, -lc, -ec …: the next word is one more command line.
			if len(a) > 1 && a[0] == '-' && a[1] != '-' && strings.ContainsRune(a, 'c') && i+2 < len(args) {
				return checkShell(args[i+2], cwd, env)
			}
		}
	case "eval":
		return checkShell(strings.Join(args[1:], " "), cwd, env)
	case "env":
		rest := args[1:]
		for len(rest) > 0 && (strings.HasPrefix(rest[0], "-") || strings.Contains(rest[0], "=")) {
			if rest[0] == "-u" || rest[0] == "--unset" || rest[0] == "-C" || rest[0] == "--chdir" || rest[0] == "-S" {
				rest = rest[min(2, len(rest)):]
				continue
			}
			rest = rest[1:]
		}
		if len(rest) == 0 {
			return dump("env")
		}
		return checkCall(rest, cwd, env)
	case "printenv":
		if len(args) == 1 {
			return dump("printenv")
		}
		for _, a := range args[1:] {
			if policy.Sensitive(a) || slices.Contains(env.Secrets, a) {
				return vault("printenv " + a)
			}
		}
	case "set":
		if len(args) == 1 {
			return dump("set")
		}
	case "op":
		switch {
		case sub(1) == "read", sub(1) == "inject":
			return vault("op " + sub(1))
		case sub(1) == "item" && sub(2) == "get" && has("--reveal"):
			return vault("op item get --reveal")
		}
	case "bws":
		if sub(1) == "secret" && (sub(2) == "get" || sub(2) == "list") {
			return vault("bws secret " + sub(2))
		}
	case "bw":
		if sub(1) == "get" || sub(1) == "list" || sub(1) == "export" {
			return vault("bw " + sub(1))
		}
	case "vault", "bao":
		if sub(1) == "read" || (sub(1) == "kv" && sub(2) == "get") {
			return vault(strings.TrimSpace(name + " " + sub(1) + " " + sub(2)))
		}
	case "security":
		if (sub(1) == "find-generic-password" || sub(1) == "find-internet-password") && has("-w", "-g") {
			return vault("security " + sub(1) + " -w")
		}
		if sub(1) == "dump-keychain" && has("-d") {
			return vault("security dump-keychain -d")
		}
	case "secret-tool":
		if sub(1) == "lookup" {
			return vault("secret-tool lookup")
		}
	case "gh":
		if sub(1) == "auth" && (sub(2) == "token" || (sub(2) == "status" && has("-t", "--show-token"))) {
			return vault("gh auth " + sub(2))
		}
	case "gcloud":
		if sub(1) == "auth" && (sub(2) == "print-access-token" || sub(2) == "print-identity-token") {
			return vault("gcloud auth " + sub(2))
		}
	case "aws":
		if sub(1) == "configure" && (sub(2) == "export-credentials" || (sub(2) == "get" && policy.Sensitive(strings.ToUpper(sub(3))))) {
			return vault("aws configure " + sub(2))
		}
	case "az":
		if sub(1) == "account" && sub(2) == "get-access-token" {
			return vault("az account get-access-token")
		}
	case "kubectl":
		if sub(1) == "config" && sub(2) == "view" && has("--raw", "--flatten") {
			return vault("kubectl config view --raw")
		}
	}
	if readers[name] || copiers[name] {
		var operands []string
		for _, a := range args[1:] {
			if a != "" && !strings.HasPrefix(a, "-") {
				operands = append(operands, a)
			}
		}
		if copiers[name] && len(operands) > 0 {
			operands = operands[:len(operands)-1] // cp .env.example .env writes .env, it does not read it
		}
		for _, a := range operands {
			if why := deniedPath(a, cwd, env); why != "" {
				return readReason(a, why)
			}
		}
	}
	if name == "cat" || name == "strings" {
		for _, a := range args[1:] {
			if strings.HasPrefix(a, "/proc/") && strings.HasSuffix(a, "/environ") {
				return dump(name + " " + a)
			}
		}
	}
	return ""
}

// skipOptions drops the leading options of a wrapper such as sudo. An
// option's argument (sudo -u USER) is taken for the command: a gap that is
// acceptable for a second line of defense, which this is.
func skipOptions(args []string) []string {
	for len(args) > 0 && strings.HasPrefix(args[0], "-") {
		args = args[1:]
	}
	return args
}

// --- prompts, results, session start ---

// pasted blocks a prompt that carries what looks like a real credential.
func pasted(text string, env Env) string {
	if env.Rules == nil {
		return ""
	}
	rs := env.Rules()
	if rs == nil {
		return ""
	}
	for _, line := range strings.Split(text, "\n") {
		for _, m := range rs.Line("prompt", line) {
			if m.Rule == "generic-api-key" {
				continue // too loose for a prompt: hashes and IDs look like it
			}
			return fmt.Sprintf("passess: this message looks like it contains a %s credential, so it was not sent: whatever reaches the model "+
				"also reaches its logs and this transcript. Store it with `passess add NAME --keychain` (you type it into the keychain), "+
				"then ask the agent to use `passess exec -s NAME -- command`. If it was a real credential that already went somewhere, rotate it.", m.Rule)
		}
	}
	return ""
}

// KnownFromEnviron builds the redactor for credential values present in an
// environment: variables named like credentials, and configured secrets.
func KnownFromEnviron(environ, secrets []string) *redact.Redactor {
	var named []redact.Secret
	for _, kv := range environ {
		k, v, _ := strings.Cut(kv, "=")
		if len(v) >= 8 && (policy.Sensitive(k) || slices.Contains(secrets, k)) {
			named = append(named, redact.Secret{Name: k, Value: secret.FromString(v)})
		}
	}
	if len(named) == 0 {
		return nil
	}
	rd, _, err := redact.New(named, redact.Options{})
	if err != nil {
		return nil
	}
	return rd
}

// redactOutput removes credentials from a tool's output: the values of
// credential variables in the harness's environment, in every encoding the
// redactor knows, and strings the rules match.
func redactOutput(text string, env Env) (string, bool) {
	out := text
	if env.Known != nil {
		if rd := env.Known(); rd != nil {
			out = string(rd.Redact([]byte(out)))
		}
	}
	if env.Rules != nil {
		if rs := env.Rules(); rs != nil {
			lines := strings.SplitAfter(out, "\n")
			for i, line := range lines {
				for _, m := range rs.Line("output", line) {
					if m.Rule == "generic-api-key" {
						continue // hashes and IDs in ordinary output look like it
					}
					lines[i] = strings.ReplaceAll(lines[i], m.Secret, "[REDACTED:"+m.Rule+"]")
				}
			}
			out = strings.Join(lines, "")
		}
	}
	return out, out != text
}

// redactValue redacts every string inside a decoded JSON value and keeps its
// shape: Claude Code rejects a replacement tool output that does not match
// the tool's own.
func redactValue(v any, env Env) (any, bool) {
	switch x := v.(type) {
	case string:
		return redactOutput(x, env)
	case []any:
		changed := false
		cp := make([]any, len(x))
		for i, e := range x {
			var c bool
			cp[i], c = redactValue(e, env)
			changed = changed || c
		}
		return cp, changed
	case map[string]any:
		changed := false
		cp := make(map[string]any, len(x))
		for k, e := range x {
			var c bool
			cp[k], c = redactValue(e, env)
			changed = changed || c
		}
		return cp, changed
	}
	return v, false
}

func startContext(env Env) string {
	names := "none configured yet"
	if len(env.Secrets) > 0 {
		names = strings.Join(env.Secrets, ", ")
	}
	return "passess manages secrets on this machine. Secret names available: " + names + " (names only; values never enter this conversation). " +
		"Never read .env or credential files and never print environment variables. " +
		"Run a command that needs a secret with `passess exec -s NAME -- command`; `passess list` shows who may use each. " +
		"If a secret is missing, ask the user to run `passess add NAME`; never ask them to paste a value."
}
