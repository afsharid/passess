// Package hook turns a harness hook event into a decision: refuse the few
// actions that put secret values into an agent's context, and say what to do
// instead. Hooks are a second line of defense (the first is that values never
// reach the agent's environment or files), so the policy is deny-only and
// fails open: anything it cannot parse or does not recognize is allowed.
package hook

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"mvdan.cc/sh/v3/syntax"

	"github.com/afsharid/passess/internal/detect"
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
	MCP    Kind = "mcp"    // an MCP tool is about to be called
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
	// AgentSocket is where the passess agent listens: no command but passess
	// has business there.
	AgentSocket string
	// Agent asks a running agent to mask, in text, the values it holds; ok is
	// false when there is none to ask. The values stay in the agent.
	Agent func(text string) (masked string, ok bool)
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
			if writesConfig(p, ev.CWD, env) {
				return Verdict{Deny: true, Reason: configReason(p)}
			}
		}
	case MCP:
		if r := checkMCP(ev.Tool); r != "" {
			return Verdict{Deny: true, Reason: r}
		}
	case Prompt:
		if r := pasted(ev.Text, env); r != "" {
			return Verdict{Deny: true, Reason: r}
		}
	case Result:
		if ev.Response != nil {
			resp, masked := agentMaskValue(ev.Response, env)
			if out, changed := redactValue(resp, env); changed || masked {
				return Verdict{Response: out, Changed: true}
			}
			break
		}
		text, masked := ev.Text, false
		if env.Agent != nil {
			if m, ok := env.Agent(text); ok && m != text {
				text, masked = m, true
			}
		}
		if out, changed := redactOutput(text, env); changed || masked {
			return Verdict{Output: out, Changed: true}
		}
	case Start:
		return Verdict{Context: startContext(env)}
	}
	return Verdict{}
}

const useInstead = "Run the command that needs a secret with `passess exec -s NAME -- command`; `passess list` shows the names."

// --- MCP tools ---

// onePasswordMCP are the tools of 1Password's Environments MCP server that put
// values where the agent reaches them: a mounted .env file any process can
// read, and variables whose values the agent itself supplies.
var onePasswordMCP = map[string]string{
	"create_local_env_file": "mounts a .env file holding the Environment's values, which the agent can then read",
	"append_variables":      "takes the values from the agent, so they pass through the conversation",
}

// checkMCP refuses the 1Password tools above. Harnesses name an MCP tool
// mcp__<server>__<tool>, or by the bare tool name when that is unambiguous.
// The server part is the user's to choose (op, 1p, …), so only the tool
// name counts: these two names are 1Password's.
func checkMCP(tool string) string {
	parts := strings.Split(tool, "__")
	name := parts[len(parts)-1]
	why, ok := onePasswordMCP[name]
	if !ok {
		return ""
	}
	return fmt.Sprintf("passess refused the 1Password MCP tool %s: it %s. "+
		"Ask the user to connect the variable in Passess.app or with `passess add NAME --ref op://…`. %s", name, why, useInstead)
}

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

func configReason(p string) string {
	return "passess: " + p + " is the passess config, which decides which program receives which secret. " +
		"Changes to it are the user's to make: tell them what you need and let them do it in Passess.app or with `passess add` or `passess set`."
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

// unplaced says p is a relative name with no directory to be relative to:
// where it lands is not known.
func unplaced(p, cwd string) bool {
	return cwd == "" && p != "" && !filepath.IsAbs(p) && !strings.HasPrefix(p, "~")
}

// credentialNames are the base names of the credential files under HOME; a
// bare "config" (.kube/config) is too common a name to stand for one.
var credentialNames = func() []string {
	var out []string
	for _, c := range credentialPaths {
		if b := filepath.Base(c); b != "config" {
			out = append(out, b)
		}
	}
	return out
}()

// writesConfig says whether writing p changes the passess config. A relative
// name that is not placed counts when it is the config file's name.
func writesConfig(p, cwd string, env Env) bool {
	return inConfig(abs(p, cwd, env.Home), env) ||
		(unplaced(p, cwd) && strings.HasPrefix(filepath.Base(p), "config.toml"))
}

// deniedPath says why reading p would expose credentials, or "".
func deniedPath(p, cwd string, env Env) string {
	full := abs(p, cwd, env.Home)
	base := filepath.Base(full)
	if unplaced(p, cwd) && slices.Contains(credentialNames, base) {
		return "may hold credentials"
	}
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
var copiers = map[string]bool{"cp": true, "scp": true, "rsync": true, "install": true, "mv": true}

// Commands that change the files they name (sed only with -i).
var writers = map[string]bool{"tee": true, "sed": true, "truncate": true, "rm": true, "ln": true, "chmod": true, "touch": true}

// Programs that run the rest of their arguments as a command.
var wrappers = map[string]bool{"sudo": true, "command": true, "builtin": true, "exec": true, "nohup": true,
	"nice": true, "time": true, "doas": true, "caffeinate": true, "stdbuf": true, "timeout": true, "xargs": true}

// wrapperOptions say, for the wrappers that have any, which options take the
// next word as their argument, and how many words after the options are the
// wrapper's own (timeout's duration).
var wrapperOptions = map[string]struct {
	takes      []string
	positional int
}{
	"sudo":       {[]string{"-u", "-g", "-h", "-p", "-C", "-D", "-R", "-T", "-U", "-r", "-t", "--user", "--group"}, 0},
	"doas":       {[]string{"-u", "-C"}, 0},
	"nice":       {[]string{"-n", "--adjustment"}, 0},
	"timeout":    {[]string{"-s", "-k", "--signal", "--kill-after"}, 1},
	"exec":       {[]string{"-a"}, 0},
	"stdbuf":     {[]string{"-i", "-o", "-e"}, 0},
	"caffeinate": {[]string{"-t", "-w"}, 0},
	"time":       {[]string{"-f", "-o"}, 0},
	"xargs":      {[]string{"-n", "-L", "-P", "-s", "-d", "-E", "-a", "-I"}, 0},
}

func checkShell(cmd, cwd string, env Env) string {
	file, err := syntax.NewParser(syntax.Variant(syntax.LangBash)).Parse(strings.NewReader(cmd), "")
	if err != nil {
		return "" // not ours to judge; the harness runs what it can
	}
	var reason string
	others := false // a program other than passess runs
	steered := ""   // a path setting assigned other than inline on a passess call
	// cur is the directory relative paths resolve against: where the harness
	// ran the command, then wherever a literal cd or pushd earlier in the same
	// command line moved it. "" once that is unknown.
	cur, stack := cwd, []string(nil)
	// A cd moves the shell only where the shell runs it. In a subshell, a
	// pipeline, a background job or a substitution it is undone when that ends;
	// in a branch or a function that may not run it leaves the directory
	// unknown. path holds the nodes being walked, scopes the ones that bound a cd.
	var path []syntax.Node
	var scopes []cdScope
	syntax.Walk(file, func(node syntax.Node) bool {
		if node == nil { // the children of the last node on path are done
			left := path[len(path)-1]
			path = path[:len(path)-1]
			if len(scopes) > 0 && scopes[len(scopes)-1].node == left {
				sc := scopes[len(scopes)-1]
				scopes = scopes[:len(scopes)-1]
				switch {
				case sc.undone:
					cur, stack = sc.cur, sc.stack
				case cur != sc.cur || !slices.Equal(stack, sc.stack):
					cur, stack = "", nil
				}
			}
			return true
		}
		if reason != "" {
			return false
		}
		var parent syntax.Node
		if len(path) > 0 {
			parent = path[len(path)-1]
		}
		if undone, bounded := cdScopeOf(parent, node, env); bounded {
			scopes = append(scopes, cdScope{node, undone, cur, slices.Clone(stack)})
		}
		path = append(path, node)
		switch n := node.(type) {
		case *syntax.ParamExp:
			if n.Param != nil {
				reason = checkParam(n.Param.Value, env)
			}
		case *syntax.Redirect:
			p, ok := literal(n.Word, env)
			switch {
			case !ok:
			case n.Op == syntax.RdrIn || n.Op == syntax.RdrInOut:
				if why := deniedPath(p, cur, env); why != "" {
					reason = readReason(p, why)
				}
			case writesConfig(p, cur, env): // > >> &> into the config
				reason = configReason(p)
			}
		case *syntax.CallExpr:
			var args []string
			for _, w := range n.Args {
				s, _ := literal(w, env) // a non-literal word stays "" and matches nothing
				args = append(args, s)
			}
			program := ""
			if len(args) > 0 {
				program = args[0]
			}
			if filepath.Base(program) != "passess" && len(args) > 0 {
				others = true
			}
			for _, a := range n.Assigns {
				if reason == "" && a.Name != nil {
					reason = checkAssign(a.Name.Value, program)
					if pathSettings[a.Name.Value] && filepath.Base(program) != "passess" {
						steered = a.Name.Value
					}
				}
			}
			if reason == "" {
				reason = checkCall(args, cur, env)
			}
			cur, stack = afterCd(args, cur, stack, env.Home)
			switch filepath.Base(program) {
			case "eval", "source", ".": // they run commands, a cd among them, in this shell
				cur, stack = "", nil
			}
		case *syntax.DeclClause: // export, declare, typeset, local, readonly
			reason = checkDecl(n, env)
			for _, a := range n.Args {
				if !a.Naked && a.Name != nil && pathSettings[a.Name.Value] {
					steered = a.Name.Value
				}
			}
		}
		return true
	})
	// HOME and the like set apart from the passess call, by export or for a
	// shell that runs it, still reach it: the whole text is searched.
	if reason == "" && steered != "" && strings.Contains(cmd, "passess") {
		reason = checkAssign(steered, "passess")
	}
	// A path in quotes, a variable or a script can name the socket too, so
	// the text is searched whole: $HOME/.local/state/passess/agent.sock.
	if reason == "" && others && mentionsAgent(cmd, env) {
		reason = socketReason
	}
	return reason
}

// cdScope is a part of the command line that bounds what a cd in it does to
// the directory after it, with the directory when it began.
type cdScope struct {
	node   syntax.Node
	undone bool // the cd is undone at its end; else the directory is unknown if it moved
	cur    string
	stack  []string
}

// cdScopeOf says whether node, a child of parent, bounds a cd, and how.
func cdScopeOf(parent, node syntax.Node, env Env) (undone, bounded bool) {
	switch n := node.(type) {
	case *syntax.Subshell, *syntax.CmdSubst, *syntax.ProcSubst:
		return true, true
	case *syntax.BinaryCmd:
		return true, n.Op == syntax.Pipe || n.Op == syntax.PipeAll
	case *syntax.FuncDecl, *syntax.IfClause, *syntax.WhileClause, *syntax.ForClause, *syntax.CaseClause:
		return false, true
	case *syntax.Stmt:
		if n.Background || n.Coprocess {
			return true, true
		}
		// The right side of && and || runs only when the left side lets it. A
		// chain of cds on the left is the usual `cd a && cd b`: taken as run.
		if b, ok := parent.(*syntax.BinaryCmd); ok && b.Y == n {
			return false, b.Op == syntax.OrStmt || !cdChain(b.X, env)
		}
	}
	return false, false
}

// cdChain says whether s is cd, pushd or popd, or such commands joined by &&.
func cdChain(s *syntax.Stmt, env Env) bool {
	switch c := s.Cmd.(type) {
	case *syntax.CallExpr:
		if len(c.Args) == 0 {
			return false
		}
		w, _ := literal(c.Args[0], env)
		switch w {
		case "cd", "pushd", "popd":
			return true
		}
	case *syntax.BinaryCmd:
		return c.Op == syntax.AndStmt && cdChain(c.X, env) && cdChain(c.Y, env)
	}
	return false
}

// passessSettings point passess at another config or agent: an agent's
// command has no business setting them.
var passessSettings = map[string]bool{"PASSESS_CONFIG": true, "PASSESS_AGENT_SOCK": true}

// pathSettings move passess's config and socket with everything else; set
// for a passess command, they point it elsewhere just the same.
var pathSettings = map[string]bool{"HOME": true, "XDG_CONFIG_HOME": true, "XDG_RUNTIME_DIR": true}

// afterCd returns the working directory after a cd, pushd or popd with args,
// and the pushd stack; other commands leave both as they are. A directory it
// cannot tell (cd "$X", cd -) becomes "".
func afterCd(args []string, cur string, stack []string, home string) (string, []string) {
	for len(args) > 0 && (filepath.Base(args[0]) == "builtin" || filepath.Base(args[0]) == "command") {
		args = args[1:]
	}
	if len(args) == 0 {
		return cur, stack
	}
	switch filepath.Base(args[0]) {
	case "cd", "pushd":
		ops := args[1:]
		for len(ops) > 0 && strings.HasPrefix(ops[0], "-") && ops[0] != "-" {
			ops = ops[1:] // -L, -P, -e, -@
		}
		next := home
		switch {
		case len(ops) == 0 && filepath.Base(args[0]) == "pushd":
			return "", stack // swaps with the top of a stack not known here
		case len(ops) == 0:
		case ops[0] == "" || ops[0] == "-":
			next = ""
		default:
			if next = abs(ops[0], cur, home); !filepath.IsAbs(next) {
				next = "" // relative to a directory not known here
			}
		}
		if filepath.Base(args[0]) == "pushd" {
			stack = append(stack, cur)
		}
		return next, stack
	case "popd":
		if len(stack) > 0 {
			return stack[len(stack)-1], stack[:len(stack)-1]
		}
		return "", stack
	}
	return cur, stack
}

func checkAssign(name, program string) string {
	if detect.IsMarker(name) {
		return markerReason(name)
	}
	if passessSettings[name] || (pathSettings[name] && filepath.Base(program) == "passess") {
		return fmt.Sprintf("passess: setting %s in a command points passess at another config or agent than the user's, "+
			"around the policy and the approvals the user set up. Run passess without it; its settings are the user's to change.", name)
	}
	return ""
}

func markerReason(name string) string {
	return "passess: " + name + " tells passess it runs under an agent; clearing or overriding it hides that from the " +
		"checks meant for agents. Run the command as it is."
}

const socketReason = "passess: that command talks to the passess agent's socket directly. Commands that need a secret go " +
	"through `passess exec -s NAME -- command`; the agent's approval questions are the user's to answer."

func mentionsAgent(text string, env Env) bool {
	return strings.Contains(text, "agent.sock") || (env.AgentSocket != "" && strings.Contains(text, env.AgentSocket))
}

// checkDecl refuses the forms that print variables: export -p, bare
// declare -x, declare -p NAME for a credential.
func checkDecl(n *syntax.DeclClause, env Env) string {
	if n.Variant == nil {
		return ""
	}
	var flags, names []string
	assigns := false
	for _, a := range n.Args {
		switch {
		case a.Naked && a.Name != nil:
			names = append(names, a.Name.Value)
		case a.Naked && a.Value != nil:
			if f, ok := literal(a.Value, env); ok && strings.HasPrefix(f, "-") {
				flags = append(flags, f)
			}
		default:
			if a.Name != nil {
				if r := checkAssign(a.Name.Value, ""); r != "" {
					return r
				}
			}
			assigns = true
		}
	}
	if assigns {
		return "" // an assignment: nothing is printed
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

// literal is a word's value when it has no expansion in it but the
// variables passess finds its config by: "$HOME/.config/passess" names the
// config as plainly as ~/.config/passess does. It is the value the shell
// makes of the word: backslashes are removed as the shell removes them.
func literal(w *syntax.Word, env Env) (string, bool) {
	if w == nil {
		return "", false
	}
	var b strings.Builder
	for _, part := range w.Parts {
		switch p := part.(type) {
		case *syntax.SglQuoted:
			if p.Dollar { // $'…' holds escapes the shell decodes, not the text itself
				return "", false
			}
			b.WriteString(p.Value)
		case *syntax.DblQuoted:
			for _, q := range p.Parts {
				if !plain(&b, q, env, true) {
					return "", false
				}
			}
		default:
			if !plain(&b, part, env, false) {
				return "", false
			}
		}
	}
	return b.String(), true
}

// plain writes a literal part, or the value of a locator, to b.
func plain(b *strings.Builder, part syntax.WordPart, env Env, quoted bool) bool {
	switch p := part.(type) {
	case *syntax.Lit:
		b.WriteString(unescape(p.Value, quoted))
		return true
	case *syntax.ParamExp:
		v, ok := locator(p, env)
		b.WriteString(v)
		return ok
	}
	return false
}

// unescape removes the backslashes the shell removes: before any character
// outside double quotes, and before $ ` " \ and a newline inside them. A
// backslash and a newline are a line continuation and vanish together.
func unescape(s string, quoted bool) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' || i+1 == len(s) {
			b.WriteByte(s[i])
			continue
		}
		next := s[i+1]
		switch {
		case next == '\n':
			i++
		case !quoted || strings.IndexByte("$`\"\\", next) >= 0:
			i++
			b.WriteByte(s[i])
		default:
			b.WriteByte(s[i])
		}
	}
	return b.String()
}

// locator is the value of $HOME, $XDG_CONFIG_HOME or $PASSESS_CONFIG, which
// is where config.UserPath looks, as the harness has them; a default
// (${XDG_CONFIG_HOME:-$HOME/.config}) stands in for one that is not set. Any
// other expansion, or a locator that is not set, is not known here.
func locator(p *syntax.ParamExp, env Env) (string, bool) {
	if p.Param == nil || p.Excl || p.Length || p.Width || p.Index != nil || p.Slice != nil || p.Repl != nil || p.Names != 0 {
		return "", false
	}
	v := ""
	switch p.Param.Value {
	case "HOME":
		v = env.Home
	case "XDG_CONFIG_HOME", "PASSESS_CONFIG":
		if env.Getenv != nil {
			v = env.Getenv(p.Param.Value)
		}
	default:
		return "", false
	}
	if p.Exp != nil {
		switch p.Exp.Op {
		case syntax.DefaultUnset, syntax.DefaultUnsetOrNull, syntax.AssignUnset, syntax.AssignUnsetOrNull:
		default:
			return "", false
		}
		if v == "" {
			return literal(p.Exp.Word, env)
		}
	}
	return v, v != ""
}

func checkParam(name string, env Env) string {
	configured := slices.Contains(env.Secrets, name)
	set := env.Getenv != nil && env.Getenv(name) != ""
	if exposed := policy.Sensitive(name) && set; !configured && !exposed {
		return ""
	}
	return fmt.Sprintf("passess: $%s would put a credential into the command line and this conversation. "+
		"Run the program through passess, which hands the value to it alone: `passess exec -s %s -- program args` "+
		"(without $%s). For an HTTP request, let passess send it, to the hosts the secret lists: `passess http -s %s -H 'Authorization: Bearer {{%s}}' URL`.",
		name, name, name, name, name)
}

func checkCall(args []string, cwd string, env Env) string {
	for len(args) > 0 && wrappers[filepath.Base(args[0])] {
		args = skipOptions(filepath.Base(args[0]), args[1:])
	}
	if len(args) == 0 {
		return ""
	}
	if args[0] == "" {
		// A program built from a variable or a substitution may be passess.
		// The refusals no other program shares apply to it: `$P agent stop`.
		if len(args) > 1 && (args[1] == "helper" || (len(args) > 2 && args[1] == "agent" && slices.Contains([]string{"stop", "serve", "approve"}, args[2]))) {
			return checkCall(append([]string{"passess"}, args[1:]...), cwd, env)
		}
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
	case "find":
		// -exec COMMAND … ; and -exec COMMAND … + run COMMAND.
		for i, a := range args {
			if a != "-exec" && a != "-execdir" && a != "-ok" && a != "-okdir" {
				continue
			}
			end := i + 1
			for end < len(args) && args[end] != ";" && args[end] != "+" {
				end++
			}
			if r := checkCall(args[i+1:end], cwd, env); r != "" {
				return r
			}
		}
	case "env":
		rest := args[1:]
		var set []string
		for len(rest) > 0 && (strings.HasPrefix(rest[0], "-") || strings.Contains(rest[0], "=")) {
			if (rest[0] == "-u" || rest[0] == "--unset") && len(rest) > 1 && detect.IsMarker(rest[1]) {
				return markerReason(rest[1])
			}
			if k, ok := strings.CutPrefix(rest[0], "--unset="); ok && detect.IsMarker(k) {
				return markerReason(k)
			}
			if rest[0] == "-u" || rest[0] == "--unset" || rest[0] == "-C" || rest[0] == "--chdir" || rest[0] == "-S" {
				rest = rest[min(2, len(rest)):]
				continue
			}
			if k, _, ok := strings.Cut(rest[0], "="); ok && !strings.HasPrefix(rest[0], "-") {
				set = append(set, k)
			}
			rest = rest[1:]
		}
		if len(rest) == 0 {
			return dump("env")
		}
		for _, k := range set {
			if r := checkAssign(k, rest[0]); r != "" {
				return r
			}
		}
		return checkCall(rest, cwd, env)
	case "passess":
		switch {
		case len(args) > 1 && args[1] == "":
			// $V, $(…) or $'…' as the subcommand: what runs cannot be told
			// from the text, and every subcommand an agent may run is plain.
			return "passess: write the passess subcommand out as plain text; one built from a variable or a substitution " +
				"cannot be checked, so it is refused."
		case sub(1) == "agent" && (sub(2) == "stop" || sub(2) == "serve"):
			return "passess: `passess agent " + sub(2) + "` is the user's to run: the agent asks the user before a secret " +
				"marked approve goes anywhere, and replacing or stopping it would skip that. Tell the user if the agent needs it."
		case sub(1) == "agent" && sub(2) == "approve":
			return "passess: approving is the user's alone; an agent must not answer its own approval questions. " +
				"Tell the user what you are waiting for."
		case sub(1) == "helper":
			return "passess: `passess helper` prints a secret value; it is for a harness's apiKeyHelper setting, not for commands. " +
				useInstead
		case sub(1) == "add", sub(1) == "set", sub(1) == "remove":
			return "passess: `passess " + sub(1) + "` decides who may use which secret; it is the user's to run, or to do in Passess.app. " +
				"Tell the user the name and reference you need."
		case (sub(1) == "mcp" || sub(1) == "profile") && (sub(2) == "add" || sub(2) == "set" || sub(2) == "remove"):
			return "passess: `passess " + sub(1) + " " + sub(2) + "` decides which secrets a program gets; it is the user's to run, " +
				"or to do in Passess.app. Tell the user what you need."
		case sub(1) == "agent" && sub(2) == "config" && slices.ContainsFunc(args[3:], func(a string) bool { return a != "--json" }):
			return "passess: `passess agent config` decides how long approvals and cached values last; it is the user's to run, " +
				"or to do in Passess.app."
		case sub(1) == "backend" && !slices.Contains(args, "--json"):
			return "passess: `passess backend` sets how passess reaches the user's vault and stores its credentials; it is the user's " +
				"to run, or to do in Passess.app. Tell the user which setting you need."
		case sub(1) == "discover", sub(1) == "browse":
			return "passess: `passess " + sub(1) + "` lists what the user's vault holds; that inventory is the user's to see, " +
				"in Passess.app or a terminal of their own. Ask the user for the secret you need."
		case sub(1) == "migrate" && slices.Contains(args, "--apply"):
			return "passess: `passess migrate --apply` moves values out of the user's files; it is the user's to run. " +
				"Show them the dry run and let them apply it."
		case sub(1) == "uninstall" && slices.Contains(args, "--apply"),
			sub(1) == "install" && slices.Contains(args, "--apply") && slices.Contains(args, "--no-hooks"):
			return "passess: that removes the hooks that guard this session; it is the user's to run."
		}
	case "unset":
		for _, a := range args[1:] {
			if detect.IsMarker(a) {
				return markerReason(a)
			}
		}
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
	// Commands that write the files they name: none may touch the config.
	if writers[name] || copiers[name] {
		for _, a := range args[1:] {
			if a != "" && !strings.HasPrefix(a, "-") && writesConfig(a, cwd, env) {
				if name != "sed" || slices.ContainsFunc(args[1:], func(f string) bool { return strings.HasPrefix(f, "-i") }) {
					return configReason(a)
				}
			}
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

// skipOptions drops the leading options of a wrapper such as sudo, with the
// arguments of the options it knows take one (sudo -u USER) and the words
// that are the wrapper's own (timeout's duration). An option it does not know
// that takes an argument leaves that argument in the command's place.
func skipOptions(wrapper string, args []string) []string {
	spec := wrapperOptions[wrapper]
	for len(args) > 0 && strings.HasPrefix(args[0], "-") {
		opt := args[0]
		args = args[1:]
		if slices.Contains(spec.takes, opt) && len(args) > 0 {
			args = args[1:]
		}
	}
	return args[min(spec.positional, len(args)):]
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
	refused := func(rule string) string {
		return fmt.Sprintf("passess: this message looks like it contains a %s credential, so it was not sent: whatever reaches the model "+
			"also reaches its logs and this transcript. Store it with `passess add NAME --keychain` (you type it into the keychain), "+
			"then ask the agent to use `passess exec -s NAME -- command`. If it was a real credential that already went somewhere, rotate it.", rule)
	}
	// A private key spans lines, from its BEGIN line to its END line, so that
	// rule reads the whole text.
	if strings.Contains(strings.ToLower(text), "-----begin") {
		for _, m := range rs.Line("prompt", text) {
			if m.Rule == "private-key" {
				return refused(m.Rule)
			}
		}
	}
	for _, line := range strings.Split(text, "\n") {
		for _, m := range rs.Line("prompt", line) {
			if m.Rule == "generic-api-key" {
				continue // too loose for a prompt: hashes and IDs look like it
			}
			return refused(m.Rule)
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

// agentMaskValue has the agent mask the values it holds anywhere in a decoded
// JSON value, in one round trip: the value goes as JSON and comes back as
// JSON, which [REDACTED:NAME], free of quotes and backslashes, keeps valid.
func agentMaskValue(v any, env Env) (any, bool) {
	if env.Agent == nil {
		return v, false
	}
	b, err := json.Marshal(v)
	if err != nil {
		return v, false
	}
	m, ok := env.Agent(string(b))
	if !ok || m == string(b) {
		return v, false
	}
	var out any
	if json.Unmarshal([]byte(m), &out) != nil {
		return v, false
	}
	return out, true
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
