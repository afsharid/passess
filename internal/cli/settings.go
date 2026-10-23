package cli

import (
	"errors"
	"flag"
	"fmt"
	"strings"
	"time"

	"github.com/afsharid/passess/internal/config"
	"github.com/afsharid/passess/internal/scan"
)

// Commands for the config tables that are not secrets, so that nothing in
// the config needs a hand edit: Passess.app runs these, and so can the user.
// Each writes through editUserConfig, which keeps an edit only if the config
// still loads, and so still validates.

func init() {
	commands["mcp"] = command{"the MCP servers harnesses start through passess: list, add, set, remove", runMCP}
	commands["profile"] = command{"the profiles `passess run` uses: list, add, set, remove", runProfile}
}

// multiFlag is a repeatable flag whose every value is one item, commas and
// all: a command's arguments, KEY=VALUE pairs.
type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, " ") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }

// pairs parses KEY=VALUE items into a map. An empty item adds nothing, so
// `--env ""` empties the table.
func pairs(items []string, what string) (map[string]string, error) {
	out := map[string]string{}
	for _, it := range items {
		if it == "" {
			continue
		}
		k, v, ok := strings.Cut(it, "=")
		if k = strings.TrimSpace(k); !ok || k == "" {
			return nil, fmt.Errorf("--%s takes KEY=VALUE, not %q", what, it)
		}
		if strings.ContainsAny(k+v, "\n\r\x00") {
			return nil, fmt.Errorf("--%s %s must be one line", what, k)
		}
		out[k] = v
	}
	return out, nil
}

// inlineTable is a TOML inline table of strings.
func inlineTable(m map[string]string) string {
	parts := make([]string, 0, len(m))
	for _, k := range sortedKeys(m) {
		parts = append(parts, tomlKey(k)+" = "+tomlString(m[k]))
	}
	return "{ " + strings.Join(parts, ", ") + " }"
}

// refusePlainCredential refuses a value meant to be plain (vars, a profile's
// env, the text around a header's placeholders) that looks like a
// credential: a value written into the config is where agents can read it.
func refusePlainCredential(where, value string) error {
	rs, err := scan.DefaultRules()
	if err != nil {
		return err
	}
	text := config.Expand(value, func(string) string { return "" })
	if len(rs.Line("", text)) > 0 || len(rs.Line("", where+" = "+text)) > 0 {
		return fmt.Errorf("%s looks like a credential; add it with `passess add` and name the secret instead", where)
	}
	return nil
}

// field is a Field with a literal, or with nil to remove the key.
func field(key string, lit string, keep bool) config.Field {
	if !keep {
		return config.Field{Key: key}
	}
	return config.Field{Key: key, Value: &lit}
}

// --- mcp ---

const mcpUsage = `Usage:
  passess mcp list [--json]
  passess mcp add NAME (--command PROGRAM [--command ARG]… | --url URL) [options]
  passess mcp set NAME [options]          each option given replaces what the server has
  passess mcp remove NAME
Options:
  --env VAR=SECRET        a local server's variable and the secret it gets (repeatable)
  --var VAR=VALUE         a plain, non-secret variable (repeatable)
  --inherit VAR           a variable passed through from the caller (repeatable)
  --header NAME=TEMPLATE  a remote server's header, secrets as {{NAME}} (repeatable)
  --harnesses IDS         harness IDs to register it with, comma-separated, or all
  --redact=false          pass the server's output through unredacted
Then register it: passess install HARNESS --apply, or Set up in Passess.app.`

// mcpView is one server in `mcp list --json`: names and plain values only.
type mcpView struct {
	Name      string            `json:"name"`
	Command   []string          `json:"command,omitempty"`
	URL       string            `json:"url,omitempty"`
	Env       map[string]string `json:"env,omitempty"`     // variable → secret name
	Vars      map[string]string `json:"vars,omitempty"`    // plain values
	Inherit   []string          `json:"inherit,omitempty"` // caller variables
	Headers   map[string]string `json:"headers,omitempty"` // header → {{SECRET}} template
	Harnesses []string          `json:"harnesses"`         // empty: every installed one
	Redact    bool              `json:"redact"`
	Secrets   []string          `json:"secrets"` // the secrets it uses
}

func runMCP(st *Streams, args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(st.Stderr, mcpUsage)
		return ExitUsage
	}
	switch sub, rest := args[0], args[1:]; sub {
	case "list":
		return listMCP(st, rest)
	case "add", "set":
		return editMCP(st, sub, rest)
	case "remove":
		if len(rest) != 1 || strings.HasPrefix(rest[0], "-") {
			fmt.Fprintln(st.Stderr, "Usage: passess mcp remove NAME")
			return ExitUsage
		}
		return removeTable(st, "mcp", rest[0], "MCP server", "removes how harnesses start an MCP server")
	}
	fmt.Fprintln(st.Stderr, mcpUsage)
	return ExitUsage
}

func listMCP(st *Streams, args []string) int {
	asJSON := len(args) == 1 && args[0] == "--json"
	if len(args) > 0 && !asJSON {
		fmt.Fprintln(st.Stderr, "Usage: passess mcp list [--json]")
		return ExitUsage
	}
	u, err := loadUserConfig(st)
	if err != nil && !errors.Is(err, config.ErrNoConfig) {
		return failf(st, ExitConfig, "%v", err)
	}
	out := []mcpView{}
	if u != nil {
		for _, name := range sortedKeys(u.MCP) {
			m := u.MCP[name]
			out = append(out, mcpView{Name: name, Command: m.Command, URL: m.URL, Env: m.Env, Vars: m.Vars, Inherit: m.Inherit,
				Headers: m.Headers, Harnesses: append([]string{}, m.Harnesses...), Redact: m.Redact, Secrets: m.Secrets()})
		}
	}
	if asJSON {
		return writeJSON(st, out)
	}
	if len(out) == 0 {
		fmt.Fprintln(st.Stdout, "no MCP servers; add one with `passess mcp add NAME --command …` or in Passess.app")
		return ExitOK
	}
	for _, m := range out {
		where := strings.Join(m.Command, " ")
		if m.URL != "" {
			where = m.URL
		}
		fmt.Fprintf(st.Stdout, "%-20s %s  secrets: %s\n", m.Name, where, strings.Join(m.Secrets, ", "))
	}
	return ExitOK
}

func editMCP(st *Streams, sub string, args []string) int {
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		fmt.Fprintln(st.Stderr, mcpUsage)
		return ExitUsage
	}
	name := args[0]
	if !bareKey.MatchString(name) {
		return failf(st, ExitUsage, "%q is not a server name: letters, digits, - and _", name)
	}
	fs := flag.NewFlagSet("mcp "+sub, flag.ContinueOnError)
	fs.SetOutput(st.Stderr)
	fs.Usage = func() { fmt.Fprintln(st.Stderr, mcpUsage) }
	var command, env, vars, inherit, headers multiFlag
	fs.Var(&command, "command", "the program, then each argument (repeatable)")
	url := fs.String("url", "", "a remote streamable-HTTP server")
	fs.Var(&env, "env", "VAR=SECRET (repeatable)")
	fs.Var(&vars, "var", "VAR=VALUE, plain (repeatable)")
	fs.Var(&inherit, "inherit", "a caller variable (repeatable)")
	fs.Var(&headers, "header", "NAME=TEMPLATE (repeatable)")
	harnesses := fs.String("harnesses", "", "harness IDs, comma-separated, or all")
	redact := fs.Bool("redact", true, "redact the server's output")
	if err := fs.Parse(args[1:]); err != nil {
		return ExitUsage
	}
	if fs.NArg() > 0 {
		return failf(st, ExitUsage, "unexpected argument %q", fs.Arg(0))
	}
	given := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { given[f.Name] = true })
	if sub == "add" && !given["command"] && !given["url"] {
		return failf(st, ExitUsage, "give --command (a local server) or --url (a remote one)")
	}
	if sub == "set" && len(given) == 0 {
		fmt.Fprintln(st.Stderr, mcpUsage)
		return ExitUsage
	}
	if given["command"] && given["url"] {
		return failf(st, ExitUsage, "give --command or --url, not both")
	}

	var fields []config.Field
	// Switching between a local and a remote server takes out what only
	// the other kind has.
	if given["command"] {
		for _, a := range command {
			if strings.ContainsAny(a, "\n\r\x00") {
				return failf(st, ExitUsage, "--command arguments must be one line each")
			}
		}
		fields = append(fields, field("command", arrayLiteral(command), len(command) > 0), field("url", "", false), field("headers", "", false))
	}
	if given["url"] {
		if !strings.HasPrefix(*url, "https://") && !strings.HasPrefix(*url, "http://") {
			return failf(st, ExitUsage, "--url takes an http(s) URL")
		}
		fields = append(fields, field("url", tomlString(*url), true),
			field("command", "", false), field("env", "", false), field("vars", "", false), field("inherit", "", false))
	}
	for _, f := range []struct {
		flag, key string
		items     multiFlag
		plain     bool // a value written as is, which must not be a credential
	}{{"env", "env", env, false}, {"var", "vars", vars, true}, {"header", "headers", headers, true}} {
		if !given[f.flag] {
			continue
		}
		m, err := pairs(f.items, f.flag)
		if err != nil {
			return failf(st, ExitUsage, "%v", err)
		}
		if f.plain {
			for _, k := range sortedKeys(m) {
				if err := refusePlainCredential(f.key+"."+k, m[k]); err != nil {
					return failf(st, ExitUsage, "%v", err)
				}
			}
		}
		fields = append(fields, field(f.key, inlineTable(m), len(m) > 0))
	}
	if given["inherit"] {
		fields = append(fields, field("inherit", arrayLiteral(inherit), len(inherit) > 0))
	}
	if given["harnesses"] {
		var ids listFlag
		_ = ids.Set(*harnesses)
		all := len(ids) == 1 && ids[0] == "all"
		fields = append(fields, field("harnesses", arrayLiteral(ids), !all && len(ids) > 0))
	}
	if given["redact"] {
		fields = append(fields, field("redact", "false", !*redact)) // true is the default: no key
	}
	if code := refuseUnderAgent(st, "mcp "+sub, "decides which secrets an MCP server gets"); code != 0 {
		return code
	}
	if code := startUserConfig(st); code != 0 {
		return code
	}
	path, code := editUserConfig(st, func(data []byte) ([]byte, error) {
		u, err := config.ParseUser("", data)
		if err != nil {
			return nil, err
		}
		_, there := u.MCP[name]
		switch {
		case sub == "add" && there:
			return nil, fmt.Errorf("mcp.%s is already defined; change it with `passess mcp set %s`", name, name)
		case sub == "set" && !there:
			return nil, fmt.Errorf("mcp.%s is not defined; add it first", name)
		}
		return config.SetTableFields(data, []string{"mcp", name}, fields, sub == "add")
	})
	if code != 0 {
		return code
	}
	verb := map[string]string{"add": "added", "set": "updated"}[sub]
	fmt.Fprintf(st.Stdout, "%s mcp.%s in %s; register it with `passess install HARNESS --apply` or Set up in Passess.app\n", verb, name, path)
	return ExitOK
}

// removeTable takes [table.NAME] out of the user config.
func removeTable(st *Streams, table, name, what, why string) int {
	if code := refuseUnderAgent(st, table+" remove", why); code != 0 {
		return code
	}
	path, code := editUserConfig(st, func(data []byte) ([]byte, error) {
		return config.RemoveTable(data, []string{table, name})
	})
	if code != 0 {
		return code
	}
	fmt.Fprintf(st.Stdout, "removed %s %s from %s\n", what, name, path)
	return ExitOK
}

// --- profile ---

const profileUsage = `Usage:
  passess profile list [--json]
  passess profile add NAME --secrets A,B [options]
  passess profile set NAME [options]      each option given replaces what the profile has
  passess profile remove NAME
Options:
  --secrets A,B      the secrets the program gets
  --required A,B     the ones it cannot start without
  --allow P,Q        the programs that may run under it
  --inherit VAR      a variable passed through from the caller (repeatable)
  --env VAR=VALUE    a plain, non-secret variable (repeatable)
  --tty              let a TUI have the terminal when no agent runs it
Run it with: passess run NAME -- COMMAND`

type profileView struct {
	Name     string            `json:"name"`
	Secrets  []string          `json:"secrets"`
	Required []string          `json:"required,omitempty"`
	Allow    []string          `json:"allow,omitempty"`
	Inherit  []string          `json:"inherit,omitempty"`
	Env      map[string]string `json:"env,omitempty"`
	TTY      bool              `json:"tty"`
	Run      string            `json:"run"` // the command line that uses it
}

func runProfile(st *Streams, args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(st.Stderr, profileUsage)
		return ExitUsage
	}
	switch sub, rest := args[0], args[1:]; sub {
	case "list":
		return listProfiles(st, rest)
	case "add", "set":
		return editProfile(st, sub, rest)
	case "remove":
		if len(rest) != 1 || strings.HasPrefix(rest[0], "-") {
			fmt.Fprintln(st.Stderr, "Usage: passess profile remove NAME")
			return ExitUsage
		}
		return removeTable(st, "profiles", rest[0], "profile", "decides which secrets a program gets")
	}
	fmt.Fprintln(st.Stderr, profileUsage)
	return ExitUsage
}

func listProfiles(st *Streams, args []string) int {
	asJSON := len(args) == 1 && args[0] == "--json"
	if len(args) > 0 && !asJSON {
		fmt.Fprintln(st.Stderr, "Usage: passess profile list [--json]")
		return ExitUsage
	}
	u, err := loadUserConfig(st)
	if err != nil && !errors.Is(err, config.ErrNoConfig) {
		return failf(st, ExitConfig, "%v", err)
	}
	out := []profileView{}
	if u != nil {
		for _, name := range sortedKeys(u.Profiles) {
			p := u.Profiles[name]
			out = append(out, profileView{Name: name, Secrets: append([]string{}, p.Secrets...), Required: p.Required, Allow: p.Allow,
				Inherit: p.Inherit, Env: p.Env, TTY: p.TTY, Run: "passess run " + name + " -- COMMAND"})
		}
	}
	if asJSON {
		return writeJSON(st, out)
	}
	if len(out) == 0 {
		fmt.Fprintln(st.Stdout, "no profiles; add one with `passess profile add NAME --secrets A,B` or in Passess.app")
		return ExitOK
	}
	for _, p := range out {
		fmt.Fprintf(st.Stdout, "%-20s secrets: %s\n", p.Name, strings.Join(p.Secrets, ", "))
	}
	return ExitOK
}

func editProfile(st *Streams, sub string, args []string) int {
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		fmt.Fprintln(st.Stderr, profileUsage)
		return ExitUsage
	}
	name := args[0]
	if !bareKey.MatchString(name) {
		return failf(st, ExitUsage, "%q is not a profile name: letters, digits, - and _", name)
	}
	fs := flag.NewFlagSet("profile "+sub, flag.ContinueOnError)
	fs.SetOutput(st.Stderr)
	fs.Usage = func() { fmt.Fprintln(st.Stderr, profileUsage) }
	var secrets, required, allow listFlag
	var inherit, env multiFlag
	fs.Var(&secrets, "secrets", "the secrets, comma-separated")
	fs.Var(&required, "required", "the required secrets, comma-separated")
	fs.Var(&allow, "allow", "the programs, comma-separated")
	fs.Var(&inherit, "inherit", "a caller variable (repeatable)")
	fs.Var(&env, "env", "VAR=VALUE, plain (repeatable)")
	tty := fs.Bool("tty", false, "let a TUI have the terminal when no agent runs it")
	if err := fs.Parse(args[1:]); err != nil {
		return ExitUsage
	}
	if fs.NArg() > 0 {
		return failf(st, ExitUsage, "unexpected argument %q", fs.Arg(0))
	}
	given := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { given[f.Name] = true })
	switch {
	case sub == "add" && len(secrets) == 0:
		return failf(st, ExitUsage, "give --secrets: the secrets the program gets")
	case sub == "set" && len(given) == 0:
		fmt.Fprintln(st.Stderr, profileUsage)
		return ExitUsage
	}
	var fields []config.Field
	for _, l := range []struct {
		key   string
		items []string
	}{{"secrets", secrets}, {"required", required}, {"allow", allow}, {"inherit", inherit}} {
		if given[l.key] {
			fields = append(fields, field(l.key, arrayLiteral(l.items), len(l.items) > 0))
		}
	}
	if given["env"] {
		m, err := pairs(env, "env")
		if err != nil {
			return failf(st, ExitUsage, "%v", err)
		}
		for _, k := range sortedKeys(m) {
			if err := refusePlainCredential("env."+k, m[k]); err != nil {
				return failf(st, ExitUsage, "%v", err)
			}
		}
		fields = append(fields, field("env", inlineTable(m), len(m) > 0))
	}
	if given["tty"] {
		fields = append(fields, field("tty", "true", *tty)) // false is the default: no key
	}
	if code := refuseUnderAgent(st, "profile "+sub, "decides which secrets a program gets"); code != 0 {
		return code
	}
	if code := startUserConfig(st); code != 0 {
		return code
	}
	path, code := editUserConfig(st, func(data []byte) ([]byte, error) {
		u, err := config.ParseUser("", data)
		if err != nil {
			return nil, err
		}
		_, there := u.Profiles[name]
		switch {
		case sub == "add" && there:
			return nil, fmt.Errorf("profiles.%s is already defined; change it with `passess profile set %s`", name, name)
		case sub == "set" && !there:
			return nil, fmt.Errorf("profiles.%s is not defined; add it first", name)
		}
		return config.SetTableFields(data, []string{"profiles", name}, fields, sub == "add")
	})
	if code != 0 {
		return code
	}
	verb := map[string]string{"add": "added", "set": "updated"}[sub]
	fmt.Fprintf(st.Stdout, "%s profile %s in %s; run it with `passess run %s -- COMMAND`\n", verb, name, path, name)
	return ExitOK
}

// --- agent config ---

type agentConfigView struct {
	CacheTTL        string `json:"cache_ttl"`
	ApprovalTTL     string `json:"approval_ttl"`
	ApprovalTimeout string `json:"approval_timeout"`
}

// agentConfig shows or sets [agent]. A duration of "" goes back to the
// default. Approvals are the user's line of defense, so changing how long
// they last is the user's to do.
func agentConfig(st *Streams, args []string) int {
	fs := flag.NewFlagSet("agent config", flag.ContinueOnError)
	fs.SetOutput(st.Stderr)
	fs.Usage = func() {
		fmt.Fprintln(st.Stderr, "Usage: passess agent config [--json] [--cache-ttl D] [--approval-ttl D] [--approval-timeout D]\n"+
			"  durations such as 10m or 8h; 0 turns caching or remembering off; \"\" is the default")
	}
	asJSON := fs.Bool("json", false, "print the settings as JSON")
	durs := map[string]*string{
		"cache_ttl":        fs.String("cache-ttl", "", "how long the agent keeps values it resolved"),
		"approval_ttl":     fs.String("approval-ttl", "", "how long an Allow lasts"),
		"approval_timeout": fs.String("approval-timeout", "", "how long a question waits for an answer"),
	}
	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}
	if fs.NArg() > 0 {
		return failf(st, ExitUsage, "unexpected argument %q", fs.Arg(0))
	}
	var fields []config.Field
	fs.Visit(func(f *flag.Flag) {
		if key := strings.ReplaceAll(f.Name, "-", "_"); durs[key] != nil {
			v := strings.TrimSpace(*durs[key])
			fields = append(fields, field(key, tomlString(v), v != ""))
		}
	})
	if len(fields) == 0 {
		u, err := loadUserConfig(st)
		if err != nil && !errors.Is(err, config.ErrNoConfig) {
			return failf(st, ExitConfig, "%v", err)
		}
		v := agentConfigView{config.DefaultCacheTTL.String(), config.DefaultApprovalTTL.String(), config.DefaultApprovalTimeout.String()}
		if u != nil {
			v = agentConfigView{u.Agent.CacheTTL.String(), u.Agent.ApprovalTTL.String(), u.Agent.ApprovalTimeout.String()}
		}
		if *asJSON {
			return writeJSON(st, v)
		}
		fmt.Fprintf(st.Stdout, "cache_ttl         %s\napproval_ttl      %s\napproval_timeout  %s\n", v.CacheTTL, v.ApprovalTTL, v.ApprovalTimeout)
		return ExitOK
	}
	for _, f := range fields {
		if f.Value == nil {
			continue
		}
		if _, err := time.ParseDuration(strings.Trim(*f.Value, `"`)); err != nil {
			return failf(st, ExitUsage, "--%s takes a duration such as 10m or 8h", strings.ReplaceAll(f.Key, "_", "-"))
		}
	}
	if code := refuseUnderAgent(st, "agent config", "decides how long approvals and cached values last"); code != 0 {
		return code
	}
	if code := startUserConfig(st); code != 0 {
		return code
	}
	path, code := editUserConfig(st, func(data []byte) ([]byte, error) {
		return config.SetTableFields(data, []string{"agent"}, fields, true)
	})
	if code != 0 {
		return code
	}
	fmt.Fprintf(st.Stdout, "updated agent settings in %s\n", path)
	return ExitOK
}
