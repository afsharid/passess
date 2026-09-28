// Package audit finds settings that hand credentials to agents: harness
// defaults that pass secrets on, credentials in clear in files agents can read,
// and files other users can read. It reads only; each finding says how to fix
// it, and the fix is the person's to run.
package audit

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/pelletier/go-toml/v2"

	"github.com/afsharid/passess/internal/detect"
	"github.com/afsharid/passess/internal/dotenv"
	"github.com/afsharid/passess/internal/harness"
	"github.com/afsharid/passess/internal/policy"
	"github.com/afsharid/passess/internal/scan"
)

// Finding is one problem and its fix. It never holds a value.
type Finding struct {
	Area   string `json:"area"`  // Claude Code, Codex, shell, files
	Check  string `json:"check"` // stable identifier
	Path   string `json:"path,omitempty"`
	Line   int    `json:"line,omitempty"`
	Detail string `json:"detail"`
	Fix    string `json:"fix"`
}

// Input is what the checks look at.
type Input struct {
	Home       string
	ConfigHome string   // XDG_CONFIG_HOME, if set
	Dir        string   // the working directory, for project settings
	Environ    []string // the environment passess runs in
	Harness    string   // the harness passess runs under, if any
	Adapters   []harness.Adapter
	Config     string // the passess user config
}

// Run performs every check. Errors are files that exist but could not be read.
func Run(in Input) ([]Finding, []error) {
	var out []Finding
	var errs []error
	for _, check := range []func(Input) ([]Finding, error){
		claudeSettingsEnv, mcpInline, kiroAgents, codexShellEnv, dotfileCredentials, environment, permissions,
	} {
		f, err := check(in)
		out = append(out, f...)
		if err != nil {
			errs = append(errs, err)
		}
	}
	return out, errs
}

func adapter(in Input, id string) harness.Adapter {
	for _, a := range in.Adapters {
		if a.ID() == id {
			return a
		}
	}
	return nil
}

// secretInClear is the test for a literal value: a credential by its name or
// its shape, and not a reference or a command that fetches it.
func secretInClear(name, value string) bool {
	v := strings.TrimSpace(value)
	if v == "" || policy.IsReference(v) || strings.HasPrefix(v, "$(") || strings.HasPrefix(v, "`") {
		return false
	}
	return policy.Sensitive(name) || policy.LooksLikeSecretNamed(name, v)
}

// mcpInline reports MCP entries that hold credentials in clear.
func mcpInline(in Input) ([]Finding, error) {
	var out []Finding
	var errs []error
	for _, a := range in.Adapters {
		if !a.Installed() {
			continue
		}
		entries, err := a.Entries()
		if err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				errs = append(errs, err)
			}
			continue
		}
		for _, e := range entries {
			if len(e.Leaks) == 0 {
				continue
			}
			out = append(out, Finding{
				Area: a.Label(), Check: "mcp-inline", Path: a.ConfigPath(),
				Detail: fmt.Sprintf("MCP server %q holds %s in clear; agents can read this file", e.Name, names(e.Leaks)),
				Fix:    fmt.Sprintf("passess migrate mcp %s %s", a.ID(), shellQuote(clean(e.Name))),
			})
		}
	}
	return out, errors.Join(errs...)
}

// kiroAgents reports Kiro agent profiles that do not load the global MCP
// config (includeMcpJson defaults to false), so servers installed there never
// reach them, and servers a profile defines itself with credentials in clear.
func kiroAgents(in Input) ([]Finding, error) {
	paths, _ := filepath.Glob(filepath.Join(in.Home, ".kiro", "agents", "*.json"))
	sort.Strings(paths)
	var ignoring []string
	var out []Finding
	var errs []error
	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		var agent struct {
			IncludeMCPJSON *bool                     `json:"includeMcpJson"`
			MCPServers     map[string]map[string]any `json:"mcpServers"`
		}
		err = json.Unmarshal(data, &agent)
		clear(data)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s is not valid JSON", p))
			continue
		}
		name := strings.TrimSuffix(filepath.Base(p), ".json")
		if agent.IncludeMCPJSON == nil || !*agent.IncludeMCPJSON {
			ignoring = append(ignoring, name)
		}
		for _, server := range sortedKeys(agent.MCPServers) {
			env, _ := agent.MCPServers[server]["env"].(map[string]any)
			var clearKeys []string
			for _, k := range sortedKeys(env) {
				if v, ok := env[k].(string); ok && secretInClear(k, v) {
					clearKeys = append(clearKeys, "env."+k)
				}
			}
			if len(clearKeys) > 0 {
				out = append(out, Finding{
					Area: "Kiro", Check: "mcp-inline", Path: p,
					Detail: fmt.Sprintf("agent %s's MCP server %q holds %s in clear; agents can read this file", display(name), server, names(clearKeys)),
					Fix:    "store the value with `passess add NAME --keychain`, define the server under [mcp] in the passess config, and point the agent's entry at `passess mcp-exec " + shellQuote(clean(server)) + "`",
				})
			}
		}
	}
	if len(ignoring) > 0 {
		out = append(out, Finding{
			Area: "Kiro", Check: "kiro-agents", Path: filepath.Join(in.Home, ".kiro", "agents"),
			Detail: fmt.Sprintf("%d agent profile(s) do not load ~/.kiro/settings/mcp.json, so servers passess installs there never reach them: %s",
				len(ignoring), strings.Join(ignoring, ", ")),
			Fix: "set \"includeMcpJson\": true in each profile that should get them (a profile's own mcpServers still come first)",
		})
	}
	return out, errors.Join(errs...)
}

// claudeSettingsEnv reports credentials in the env of Claude Code settings,
// which every session and every command it runs receives.
func claudeSettingsEnv(in Input) ([]Finding, error) {
	var out []Finding
	var errs []error
	paths := []string{filepath.Join(in.Home, ".claude", "settings.json"), filepath.Join(in.Home, ".claude", "settings.local.json")}
	if in.Dir != "" && in.Dir != in.Home {
		paths = append(paths, filepath.Join(in.Dir, ".claude", "settings.json"), filepath.Join(in.Dir, ".claude", "settings.local.json"))
	}
	for _, p := range paths {
		data, err := os.ReadFile(p)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			errs = append(errs, err)
			continue
		}
		var doc struct {
			Env map[string]any `json:"env"`
		}
		err = json.Unmarshal(data, &doc)
		clear(data)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s is not valid JSON", p))
			continue
		}
		for _, k := range sortedKeys(doc.Env) {
			if v, ok := doc.Env[k].(string); ok && secretInClear(k, v) {
				out = append(out, Finding{
					Area: "Claude Code", Check: "claude-settings-env", Path: p,
					Detail: fmt.Sprintf("env.%s gives a credential in clear to every session, every command it runs and every MCP server", display(k)),
					Fix:    removeFix("env.", k, "from this file"),
				})
			}
		}
	}
	return out, errors.Join(errs...)
}

// Codex's shell_environment_policy, measured on codex-cli 0.155 with
// `codex sandbox -- env`: with no policy, variables named *KEY*, *SECRET* and
// *TOKEN* reach the commands the agent runs; ignore_default_excludes = false
// drops those three, and *PASSWORD* needs an explicit exclude.
const codexFix = `[shell_environment_policy]
ignore_default_excludes = false
exclude = ["*PASSWORD*", "*PASSWD*"]`

func codexShellEnv(in Input) ([]Finding, error) {
	a := adapter(in, "codex")
	if a == nil {
		return nil, nil
	}
	path := a.ConfigPath()
	data, err := os.ReadFile(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		if !a.Installed() {
			return nil, nil
		}
		data = nil
	case err != nil:
		return nil, err
	}
	var doc struct {
		Policy *struct {
			Inherit               string         `toml:"inherit"`
			IgnoreDefaultExcludes *bool          `toml:"ignore_default_excludes"`
			Exclude               []string       `toml:"exclude"`
			Set                   map[string]any `toml:"set"`
		} `toml:"shell_environment_policy"`
	}
	err = toml.Unmarshal(data, &doc)
	clear(data)
	if err != nil {
		return nil, fmt.Errorf("%s is not valid TOML", path)
	}
	p := doc.Policy
	if p == nil {
		return []Finding{{
			Area: "Codex", Check: "codex-shell-env", Path: path,
			Detail: "commands the agent runs receive every variable in Codex's environment, *KEY*, *SECRET* and *TOKEN* ones included (Codex sets no shell_environment_policy by default)",
			Fix:    "add to " + path + ":\n" + codexFix,
		}}, nil
	}
	var out []Finding
	inheritsAll := p.Inherit == "" || p.Inherit == "all"
	switch {
	case inheritsAll && (p.IgnoreDefaultExcludes == nil || *p.IgnoreDefaultExcludes):
		out = append(out, Finding{
			Area: "Codex", Check: "codex-shell-env", Path: path,
			Detail: "commands the agent runs receive *KEY*, *SECRET* and *TOKEN* variables: ignore_default_excludes is not false",
			Fix:    "set in [shell_environment_policy] of " + path + ":\nignore_default_excludes = false\nexclude = [\"*PASSWORD*\", \"*PASSWD*\"]",
		})
	case inheritsAll:
		var missing []string
		for _, name := range []string{"DB_PASSWORD", "MYSQL_PASSWD"} {
			if !globsMatch(p.Exclude, name) {
				missing = append(missing, name)
			}
		}
		if len(missing) > 0 {
			out = append(out, Finding{
				Area: "Codex", Check: "codex-shell-env-password", Path: path,
				Detail: fmt.Sprintf("variables such as %s still reach the commands the agent runs: the default filter covers KEY, SECRET and TOKEN only", strings.Join(missing, " and ")),
				Fix:    "add to [shell_environment_policy] of " + path + ":\nexclude = [\"*PASSWORD*\", \"*PASSWD*\"]",
			})
		}
	}
	for _, k := range sortedKeys(p.Set) {
		if v, ok := p.Set[k].(string); ok && secretInClear(k, v) {
			out = append(out, Finding{
				Area: "Codex", Check: "codex-shell-env-set", Path: path,
				Detail: fmt.Sprintf("shell_environment_policy.set.%s puts a credential in clear into every command the agent runs", display(k)),
				Fix:    removeFix("set.", k, ""),
			})
		}
	}
	return out, nil
}

// globsMatch reports whether a Codex exclude pattern (case-insensitive,
// * and ? wildcards) matches name.
func globsMatch(patterns []string, name string) bool {
	for _, p := range patterns {
		if ok, _ := filepath.Match(strings.ToUpper(p), strings.ToUpper(name)); ok {
			return true
		}
	}
	return false
}

var shellRCs = []string{".zshrc", ".zprofile", ".zshenv", ".bashrc", ".bash_profile", ".profile", ".config/fish/config.fish"}

// fish: set -gx NAME value, set -x NAME value, set -Ux NAME value
var fishSet = regexp.MustCompile(`^\s*set\s+(?:-[A-Za-z]+\s+)*([A-Za-z_][A-Za-z0-9_]*)\s+(.+?)\s*$`)

// dotfileCredentials reports credentials written in clear into shell startup
// files: any agent can read them, and exported ones reach every program.
func dotfileCredentials(in Input) ([]Finding, error) {
	var out []Finding
	var errs []error
	for _, rel := range shellRCs {
		p := filepath.Join(in.Home, rel)
		data, err := os.ReadFile(p)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			errs = append(errs, err)
			continue
		}
		var entries []dotenv.Entry
		if strings.HasSuffix(rel, ".fish") {
			for i, line := range strings.Split(string(data), "\n") {
				if m := fishSet.FindStringSubmatch(line); m != nil {
					entries = append(entries, dotenv.Entry{Line: i + 1, Key: m[1], Value: strings.Trim(m[2], `"'`)})
				}
			}
		} else {
			entries = dotenv.Parse(string(data))
		}
		clear(data)
		for _, e := range entries {
			if !secretInClear(e.Key, e.Value) {
				continue
			}
			fix := fmt.Sprintf("delete line %d", e.Line)
			if identifier.MatchString(e.Key) {
				fix = fmt.Sprintf("passess add %s --keychain   # you type the value\nthen delete line %d; programs that need it: passess exec -s %s -- PROGRAM", e.Key, e.Line, e.Key)
			}
			out = append(out, Finding{
				Area: "shell", Check: "dotfile-credential", Path: p, Line: e.Line,
				Detail: fmt.Sprintf("%s is set in clear in a file every agent can read, and every program started from the shell may inherit it", display(e.Key)),
				Fix:    fix,
			})
		}
	}
	return out, errors.Join(errs...)
}

// environment reports credentials in the environment passess itself runs in:
// every harness started from it inherits them.
func environment(in Input) ([]Finding, error) {
	var names []string
	own, skipped := detect.OwnPrefix(in.Harness), 0
	for _, kv := range in.Environ {
		k, v, ok := strings.Cut(kv, "=")
		switch {
		case !ok || v == "" || !policy.Sensitive(k):
		case own != "" && strings.HasPrefix(k, own):
			skipped++ // the harness's own, not the user's to move
		default:
			names = append(names, k)
		}
	}
	if len(names) == 0 {
		return nil, nil
	}
	sort.Strings(names)
	where := "this shell"
	if in.Harness != "" {
		where = in.Harness + "'s environment"
		if skipped > 0 {
			where += fmt.Sprintf(" (leaving out %d it sets for itself)", skipped)
		}
	}
	return []Finding{{
		Area: "shell", Check: "environment",
		Detail: fmt.Sprintf("%d credential variable(s) are set in %s: %s. Every harness started from it inherits them and can pass them on to MCP servers and commands",
			len(names), where, strings.Join(names, ", ")),
		Fix: "find where each is set (shell startup files, launchctl setenv, direnv), move it into passess with `passess add NAME --ref …` or `--keychain`, and delete the export",
	}}, nil
}

// permissions reports harness configs and credential files that other users
// on the machine can read.
func permissions(in Input) ([]Finding, error) {
	type file struct{ path, holds string }
	var files []file
	for _, p := range scan.KnownConfigs(in.Home, in.ConfigHome) {
		if kiroProfile(in, p) && !holdsCredential(p) {
			continue // kiroAgents reports what a profile holds; its mode alone says little
		}
		if definesServersOrEnv(p) {
			files = append(files, file{p, "harness config, which can hold credentials"})
		}
	}
	if in.Config != "" {
		files = append(files, file{in.Config, "passess config"})
	}
	for _, c := range scan.CredentialFiles {
		files = append(files, file{filepath.Join(in.Home, c.Path), c.Holds})
	}
	var out []Finding
	seen := map[string]bool{}
	for _, f := range files {
		if seen[f.path] {
			continue
		}
		seen[f.path] = true
		st, err := os.Stat(f.path)
		if err != nil || !st.Mode().IsRegular() || st.Mode().Perm()&0o077 == 0 {
			continue
		}
		out = append(out, Finding{
			Area: "files", Check: "permissions", Path: f.path,
			Detail: fmt.Sprintf("other users on this machine can read it (mode %04o): %s", st.Mode().Perm(), f.holds),
			Fix:    "chmod 600 " + shellQuote(f.path),
		})
	}
	return out, nil
}

func kiroProfile(in Input, p string) bool {
	return filepath.Dir(p) == filepath.Join(in.Home, ".kiro", "agents")
}

// holdsCredential reports a JSON config with a credential in clear in any
// server's env.
func holdsCredential(p string) bool {
	data, err := os.ReadFile(p)
	if err != nil {
		return false
	}
	defer clear(data)
	var doc struct {
		MCPServers map[string]map[string]any `json:"mcpServers"`
	}
	if json.Unmarshal(data, &doc) != nil {
		return false
	}
	for _, srv := range doc.MCPServers {
		env, _ := srv["env"].(map[string]any)
		for k, v := range env {
			if s, ok := v.(string); ok && secretInClear(k, s) {
				return true
			}
		}
	}
	return false
}

// definesServersOrEnv tells files made for MCP servers apart from editor
// settings files, which are 0644 by default and usually hold no credential:
// a settings.json counts only once it defines servers or an environment.
func definesServersOrEnv(path string) bool {
	if b := filepath.Base(path); b != "settings.json" && b != "settings.local.json" {
		return true
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	defer clear(data)
	for _, key := range []string{`"mcpServers"`, `"mcp"`, `"context_servers"`, `"env"`} {
		if bytes.Contains(data, []byte(key)) {
			return true
		}
	}
	return false
}

var (
	identifier = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)   // fit for a command line
	plainName  = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.-]*$`) // env.X, header.X-Y
)

// display is a name read from a file, fit to print: as it is when it is a
// plain name, Go-quoted otherwise so that no control character (a newline, a
// terminal escape) reaches the report.
func display(s string) string {
	if plainName.MatchString(s) {
		return s
	}
	return fmt.Sprintf("%q", s)
}

func names(ss []string) string {
	out := make([]string, len(ss))
	for i, s := range ss {
		out[i] = display(s)
	}
	return strings.Join(out, ", ")
}

// clean drops control characters from s.
func clean(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
}

// removeFix says to remove prefix+k, and offers the passess command only for
// a name that can be one: the fix line is meant to be copied into a shell.
func removeFix(prefix, k, where string) string {
	fix := "remove " + prefix + display(k)
	if where != "" {
		fix += " " + where
	}
	if identifier.MatchString(k) {
		fix += "; give it to the one program that needs it: passess exec -s " + k + " -- PROGRAM"
	}
	return fix
}

func shellQuote(s string) string {
	if strings.ContainsAny(s, " \t'\"$`\\!*?[]{}()<>|&;#~") {
		return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
	}
	return s
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
