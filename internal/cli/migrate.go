package cli

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/afsharid/passess/internal/config"
	"github.com/afsharid/passess/internal/detect"
	"github.com/afsharid/passess/internal/dotenv"
	"github.com/afsharid/passess/internal/harness"
	"github.com/afsharid/passess/internal/policy"
	"github.com/afsharid/passess/internal/provider"
	"github.com/afsharid/passess/internal/secret"
)

func init() {
	commands["migrate"] = command{"move secrets stored in clear (.env, MCP entries) into the keychain (dry run unless --apply)", runMigrate}
}

// keychainService is where migrated values are stored.
const keychainService = "passess"

// keychainStore writes a value to the OS keychain; tests replace it so they
// never touch the real one.
var keychainStore = func(st *Streams) func(context.Context, string, string, secret.Value) error {
	return provider.Keychain{Runner: provider.ExecRunner{}, Getenv: st.Getenv}.Store
}

func runMigrate(st *Streams, args []string) int {
	usage := func() int {
		fmt.Fprintln(st.Stderr, "Usage: passess migrate env FILE [--apply] [--yes]")
		fmt.Fprintln(st.Stderr, "       passess migrate mcp HARNESS SERVER [--apply] [--yes]")
		fmt.Fprintln(st.Stderr, "Values move into the OS keychain; config gets references, the file loses the value.")
		return ExitUsage
	}
	if len(args) == 0 {
		return usage()
	}
	fs := flag.NewFlagSet("migrate", flag.ContinueOnError)
	fs.SetOutput(st.Stderr)
	apply := fs.Bool("apply", false, "make the changes (without it, only show them)")
	yes := fs.Bool("yes", false, "with --apply: do not ask about each value")
	pos, err := parseAnywhere(fs, args[1:])
	if err != nil {
		return usage()
	}
	m := &migration{st: st, apply: *apply, yes: *yes}
	switch {
	case args[0] == "env" && len(pos) == 1:
		return m.env(pos[0])
	case args[0] == "mcp" && len(pos) == 2:
		return m.mcp(pos[0], pos[1])
	}
	return usage()
}

type migration struct {
	st         *Streams
	apply, yes bool
	all        bool
	in         *bufio.Reader
}

// guard refuses to move values unless a person is running this.
func (m *migration) guard() int {
	if h := detect.Harness(m.st.Getenv); h != "" {
		return failf(m.st, ExitNoPerm, "migrate --apply moves values out of your files; run it yourself in a terminal, not from %s", h)
	}
	if !m.yes && !isTerminal(m.st.Stdin) {
		return failf(m.st, ExitUsage, "migrate --apply asks about each value; run it in a terminal or add --yes")
	}
	return 0
}

// confirm asks y/N/a(ll)/q(uit); the second result is quit.
func (m *migration) confirm(question string) (bool, bool) {
	if m.yes || m.all {
		return true, false
	}
	if m.in == nil {
		m.in = bufio.NewReader(m.st.Stdin)
	}
	fmt.Fprintf(m.st.Stdout, "%s [y/N/a/q] ", question)
	answer, err := m.in.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return false, true
	}
	switch strings.ToLower(strings.TrimSpace(answer)) {
	case "y", "yes":
		return true, false
	case "a", "all":
		m.all = true
		return true, false
	case "q", "quit":
		return false, true
	}
	return false, false
}

func (m *migration) userConfig() (string, *config.User, int) {
	path, err := config.UserPath(m.st.Getenv)
	if err != nil {
		return "", nil, failf(m.st, ExitConfig, "%v", err)
	}
	u, err := config.LoadUser(path)
	switch {
	case errors.Is(err, config.ErrNoConfig):
		return path, &config.User{Path: path, Secrets: map[string]config.Secret{}, MCP: map[string]config.MCPServer{}}, 0
	case err != nil:
		return "", nil, failf(m.st, ExitConfig, "%v", err)
	}
	return path, u, 0
}

func (m *migration) backup(paths ...string) (string, error) {
	return harness.Backup(filepath.Join(stateDir(m.st.Getenv), "backups"), paths, time.Now())
}

var nonIdent = regexp.MustCompile(`[^A-Za-z0-9]+`)

func identifier(s string) string {
	return strings.Trim(strings.ToUpper(nonIdent.ReplaceAllString(s, "_")), "_")
}

// appendConfig adds blocks to the user config and keeps the result only if it loads.
func appendConfig(path string, blocks []byte) error {
	before, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	after := append([]byte{}, before...)
	if len(after) == 0 {
		after = []byte("version = 1\n")
	}
	if !strings.HasSuffix(string(after), "\n") {
		after = append(after, '\n')
	}
	after = append(after, blocks...)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	if err := writeFileAtomic(path, after, 0o600); err != nil {
		return err
	}
	if _, err := config.LoadUser(path); err != nil {
		if len(before) == 0 {
			_ = os.Remove(path)
		} else {
			_ = writeFileAtomic(path, before, 0o600)
		}
		return fmt.Errorf("the new config did not validate, left unchanged: %w", err)
	}
	return nil
}

// --- migrate env ---

type envMove struct {
	dotenv.Entry
	account string
}

func (m *migration) env(file string) int {
	st := m.st
	cfgPath, u, code := m.userConfig()
	if code != 0 {
		return code
	}
	abs, err := filepath.Abs(file)
	if err != nil {
		return failf(st, ExitUsage, "%v", err)
	}
	data, err := os.ReadFile(abs)
	if err != nil {
		return failf(st, ExitUsage, "%v", err)
	}
	project := strings.ToLower(strings.Trim(nonIdent.ReplaceAllString(filepath.Base(filepath.Dir(abs)), "-"), "-"))
	var moves []envMove
	for _, e := range dotenv.Parse(string(data)) {
		secretish := policy.Sensitive(e.Key) || policy.LooksLikeSecret(e.Value)
		switch {
		case e.Value == "" || !secretish:
			continue
		case policy.IsReference(e.Value):
			fmt.Fprintf(st.Stdout, "  skip %s (line %d): refers to another variable; left in the file\n", e.Key, e.Line)
		case !envNameRe.MatchString(e.Key):
			fmt.Fprintf(st.Stdout, "  skip %s (line %d): not usable as a secret name\n", e.Key, e.Line)
		case u.Secrets[e.Key].Name != "":
			fmt.Fprintf(st.Stdout, "  skip %s (line %d): already defined in %s; left in the file\n", e.Key, e.Line, cfgPath)
		case strings.ContainsAny(e.Value, "\n\r"):
			fmt.Fprintf(st.Stdout, "  skip %s (line %d): multi-line values are not moved\n", e.Key, e.Line)
		default:
			moves = append(moves, envMove{Entry: e, account: project + "." + e.Key})
		}
	}
	if len(moves) == 0 {
		fmt.Fprintf(st.Stdout, "Nothing in %s looks like a secret passess should move.\n", file)
		return ExitOK
	}
	for _, mv := range moves {
		fmt.Fprintf(st.Stdout, "  %s (line %d) -> keychain://%s/%s\n", mv.Key, mv.Line, keychainService, mv.account)
	}
	projectFile := filepath.Join(filepath.Dir(abs), config.ProjectFile)
	if !m.apply {
		fmt.Fprintf(st.Stdout, "\nDry run: nothing changed. With --apply the values move into the keychain, %s gets references,\n", cfgPath)
		fmt.Fprintf(st.Stdout, "%s loses those lines and %s lists the names.\n", file, projectFile)
		return ExitOK
	}
	if code := m.guard(); code != 0 {
		return code
	}
	backup, err := m.backup(abs, cfgPath, projectFile)
	if err != nil {
		return failf(st, ExitSoftware, "backup failed, nothing changed: %v", err)
	}

	store := keychainStore(st)
	var blocks []byte
	var names []string
	moved := map[int]bool{}
	for _, mv := range moves {
		ok, quit := m.confirm(fmt.Sprintf("Move %s (line %d) into the keychain?", mv.Key, mv.Line))
		if quit {
			break
		}
		if !ok {
			continue
		}
		v := secret.FromString(mv.Value)
		err := store(context.Background(), keychainService, mv.account, v)
		v.Zero()
		if err != nil {
			fmt.Fprintf(st.Stdout, "  %s: %v (left in the file)\n", mv.Key, err)
			continue
		}
		blocks = append(blocks, secretBlock(mv.Key, []string{"keychain://" + keychainService + "/" + mv.account}, nil, "moved from "+file)...)
		names = append(names, mv.Key)
		moved[mv.Line] = true
	}
	if len(moved) == 0 {
		fmt.Fprintln(st.Stdout, "Nothing moved.")
		return ExitOK
	}
	if err := appendConfig(cfgPath, blocks); err != nil {
		return failf(st, ExitSoftware, "%v; the values are in the keychain, %s is untouched (backup: %s)", err, file, backup)
	}
	perm := os.FileMode(0o600)
	if info, err := os.Stat(abs); err == nil {
		perm = info.Mode().Perm()
	}
	if err := writeFileAtomic(abs, []byte(dotenv.Without(string(data), moved)), perm); err != nil {
		return failf(st, ExitSoftware, "config updated but %s could not be rewritten: %v (backup: %s)", file, err, backup)
	}
	if err := addNeeds(projectFile, names); err != nil {
		fmt.Fprintf(st.Stdout, "note: %s not updated: %v\n", projectFile, err)
	}
	sort.Strings(names)
	fmt.Fprintf(st.Stdout, "\nMoved %d secret(s) into the keychain: %s.\n", len(names), strings.Join(names, ", "))
	fmt.Fprintf(st.Stdout, "%s no longer holds them; backup: %s\n", file, backup)
	fmt.Fprintf(st.Stdout, "Start the app through passess, e.g. add to %s:\n", cfgPath)
	fmt.Fprintf(st.Stdout, "  [profiles.%s]\n  secrets = [%s]\n  allow   = [\"npm\"]   # the program you start\n", project, quoteList(names))
	fmt.Fprintf(st.Stdout, "and run: passess run %s -- npm run dev\n", project)
	fmt.Fprintln(st.Stdout, "If the file was ever committed or shared, rotate these values at their provider.")
	return ExitOK
}

func quoteList(names []string) string {
	q := make([]string, len(names))
	for i, n := range names {
		q[i] = tomlString(n)
	}
	return strings.Join(q, ", ")
}

// addNeeds lists names in a project file, creating it if needed.
func addNeeds(path string, names []string) error {
	data, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	var existing *config.Project
	if len(data) > 0 {
		if existing, err = config.LoadProject(path); err != nil {
			return err
		}
	} else {
		data = []byte("version = 1\n")
	}
	var b strings.Builder
	b.Write(data)
	if !strings.HasSuffix(b.String(), "\n") {
		b.WriteByte('\n')
	}
	for _, n := range names {
		if _, ok := existing.NeedsName(n); ok {
			continue
		}
		fmt.Fprintf(&b, "\n[needs.%s]\n", n)
	}
	if err := writeFileAtomic(path, []byte(b.String()), 0o644); err != nil {
		return err
	}
	_, err = config.LoadProject(path)
	return err
}

// --- migrate mcp ---

type mcpMove struct {
	from    string // env.VAR or headers.H
	secret  string // new secret name
	value   string
	account string
}

func (m *migration) mcp(harnessID, server string) int {
	st := m.st
	var adapter harness.Adapter
	for _, a := range adapters(st) {
		if a.ID() == harnessID {
			adapter = a
		}
	}
	if adapter == nil {
		return failf(st, ExitUsage, "unknown harness %q (known: claude, codex)", harnessID)
	}
	cfgPath, u, code := m.userConfig()
	if code != 0 {
		return code
	}
	if _, ok := u.MCP[server]; ok {
		return failf(st, ExitConfig, "mcp.%s is already defined in %s; use `passess install %s --apply --force`", server, cfgPath, harnessID)
	}
	raw, ok, err := adapter.Raw(server)
	if err != nil {
		return failf(st, ExitConfig, "%v", err)
	}
	if !ok {
		return failf(st, ExitUsage, "%s has no MCP server named %s", adapter.Label(), server)
	}
	var refs []string
	for _, k := range sortedKeys(raw.Env) {
		if policy.IsReference(raw.Env[k]) {
			refs = append(refs, "env."+k)
		}
	}
	for _, h := range sortedKeys(raw.Headers) {
		if policy.IsReference(raw.Headers[h]) {
			refs = append(refs, "headers."+h)
		}
	}
	if len(refs) > 0 {
		return failf(st, ExitConfig, "%s takes %s from %s's environment, so there is no value to move; define it with `passess add`, write [mcp.%s] in %s by hand, then run `passess install %s --apply --force`",
			server, strings.Join(refs, ", "), adapter.Label(), server, cfgPath, harnessID)
	}

	used := map[string]bool{}
	for n := range u.Secrets {
		used[n] = true
	}
	pick := func(preferred string) string {
		base := identifier(preferred)
		if base == "" || (base[0] >= '0' && base[0] <= '9') {
			base = "S_" + base
		}
		name := base
		for i := 2; used[name]; i++ {
			name = fmt.Sprintf("%s_%d", base, i)
		}
		used[name] = true
		return name
	}

	var moves []mcpMove
	envMap, vars := map[string]string{}, map[string]string{}
	for _, k := range sortedKeys(raw.Env) {
		v := raw.Env[k]
		if policy.Sensitive(k) || policy.LooksLikeSecret(v) {
			name := pick(k)
			moves = append(moves, mcpMove{from: "env." + k, secret: name, value: v, account: "mcp." + server + "." + name})
			envMap[k] = name
		} else {
			vars[k] = v
		}
	}
	headers := map[string]string{}
	for _, h := range sortedKeys(raw.Headers) {
		v := raw.Headers[h]
		if !policy.SecretHeader(h, v) {
			headers[h] = v
			continue
		}
		prefix, rest := "", v
		for _, scheme := range []string{"Bearer ", "Token ", "Basic "} {
			if strings.HasPrefix(strings.ToLower(v), strings.ToLower(scheme)) {
				prefix, rest = v[:len(scheme)], v[len(scheme):]
				break
			}
		}
		base := server + "_" + h
		if strings.EqualFold(h, "Authorization") {
			base = server + "_TOKEN"
		}
		name := pick(base)
		moves = append(moves, mcpMove{from: "headers." + h, secret: name, value: rest, account: "mcp." + server + "." + name})
		headers[h] = prefix + "{{" + name + "}}"
	}
	if len(moves) == 0 {
		fmt.Fprintf(st.Stdout, "%s's entry %s holds nothing that looks like a secret; `passess install --force` can still move it.\n", adapter.Label(), server)
		return ExitOK
	}

	block := mcpBlock(server, raw, envMap, vars, headers)
	for _, mv := range moves {
		fmt.Fprintf(st.Stdout, "  %s -> %s at keychain://%s/%s\n", mv.from, mv.secret, keychainService, mv.account)
	}
	fmt.Fprintf(st.Stdout, "\nNew entry for %s:\n%s", cfgPath, block)
	fmt.Fprintf(st.Stdout, "\n%s will start it as `passess mcp-exec %s`.\n", adapter.Label(), server)
	if !m.apply {
		fmt.Fprintln(st.Stdout, "Dry run: nothing changed.")
		return ExitOK
	}
	if code := m.guard(); code != 0 {
		return code
	}
	if ok, _ := m.confirm(fmt.Sprintf("Move %d value(s) from %s into the keychain and switch %s to passess?", len(moves), adapter.ConfigPath(), server)); !ok {
		fmt.Fprintln(st.Stdout, "Nothing changed.")
		return ExitOK
	}
	backup, err := m.backup(adapter.ConfigPath(), cfgPath)
	if err != nil {
		return failf(st, ExitSoftware, "backup failed, nothing changed: %v", err)
	}
	store := keychainStore(st)
	var blocks []byte
	for _, mv := range moves {
		v := secret.FromString(mv.value)
		err := store(context.Background(), keychainService, mv.account, v)
		v.Zero()
		if err != nil {
			return failf(st, ExitUnavailable, "%s: %v; nothing else changed (backup: %s)", mv.secret, err, backup)
		}
		blocks = append(blocks, secretBlock(mv.secret, []string{"keychain://" + keychainService + "/" + mv.account}, nil, "moved from "+adapter.Label()+" "+server)...)
	}
	blocks = append(blocks, block...)
	if err := appendConfig(cfgPath, blocks); err != nil {
		return failf(st, ExitSoftware, "%v (backup: %s)", err, backup)
	}
	self := passessPath()
	for _, cmd := range [][]string{adapter.RemoveCommand(server), adapter.AddCommand(server, []string{self, "mcp-exec", server})} {
		res, err := (provider.ExecRunner{}).Run(context.Background(), provider.Cmd{Name: cmd[0], Args: cmd[1:], Env: os.Environ()})
		if err == nil && res.Exit != 0 {
			err = errors.New(provider.CLIMessage(res.Stderr))
		}
		if err != nil {
			return failf(st, ExitUnavailable, "%s: %v; passess config is updated, finish with `passess install %s --apply --force` (backup: %s)",
				strings.Join(cmd[:3], " "), err, harnessID, backup)
		}
	}
	fmt.Fprintf(st.Stdout, "\n%s now starts %s through passess; backup: %s\n", adapter.Label(), server, backup)
	fmt.Fprintf(st.Stdout, "The credential sat in clear in %s: rotate it at its provider, then update the keychain item.\n", adapter.ConfigPath())
	return ExitOK
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// mcpBlock renders [mcp.NAME]; it holds names and non-secret values only.
func mcpBlock(name string, raw harness.Raw, env, vars, headers map[string]string) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "\n[mcp.%s]\n", tomlKey(name))
	inline := func(m map[string]string) string {
		parts := make([]string, 0, len(m))
		for _, k := range sortedKeys(m) {
			parts = append(parts, tomlKey(k)+" = "+tomlString(m[k]))
		}
		return "{ " + strings.Join(parts, ", ") + " }"
	}
	if raw.URL != "" {
		fmt.Fprintf(&b, "url = %s\n", tomlString(raw.URL))
		if len(headers) > 0 {
			fmt.Fprintf(&b, "headers = %s\n", inline(headers))
		}
		return []byte(b.String())
	}
	argv := append([]string{raw.Command}, raw.Args...)
	quoted := make([]string, len(argv))
	for i, a := range argv {
		quoted[i] = tomlString(a)
	}
	fmt.Fprintf(&b, "command = [%s]\n", strings.Join(quoted, ", "))
	if len(env) > 0 {
		fmt.Fprintf(&b, "env = %s\n", inline(env))
	}
	if len(vars) > 0 {
		fmt.Fprintf(&b, "vars = %s\n", inline(vars))
	}
	return []byte(b.String())
}

var bareKey = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

func tomlKey(k string) string {
	if bareKey.MatchString(k) {
		return k
	}
	return tomlString(k)
}
