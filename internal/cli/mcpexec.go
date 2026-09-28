package cli

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"

	"github.com/afsharid/passess/internal/config"
	"github.com/afsharid/passess/internal/launch"
	"github.com/afsharid/passess/internal/mcpbridge"
	"github.com/afsharid/passess/internal/policy"
	"github.com/afsharid/passess/internal/provider"
	"github.com/afsharid/passess/internal/redact"
	"github.com/afsharid/passess/internal/secret"
)

func init() {
	commands["mcp-exec"] = command{"start the MCP server defined as [mcp.NAME] (what harness configs call)", runMCPExec}
}

// augmentPath appends the usual install locations to PATH. Harnesses started
// from the Dock hand their MCP servers a minimal PATH, which would hide both
// the server's own command and backend CLIs such as bws.
func augmentPath(getenv func(string) string) {
	path := getenv("PATH")
	have := map[string]bool{}
	for _, d := range filepath.SplitList(path) {
		have[d] = true
	}
	home := getenv("HOME")
	for _, d := range []string{home + "/.local/bin", home + "/go/bin", "/opt/homebrew/bin", "/usr/local/bin", "/usr/bin", "/bin", "/usr/sbin", "/sbin"} {
		if d != "/.local/bin" && d != "/go/bin" && !have[d] {
			path += string(filepath.ListSeparator) + d
			have[d] = true
		}
	}
	_ = os.Setenv("PATH", strings.TrimPrefix(path, string(filepath.ListSeparator)))
}

func runMCPExec(st *Streams, args []string) int {
	if len(args) != 1 || strings.HasPrefix(args[0], "-") {
		fmt.Fprintln(st.Stderr, "Usage: passess mcp-exec NAME")
		fmt.Fprintln(st.Stderr, "The command, url and secrets of the server live in [mcp.NAME] of your passess config;")
		fmt.Fprintln(st.Stderr, "nothing on this command line can change them.")
		return ExitUsage
	}
	name := args[0]
	augmentPath(st.Getenv)

	// Only the user config: harnesses start servers in whatever project is open,
	// and a project file has no say over MCP servers.
	path, err := config.UserPath(st.Getenv)
	if err != nil {
		return failf(st, ExitConfig, "%v", err)
	}
	u, err := config.LoadUser(path)
	if err != nil {
		return failf(st, ExitConfig, "%v", err)
	}
	srv, ok := u.MCP[name]
	if !ok {
		return failf(st, ExitConfig, "no MCP server %q in %s", name, u.Path)
	}

	var prog policy.Program
	if len(srv.Command) > 0 {
		if prog, err = policy.Inspect(srv.Command[0], mcpLookPath); err != nil {
			hint := ""
			if !filepath.IsAbs(srv.Command[0]) {
				hint = "; passess looks only in the standard install locations, so give its absolute path in mcp." + name + ".command"
			}
			return failf(st, ExitNotFound, "mcp.%s: %v%s", name, err, hint)
		}
		for _, s := range srv.Secrets() {
			if d := policy.CheckConfigured(s, prog, u.Secrets[s].Allow); !d.Allowed {
				return failf(st, ExitNoPerm, "mcp.%s: refusing to give %s to this server: %s", name, s, d.Reason)
			}
		}
	}

	// A remote server's secrets go to passess's own bridge. The agent finds
	// the program for itself, so name this one by a path it cannot miss.
	argv := srv.Command
	if len(argv) == 0 {
		self, err := os.Executable()
		if err != nil {
			self = "passess"
		}
		argv = []string{self, "mcp-exec", name}
	}
	if code := askApproval(st, u, srv.Secrets(), argv); code != 0 {
		return code
	}
	res, zero := newResolver(st, u)
	defer zero()
	values := map[string]secret.Value{}
	var named []redact.Secret
	for _, s := range srv.Secrets() {
		v, err := res.Secret(context.Background(), u.Secrets[s])
		if err != nil {
			return failf(st, resolveExitCode(err), "mcp.%s: %v", name, err)
		}
		values[s] = v
		named = append(named, redact.Secret{Name: s, Value: v})
	}
	rd, _, err := redact.New(named, redact.Options{})
	if err != nil {
		return failf(st, ExitConfig, "mcp.%s: %v", name, err)
	}
	defer rd.Zero()

	if srv.URL != "" {
		headers := http.Header{}
		for h, tmpl := range srv.Headers {
			headers.Set(h, config.Expand(tmpl, func(s string) string { return string(values[s].Bytes()) }))
		}
		in, ok := st.Stdin.(io.ReadCloser)
		if !ok {
			in = io.NopCloser(st.Stdin)
		}
		if err := mcpbridge.Run(context.Background(), srv.URL, headers, in, st.Stdout, rd); err != nil {
			return failf(st, ExitUnavailable, "mcp.%s: remote server: %v", name, err)
		}
		return ExitOK
	}

	inject := map[string]secret.Value{}
	for envName, s := range srv.Env {
		inject[envName] = values[s]
	}
	env := mcpEnv(st.Getenv, srv, inject, filepath.Dir(prog.Path))
	if !srv.Redact {
		if err := prog.Unchanged(); err != nil {
			return failf(st, ExitNotExec, "mcp.%s: %v", name, err)
		}
		err := syscall.Exec(prog.Path, srv.Command, env)
		return failf(st, ExitNotExec, "mcp.%s: %v", name, err)
	}
	status, err := launch.Run(launch.Spec{
		Path: prog.Path, Argv: srv.Command, Env: env,
		Stdin: st.Stdin, Stdout: st.Stdout, Stderr: st.Stderr,
		Redactor: rd, ForwardInterrupt: true, Verify: prog.Unchanged,
	})
	if err != nil && status >= launch.NotExecutable {
		return failf(st, status, "mcp.%s: %v", name, err)
	}
	return status
}

// mcpEnv is a server's environment: the safe caller variables, those it
// inherits, its plain vars and its secrets — nothing else from the harness.
// mcpLookPath finds a configured server's command. An absolute path in the
// config is used as written; a bare name is looked up only in install
// locations, not on the caller's PATH, which would otherwise choose the
// program that receives the server's secrets.
func mcpLookPath(name string) (string, error) {
	if filepath.IsAbs(name) {
		return name, nil
	}
	if strings.ContainsRune(name, filepath.Separator) {
		return "", fmt.Errorf("%s: give the command as a bare name or an absolute path", name)
	}
	p, err := provider.LookTrusted(name)
	if err != nil {
		return "", fmt.Errorf("%s is not in a standard install location; give its absolute path in the config", name)
	}
	return p, nil
}

// mcpEnv is the server's environment. Its PATH is the command's own
// directory, then the install locations: what the server starts in turn
// (node for npx, say) comes from there, not from the caller's PATH.
func mcpEnv(getenv func(string) string, srv config.MCPServer, inject map[string]secret.Value, progDir string) []string {
	vars := map[string]string{}
	for _, k := range append(append([]string{}, safeEnv...), srv.Inherit...) {
		if v := getenv(k); v != "" {
			vars[k] = v
		}
	}
	for _, kv := range os.Environ() {
		if k, v, _ := strings.Cut(kv, "="); strings.HasPrefix(k, "LC_") {
			vars[k] = v
		}
	}
	vars["PATH"] = provider.TrustedPath()
	if progDir != "" && progDir != "." {
		vars["PATH"] = progDir + string(filepath.ListSeparator) + vars["PATH"]
	}
	for k, v := range srv.Vars {
		vars[k] = v
	}
	env := make([]string, 0, len(vars)+len(inject))
	for k, v := range vars {
		if _, isSecret := inject[k]; !isSecret {
			env = append(env, k+"="+v)
		}
	}
	sort.Strings(env)
	names := make([]string, 0, len(inject))
	for k := range inject {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, k := range names {
		env = append(env, k+"="+string(inject[k].Bytes()))
	}
	return env
}
