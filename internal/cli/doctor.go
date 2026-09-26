package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"sort"

	"github.com/afsharid/passess/internal/buildinfo"
	"github.com/afsharid/passess/internal/config"
	"github.com/afsharid/passess/internal/detect"
	"github.com/afsharid/passess/internal/ref"
)

func init() {
	commands["doctor"] = command{"check the configuration and backends, and say how to fix what is wrong", runDoctor}
}

type fileStatus struct {
	Path  string `json:"path"`
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

type backendStatus struct {
	Scheme string `json:"scheme"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail,omitempty"`
}

type problem struct {
	Severity string `json:"severity"` // error | warning
	Message  string `json:"message"`
	Fix      string `json:"fix,omitempty"`
}

type doctorOutput struct {
	Version  string          `json:"version"`
	OK       bool            `json:"ok"`
	Config   fileStatus      `json:"config"`
	Project  *fileStatus     `json:"project,omitempty"`
	Secrets  int             `json:"secrets"`
	Profiles int             `json:"profiles"`
	Backends []backendStatus `json:"backends"`
	Harness  string          `json:"harness,omitempty"`
	Problems []problem       `json:"problems"`
}

func runDoctor(st *Streams, args []string) int {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	fs.SetOutput(st.Stderr)
	asJSON := fs.Bool("json", false, "machine-readable output")
	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}
	out := diagnose(st)
	if *asJSON {
		if code := writeJSON(st, out); code != ExitOK {
			return code
		}
	} else {
		printDoctor(st, out)
	}
	if !out.OK {
		return 1
	}
	return ExitOK
}

func diagnose(st *Streams) doctorOutput {
	out := doctorOutput{Version: buildinfo.String(), Backends: []backendStatus{}, Problems: []problem{}, Harness: detect.Harness(st.Getenv)}
	add := func(sev, msg, fix string) { out.Problems = append(out.Problems, problem{sev, msg, fix}) }

	path, err := config.UserPath(st.Getenv)
	if err != nil {
		add("error", err.Error(), "set HOME or PASSESS_CONFIG")
		return finish(out)
	}
	out.Config.Path = path
	u, err := config.LoadUser(path)
	switch {
	case errors.Is(err, config.ErrNoConfig):
		out.Config.Error = "not found"
		add("error", "no config file", fmt.Sprintf("passess add NAME --ref <reference>, or create %s with version = 1", path))
		return finish(out)
	case err != nil:
		out.Config.Error = err.Error()
		add("error", "the config file does not load", "fix the reported line in "+path)
		return finish(out)
	}
	out.Config.OK = true
	out.Secrets, out.Profiles = len(u.Secrets), len(u.Profiles)
	if st, err := os.Stat(path); err == nil && st.Mode().Perm()&0o077 != 0 {
		add("warning", fmt.Sprintf("%s is readable by other users (%o)", path, st.Mode().Perm()), "chmod 600 "+path)
	}

	var proj *config.Project
	if wd, err := os.Getwd(); err == nil {
		if pf := config.FindProject(wd); pf != "" {
			fsProj := &fileStatus{Path: pf}
			if proj, err = config.LoadProject(pf); err != nil {
				fsProj.Error = err.Error()
				add("error", "the project file does not load", "fix "+pf)
			} else {
				fsProj.OK = true
				var missing []string
				for n := range proj.Needs {
					if _, ok := u.Secrets[n]; !ok {
						missing = append(missing, n)
					}
				}
				sort.Strings(missing)
				for _, n := range missing {
					add("warning", fmt.Sprintf("the project needs %s, which your config does not define", n),
						fmt.Sprintf("passess add %s --ref <reference>", n))
				}
			}
			out.Project = fsProj
		}
	}

	used := map[string]bool{}
	for _, s := range u.Secrets {
		for _, r := range s.Refs {
			used[r.Scheme] = true
		}
	}
	res, zero := newResolver(st, u)
	defer zero()
	schemes := make([]string, 0, len(used))
	for s := range used {
		schemes = append(schemes, s)
	}
	sort.Strings(schemes)
	for _, scheme := range schemes {
		b := backendStatus{Scheme: scheme}
		if tool := cliFor(scheme); tool != "" {
			if _, err := exec.LookPath(tool); err != nil {
				b.Detail = tool + " is not installed or not on PATH"
				add("error", fmt.Sprintf("%s:// references need %s", scheme, tool), installHint(tool))
				out.Backends = append(out.Backends, b)
				continue
			}
		}
		if err := res.Available(context.Background(), scheme); err != nil {
			b.Detail = err.Error()
			add("error", fmt.Sprintf("%s:// is not usable", scheme), fixFor(scheme, u))
		} else {
			b.OK = true
			if scheme == ref.BWS {
				b.Detail = "machine token " + tokenSource(u)
			}
		}
		out.Backends = append(out.Backends, b)
	}
	return finish(out)
}

func finish(out doctorOutput) doctorOutput {
	out.OK = true
	for _, p := range out.Problems {
		if p.Severity == "error" {
			out.OK = false
		}
	}
	return out
}

func cliFor(scheme string) string {
	switch scheme {
	case ref.BWS:
		return "bws"
	case ref.OnePassword:
		return "op"
	case ref.Bitwarden:
		return "bw"
	}
	return ""
}

func installHint(tool string) string {
	switch tool {
	case "bws":
		return "install the Bitwarden Secrets Manager CLI: https://bitwarden.com/help/secrets-manager-cli/"
	case "op":
		return "install the 1Password CLI: brew install 1password-cli"
	case "bw":
		return "install the Bitwarden CLI: brew install bitwarden-cli"
	}
	return "install " + tool
}

func fixFor(scheme string, u *config.User) string {
	switch scheme {
	case ref.BWS:
		if u.Backends.BWS.AccessToken == nil {
			return "store the machine token with `security add-generic-password -U -s passess -a bws -w` and set backends.bws.access_token = \"keychain://passess/bws\""
		}
		return "check that " + u.Backends.BWS.AccessToken.String() + " holds a valid machine-account token"
	case ref.Keychain:
		return "keychain:// works on macOS (security) and Linux (secret-tool)"
	case ref.OnePassword:
		return "unlock the 1Password app and turn on Settings → Developer → Integrate with 1Password CLI, or set OP_SERVICE_ACCOUNT_TOKEN"
	case ref.Vault:
		return "set backends.vault.address (or VAULT_ADDR) and a token: backends.vault.token, VAULT_TOKEN or `vault login`"
	case ref.Bitwarden:
		return "run `bw unlock` and keep the session in backends.bw.session (for example keychain://passess/bw-session)"
	}
	return scheme + ":// is not supported"
}

func tokenSource(u *config.User) string {
	if u.Backends.BWS.AccessToken != nil {
		return "from " + u.Backends.BWS.AccessToken.String()
	}
	return "from BWS_ACCESS_TOKEN"
}

func printDoctor(st *Streams, out doctorOutput) {
	mark := func(ok bool) string {
		if ok {
			return "ok"
		}
		return "FAIL"
	}
	fmt.Fprintf(st.Stdout, "passess %s\n", out.Version)
	fmt.Fprintf(st.Stdout, "config    %-4s %s", mark(out.Config.OK), out.Config.Path)
	if out.Config.OK {
		fmt.Fprintf(st.Stdout, " (%d secrets, %d profiles)", out.Secrets, out.Profiles)
	}
	fmt.Fprintln(st.Stdout)
	if out.Project != nil {
		fmt.Fprintf(st.Stdout, "project   %-4s %s\n", mark(out.Project.OK), out.Project.Path)
	}
	for _, b := range out.Backends {
		fmt.Fprintf(st.Stdout, "%-9s %-4s %s\n", b.Scheme+"://", mark(b.OK), b.Detail)
	}
	if out.Harness != "" {
		fmt.Fprintf(st.Stdout, "harness   %s (output is always redacted here)\n", out.Harness)
	}
	for _, p := range out.Problems {
		fmt.Fprintf(st.Stdout, "\n%s: %s\n", p.Severity, p.Message)
		if p.Fix != "" {
			fmt.Fprintf(st.Stdout, "  fix: %s\n", p.Fix)
		}
	}
}
