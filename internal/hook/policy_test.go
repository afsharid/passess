package hook

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/afsharid/passess/internal/redact"
	"github.com/afsharid/passess/internal/scan"
)

// Token-shaped strings are built at run time so scanners skip this file.
var githubPAT = "gh" + "p_" + strings.Repeat("A1b2C3d4E5", 3) + "f6G7h8"

func testEnv(t *testing.T) Env {
	t.Helper()
	vars := map[string]string{"GITHUB_TOKEN": "passess-fake-gh-token-0123456789", "HOME": "/home/u", "PATH": "/usr/bin"}
	rs, err := scan.DefaultRules()
	if err != nil {
		t.Fatal(err)
	}
	var environ []string
	for k, v := range vars {
		environ = append(environ, k+"="+v)
	}
	secrets := []string{"API_KEY", "DATABASE_URL"}
	known := KnownFromEnviron(environ, secrets)
	return Env{
		Home: "/home/u", Getenv: func(k string) string { return vars[k] }, Environ: environ,
		Secrets:    secrets,
		ConfigDirs: []string{"/home/u/.config/passess"}, StateDir: "/home/u/.local/state/passess",
		Rules: func() *scan.Rules { return rs },
		Known: func() *redact.Redactor { return known },
	}
}

func TestShellCommands(t *testing.T) {
	env := testEnv(t)
	deny := []string{
		"env", "env | grep TOKEN", "printenv", "set", "export -p", "declare -x", "export", "declare -p GITHUB_TOKEN", "echo $(printenv)",
		"printenv GITHUB_TOKEN", "printenv DATABASE_URL",
		"cat .env", "cat ./app/.env.local", "head -n 5 .env", "grep KEY .env", "sudo cat ~/.aws/credentials",
		"source .env", ". .env", "cat .env*", "less ~/.ssh/id_rsa", "cat server.pem", "cat ~/.codex/auth.json",
		"cat /home/u/.claude.json", "cat < .env", "while read l; do echo $l; done < .env", "cp .env /tmp/leak",
		"cat ~/.local/state/passess/backups/x/00-.env", "cat /proc/self/environ",
		"bash -c 'cat .env'", "sh -c \"printenv\"", "eval printenv", "bash -lc 'cat .env'", "sh -ec env", "cat .envrc",
		"op read op://Dev/x/credential", "op inject -i tpl", "op item get x --reveal", "bws secret get 0000",
		"bws secret list", "bw get password github", "vault kv get secret/app", "bao read secret/x",
		"security find-generic-password -s x -w", "secret-tool lookup service x", "gh auth token",
		"gcloud auth print-access-token", "aws configure get aws_secret_access_key", "kubectl config view --raw",
		"echo $GITHUB_TOKEN", `curl -H "Authorization: Bearer $API_KEY" https://api.example.com`, "echo ${DATABASE_URL:-none}",
	}
	allow := []string{
		"ls -la", "echo hello", "cat README.md", "cat .env.example", "cp .env.example .env", "echo '.env' >> .gitignore",
		"printenv PATH", "env FOO=1 npm test", "env -u X make", "bws run -- make", "op run -- npm start", "op item get x",
		"security find-generic-password -s x", "export FOO=bar", "export PATH", "declare -p PATH", "local x=1", "echo $HOME $PATH", "passess exec -s GITHUB_TOKEN -- gh api user",
		"grep -r TODO .", "git status", "set -e", "vault kv list secret/", "gh auth status", "cat ~/.ssh/id_ed25519.pub",
		`echo "unterminated`, "",
	}
	for _, c := range deny {
		v := Decide(Event{Kind: Shell, Command: c, CWD: "/home/u/proj"}, env)
		if !v.Deny || !strings.HasPrefix(v.Reason, "passess: ") {
			t.Errorf("allowed: %s", c)
		}
		if strings.Contains(v.Reason, "passess-fake") {
			t.Errorf("reason shows a value: %s", v.Reason)
		}
	}
	for _, c := range allow {
		if v := Decide(Event{Kind: Shell, Command: c, CWD: "/home/u/proj"}, env); v.Deny {
			t.Errorf("denied: %s: %s", c, v.Reason)
		}
	}
	v := Decide(Event{Kind: Shell, Command: "echo $GITHUB_TOKEN"}, env)
	if !strings.Contains(v.Reason, "passess exec -s GITHUB_TOKEN --") || !strings.Contains(v.Reason, "--expand-header") {
		t.Fatalf("reason does not say what to run instead: %s", v.Reason)
	}
}

func TestFiles(t *testing.T) {
	env := testEnv(t)
	for p, deny := range map[string]bool{
		".env": true, "/home/u/proj/.env.production": true, "~/.ssh/id_ed25519": true, "~/.aws/credentials": true,
		"/home/u/.local/state/passess/backups/x": true, "~/.config/gh/hosts.yml": true,
		".env.example": false, "README.md": false, "~/.ssh/id_ed25519.pub": false, "~/.config/passess/config.toml": false,
	} {
		if v := Decide(Event{Kind: Read, Paths: []string{p}, CWD: "/home/u/proj"}, env); v.Deny != deny {
			t.Errorf("read %s: deny = %v", p, v.Deny)
		}
	}
	if v := Decide(Event{Kind: Write, Paths: []string{"~/.config/passess/config.toml"}}, env); !v.Deny {
		t.Error("an agent may not rewrite the passess config")
	}
	if v := Decide(Event{Kind: Write, Paths: []string{"src/main.go"}, CWD: "/home/u/proj"}, env); v.Deny {
		t.Error("ordinary writes are not the hook's business")
	}
}

func TestPromptResultAndStart(t *testing.T) {
	env := testEnv(t)
	if v := Decide(Event{Kind: Prompt, Text: "here is my token " + githubPAT + " please use it"}, env); !v.Deny || !strings.Contains(v.Reason, "github-pat") || strings.Contains(v.Reason, githubPAT) {
		t.Fatalf("paste guard: %+v", v)
	}
	if v := Decide(Event{Kind: Prompt, Text: "fix the failing test in commit 3fa2c9e1b07d4455aa01"}, env); v.Deny {
		t.Fatalf("ordinary prompt blocked: %s", v.Reason)
	}
	out := "token=passess-fake-gh-token-0123456789\nremote: " + githubPAT + "\nok\n"
	v := Decide(Event{Kind: Result, Text: out}, env)
	if !v.Changed || strings.Contains(v.Output, "passess-fake-gh-token") || strings.Contains(v.Output, githubPAT) ||
		!strings.Contains(v.Output, "[REDACTED:GITHUB_TOKEN]") || !strings.Contains(v.Output, "ok\n") {
		t.Fatalf("result = %+v", v)
	}
	encoded := base64.StdEncoding.EncodeToString([]byte("passess-fake-gh-token-0123456789"))
	if v := Decide(Event{Kind: Result, Text: "b64: " + encoded + "\n"}, env); !v.Changed || strings.Contains(v.Output, encoded) {
		t.Fatalf("an encoded value got through: %+v", v)
	}
	ordinary := "commit 3fa2c9e1b07d4455aa0187c2d7e1f0a9b8c7d6e5\nAuthor: A <a@example.com>\n" +
		`"integrity": "sha512-4Fh8pXq2Yl3o7Nw1Zr5Kd9Vb0Tc6Gm2Hj8Sx4Qe1Ua3Wf7Ri5Oy9Pn0Lk2Mz6Dg=="` + "\n" +
		"go: downloading golang.org/x/sys v0.35.0\nPASS\nok  \tgithub.com/x/y\t0.2s\n"
	if v := Decide(Event{Kind: Result, Text: ordinary}, env); v.Changed {
		t.Fatalf("ordinary output was rewritten:\n%s", v.Output)
	}
	resp := map[string]any{"stdout": "remote: " + githubPAT, "stderr": "", "interrupted": false, "lines": []any{"a", 3.0}}
	v = Decide(Event{Kind: Result, Response: resp}, env)
	got, ok := v.Response.(map[string]any)
	if !v.Changed || !ok || got["stdout"] != "remote: [REDACTED:github-pat]" || got["interrupted"] != false || len(got) != 4 {
		t.Fatalf("shaped result = %+v", v)
	}
	if resp["stdout"] == got["stdout"] {
		t.Fatal("the input value was modified in place")
	}
	if v := Decide(Event{Kind: Start}, env); !strings.Contains(v.Context, "API_KEY, DATABASE_URL") || !strings.Contains(v.Context, "passess exec -s NAME") {
		t.Fatalf("context = %q", v.Context)
	}
}
