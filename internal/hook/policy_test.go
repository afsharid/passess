package hook

import (
	"crypto/sha256"
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
		// Commands that change what protects the user, and hiding the harness.
		"passess add EVIL --ref keychain://passess/X --allow curl", "passess migrate env .env --apply --yes",
		"passess set GITHUB_TOKEN --clients all", "passess remove GITHUB_TOKEN", "passess discover --json",
		"passess uninstall --apply", "passess install --no-hooks --apply",
		"passess browse op --json", "passess backend vault --token", "passess backend op --account x",
		"passess mcp add gh --command gh-mcp --env GH=GITHUB_TOKEN", "passess profile set web --secrets API_KEY",
		"passess mcp remove gh", "passess agent config --approval-ttl 999h",
		// A literal cd earlier in the line moves where relative paths point.
		`cd ~/.config/passess && echo 'allow = ["sh"]' >> config.toml`, "cd ~/.local/state/passess/backups && cat x",
		"pushd ~/.config/passess && echo x > config.toml", "cd ~ && cd .config/passess && echo x >> config.toml",
		"cd -P ~/.config/passess; echo x >> config.toml",
		"env -u CLAUDECODE passess exec -s X -- gh", "env --unset=CLAUDECODE gh", "unset CLAUDECODE",
		"CLAUDECODE= passess migrate env .env --apply", "export CODEX_THREAD_ID=",
		"op read op://Dev/x/credential", "op inject -i tpl", "op item get x --reveal", "bws secret get 0000",
		"bws secret list", "bw get password github", "vault kv get secret/app", "bao read secret/x",
		"security find-generic-password -s x -w", "secret-tool lookup service x", "gh auth token",
		"gcloud auth print-access-token", "aws configure get aws_secret_access_key", "kubectl config view --raw",
		"echo $GITHUB_TOKEN", `curl -H "Authorization: Bearer $API_KEY" https://api.example.com`, "echo ${DATABASE_URL:-none}",
		"echo 'allow = [\"sh\"]' >> ~/.config/passess/config.toml", "tee -a ~/.config/passess/config.toml",
		"sed -i '' s/gh/sh/ ~/.config/passess/config.toml", "cp /tmp/x ~/.config/passess/config.toml", "rm ~/.config/passess/config.toml",
		// The same writes through the variables passess finds its config by.
		"echo x >> $HOME/.config/passess/config.toml", `echo x >> "${HOME}/.config/passess/config.toml"`,
		`tee -a "$HOME/.config/passess/config.toml"`, `sed -i '' s/gh/sh/ "$HOME/.config/passess/config.toml"`,
		`cp /tmp/x "${XDG_CONFIG_HOME:-$HOME/.config}/passess/config.toml"`, `cd "$HOME/.config/passess" && echo x >> config.toml`,
		"cat <<'EOF' > \"$HOME/.config/passess/config.toml\"\nversion = 1\nEOF", "$HOME/go/bin/passess agent stop",
		"cat $HOME/.aws/credentials", `cat "$HOME/.local/state/passess/backups/x/00-.env"`,
		// around the agent and its approvals
		"passess agent stop", "/opt/homebrew/bin/passess agent stop", "passess agent approve", "passess agent serve",
		"passess helper ANTHROPIC_API_KEY", "PASSESS_CONFIG=/tmp/x.toml passess exec -s API_KEY -- gh api user",
		"env PASSESS_AGENT_SOCK=/tmp/a.sock passess exec -s API_KEY -- gh api user", "export PASSESS_CONFIG=/tmp/x.toml",
		"export FOO=1 PASSESS_CONFIG=/tmp/x.toml", "HOME=/tmp passess exec -s API_KEY -- gh api user", "XDG_CONFIG_HOME=/tmp passess list",
		// The subcommand built at run time, and HOME set apart from the call.
		"V=add; passess $V EVIL --ref keychain://passess/X", "passess $(echo set) GITHUB_TOKEN --clients all",
		"passess $'\\x61dd' EVIL --ref keychain://passess/X", `passess "$CMD" --json`,
		"export HOME=/tmp; passess exec -s API_KEY -- gh api user", "HOME=/tmp\npassess list",
		"HOME=/tmp sh -c 'passess list'", "export XDG_CONFIG_HOME=/tmp/x; passess list",
		"nc -U ~/.local/state/passess/agent.sock", "socat - UNIX-CONNECT:$HOME/.local/state/passess/agent.sock",
		`python3 -c "import socket; s = socket.socket(socket.AF_UNIX); s.connect('/home/u/.local/state/passess/agent.sock')"`,
	}
	allow := []string{
		"ls -la", "echo hello", "cat README.md", "cat .env.example", "cp .env.example .env", "echo '.env' >> .gitignore",
		"printenv PATH", "env FOO=1 npm test", "env -u X make", "bws run -- make", "op run -- npm start", "op item get x",
		"security find-generic-password -s x", "export FOO=bar", "export PATH", "declare -p PATH", "local x=1", "echo $HOME $PATH", "passess exec -s GITHUB_TOKEN -- gh api user",
		"grep -r TODO .", "git status", "set -e", "vault kv list secret/", "gh auth status", "cat ~/.ssh/id_ed25519.pub",
		`echo "unterminated`, "", "cat ~/.config/passess/config.toml", "sed -n 1p ~/.config/passess/config.toml",
		"echo hi > /tmp/out.txt", `cat "$HOME/.config/passess/config.toml"`, "grep -n hosts $HOME/.config/passess/config.toml",
		`sed -n 1p "${XDG_CONFIG_HOME:-$HOME/.config}/passess/config.toml"`, "ls $HOME/.config/passess", `echo x >> "$HOME/notes.txt"`,
		"passess agent status", "passess agent start", "passess agent lock", "passess list", "passess backend --json", "passess mcp list --json",
		"passess profile list", "passess agent config", "passess agent config --json", "HOME=/tmp ls",
		"passess migrate env .env", "passess install --apply", "passess uninstall", "env -u FOO gh",
		"cd /tmp && ls", "cd /tmp && cat README.md", "pushd /tmp && popd && ls",
		"FOO=1 passess exec -s API_KEY -- gh api user",
		"export HOME=/tmp; npm test", "HOME=/tmp sh -c 'make'", "passess exec -s X -- echo $'a\\tb'",
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
	if !strings.Contains(v.Reason, "passess exec -s GITHUB_TOKEN --") || !strings.Contains(v.Reason, "passess http -s GITHUB_TOKEN -H") {
		t.Fatalf("reason does not say what to run instead: %s", v.Reason)
	}
}

// With XDG_CONFIG_HOME and PASSESS_CONFIG set, a write through them is a
// write to the config; a variable that is not a locator stays unknown.
func TestConfigLocators(t *testing.T) {
	env := testEnv(t)
	vars := map[string]string{"XDG_CONFIG_HOME": "/home/u/xdg", "PASSESS_CONFIG": "/home/u/cfg/passess.toml"}
	env.Getenv = func(k string) string { return vars[k] }
	env.ConfigDirs = []string{"/home/u/xdg/passess", "/home/u/cfg"}
	for c, deny := range map[string]bool{
		"echo x >> $XDG_CONFIG_HOME/passess/config.toml":                  true,
		`tee "${XDG_CONFIG_HOME:-/nowhere}/passess/config.toml"`:          true,
		`echo x >> "$PASSESS_CONFIG"`:                                     true,
		"sed -i '' s/a/b/ $PASSESS_CONFIG":                                true,
		`echo x >> "${XDG_CONFIG_HOME:-$HOME/.config}/other/config.toml"`: false,
		"cat $XDG_CONFIG_HOME/passess/config.toml":                        false,
		`echo x >> "$TMPDIR/passess/config.toml"`:                         false,
		`echo x >> "${XDG_CONFIG_HOME#/home}/passess/config.toml"`:        false,
	} {
		if v := Decide(Event{Kind: Shell, Command: c, CWD: "/home/u/proj"}, env); v.Deny != deny {
			t.Errorf("%s: deny = %v (%s)", c, v.Deny, v.Reason)
		}
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

// 1Password's MCP tools that hand values to the agent are refused, under any
// server name the user gave it and any form a harness names them in; the
// rest of that server is not.
func TestMCPTools(t *testing.T) {
	env := testEnv(t)
	for _, tool := range []string{
		"mcp__plugin_1password_1password__create_local_env_file", "mcp__1password__append_variables",
		"mcp__onepassword-mcp__create_local_env_file", "1Password__append_variables", "create_local_env_file",
		"mcp__op__create_local_env_file", "mcp__1p__append_variables",
	} {
		if v := Decide(Event{Kind: MCP, Tool: tool}, env); !v.Deny || !strings.Contains(v.Reason, "passess add") {
			t.Errorf("%s allowed: %+v", tool, v)
		}
	}
	for _, tool := range []string{
		"mcp__plugin_1password_1password__list_variables", "mcp__1password__list_environments",
		"mcp__op__list_local_env_files", "mcp__github__create_issue",
	} {
		if v := Decide(Event{Kind: MCP, Tool: tool}, env); v.Deny {
			t.Errorf("%s denied: %s", tool, v.Reason)
		}
	}
}

// A running agent masks the values it holds before the hook's own
// redaction, for a plain output and for a shaped one alike.
func TestResultMaskedByTheAgent(t *testing.T) {
	env := testEnv(t)
	const held = "passess-fake-held-by-agent-0123456789"
	asked := 0
	env.Agent = func(text string) (string, bool) {
		asked++
		return strings.ReplaceAll(text, held, "[REDACTED:VAULT_TOKEN]"), true
	}
	v := Decide(Event{Kind: Result, Text: "value " + held + "\n"}, env)
	if !v.Changed || v.Output != "value [REDACTED:VAULT_TOKEN]\n" {
		t.Fatalf("plain output: %+v", v)
	}
	resp := map[string]any{"stdout": "a " + held, "stderr": "", "code": 0.0}
	v = Decide(Event{Kind: Result, Response: resp}, env)
	got, ok := v.Response.(map[string]any)
	if !v.Changed || !ok || got["stdout"] != "a [REDACTED:VAULT_TOKEN]" || got["code"] != 0.0 || len(got) != 3 {
		t.Fatalf("shaped output: %+v", v)
	}
	if asked != 2 {
		t.Fatalf("the agent was asked %d times, want once per result", asked)
	}
	// No agent to ask: the hook goes on with its own redaction.
	env.Agent = func(string) (string, bool) { return "", false }
	if v := Decide(Event{Kind: Result, Text: "ok\n"}, env); v.Changed {
		t.Fatalf("an unreachable agent changed the output: %+v", v)
	}
}

// shellVerdicts checks one list of commands that must be refused and one that
// must pass, run from /home/u/proj.
func shellVerdicts(t *testing.T, deny, allow []string) {
	t.Helper()
	env := testEnv(t)
	for _, c := range deny {
		v := Decide(Event{Kind: Shell, Command: c, CWD: "/home/u/proj"}, env)
		if !v.Deny || !strings.HasPrefix(v.Reason, "passess: ") {
			t.Errorf("allowed: %s", c)
		}
	}
	for _, c := range allow {
		if v := Decide(Event{Kind: Shell, Command: c, CWD: "/home/u/proj"}, env); v.Deny {
			t.Errorf("denied: %s: %s", c, v.Reason)
		}
	}
}

// A program or subcommand spelled with escapes, built from a variable, or
// behind a wrapper's option argument is still passess.
func TestProgramNameSpellings(t *testing.T) {
	shellVerdicts(t, []string{
		`\passess agent stop`, `passess agent st\op`, `passess a\dd X --ref keychain://passess/X`, `\passess helper API_KEY`,
		`P=passess; $P agent stop`, `P=passess; "$P" agent stop`, `$(command -v passess) agent serve`, `$P helper API_KEY`,
		`timeout 5 passess agent stop`, `timeout -s KILL 5 passess agent stop`, `timeout --signal=KILL 5 passess agent stop`,
		`nice -n 10 passess agent stop`, `sudo -u root passess helper API_KEY`, `sudo -g adm -u root passess agent stop`,
		`doas -u root passess agent stop`, `exec -a x passess agent stop`, `time -p passess agent stop`,
		`xargs -n1 passess agent stop`, `echo x | xargs -I {} passess agent approve`,
		`find . -exec passess agent stop \;`, `find . -name x -execdir passess helper API_KEY +`,
		`env \passess agent stop`, `bash -c '\passess agent stop'`,
	}, []string{
		`timeout 5 make test`, `nice -n 10 make`, `sudo -u root ls`, `exec -a x make`, `xargs -n1 echo`, `xargs grep TODO`,
		`find . -name x -exec echo {} \;`, `find . -type f -exec grep -l TODO {} +`, `$MAKE test`, `$GIT add .`, `$NPM remove left-pad`,
		`$P agent status`, `\ls`, `echo a\ b`, `\passess list`, `passess a\gent status`,
	})
}

// The shell removes the backslashes of an unquoted word, and of a quoted one
// before $ ` " \ and a newline: the guards read the word the shell does.
func TestBackslashEscapedWords(t *testing.T) {
	shellVerdicts(t, []string{
		`cat .e\nv`, `cat \.env`, `cat ~/.aws/cred\entials`, `cat ~/.ssh/id_\rsa`, `cat < .e\nv`,
		`cat "$HOME"/.aws/cred\entials`, `cat .e\
nv`, `grep KEY .env\*`,
		`echo x > ~/.config/pass\ess/config.toml`, `echo x >> ~/.config/pass\ess/config.toml`, `tee -a ~/.config/pass\ess/config.toml`,
		`cp /tmp/x ~/.config/pass\ess/config.toml`, `cd ~/.config/pass\ess && echo x >> config.toml`,
		`cat ~/.local/state/pass\ess/backups/x/00-.env`, `sed -i '' s/a/b/ ~/.config/\passess/config.toml`,
		`echo x > "$HOME"/.config/pass\ess/config.toml`,
	}, []string{
		`cat .e\\nv`, `cat ".e\nv"`, `cat '.e\nv'`, `echo a\ b > /tmp/x`, `cat README\.md`, `cat .env.exam\ple`,
		`echo x > ~/.config/pass\\ess/config.toml`, `echo "\"" > /tmp/x`, `echo \$HOME`,
	})
}

// A cd moves the shell only where the shell itself runs it: not in a subshell,
// a pipeline, a background job or a command substitution, and not surely in a
// branch that may be skipped.
func TestCdScope(t *testing.T) {
	shellVerdicts(t, []string{
		`cd ~/.config/passess && (cd /tmp) && echo x >> config.toml`,
		`cd ~/.config/passess; cd /tmp | cat; echo x >> config.toml`,
		`cd ~/.config/passess; false && cd /tmp; echo x >> config.toml`,
		`cd ~/.config/passess; true || cd /tmp; echo x >> config.toml`,
		`cd ~/.config/passess; { cd /tmp; } & echo x >> config.toml`,
		`cd ~/.config/passess; cd /tmp & echo x >> config.toml`,
		`cd ~/.config/passess; echo $(cd /tmp); echo x >> config.toml`,
		`cd ~/.config/passess; if false; then cd /tmp; fi; echo x >> config.toml`,
		`cd ~/.config/passess; for d in /tmp; do cd $d; done; echo x >> config.toml`,
		`cd ~/.config/passess; case x in y) cd /tmp;; esac; echo x >> config.toml`,
		`cd ~/.config/passess; cat <(cd /tmp); echo x >> config.toml`,
		`cd ~/.aws; (cd /tmp); cat credentials`, `cd ~/.aws; (cd /tmp); cat < credentials`,
		`cd ~/.aws; { cd /tmp; } | cat; cat credentials`,
		// the cd's own scope still counts inside it
		`(cd ~/.config/passess && echo x >> notes)`, `(cd ~/.config/passess; tee notes)`, `{ cd ~/.aws; } && cat credentials`,
		`cd ~/.config/passess && { echo x >> config.toml; }`, `cd ~/.aws && cd . && cat credentials`,
		// a directory that may or may not be entered is not known afterwards
		`f() { cd ~/.config/passess; }; f; echo x >> config.toml`,
		`builtin cd ~/.config/passess; echo x >> notes`, `command cd ~/.aws && cat credentials`,
	}, []string{
		`cd /tmp && ls`, `cd /tmp && cd sub && echo x > out.txt`, `(cd /tmp); echo x >> config.toml`, `(cd /tmp); cat credentials`,
		`cd /tmp; echo x >> config.toml`, `cd /tmp | cat; echo x > out.txt`, `false && cd /tmp; echo x > out.txt`,
		`echo $(cd /tmp); cat README.md`, `if true; then cd /tmp; fi; cat README.md`, `cd ~/.config/passess; (cd /tmp); cat README.md`,
		`cd ~/.aws; ls; (cd /tmp); echo x > out.txt`, `{ cd /tmp; } & cat README.md`,
		// the directory is lost from an ordinary one: see TestUnknownDirectory
		`false && cd /tmp; echo x >> config.toml`, `if true; then cd /tmp; fi; cat < credentials`,
		`source ./go.sh; cat credentials`, `. ./go.sh; echo x >> config.toml`,
	})
}

// A pasted private key is refused however its lines are laid out, without
// the reason showing it.
func TestPromptPrivateKeyBlock(t *testing.T) {
	env := testEnv(t)
	body := func(n int) []string {
		var lines []string
		sum := sha256.Sum256([]byte("passess-fake-key-body"))
		for i := 0; i < n; i++ {
			sum = sha256.Sum256(sum[:])
			lines = append(lines, base64.StdEncoding.EncodeToString(append(sum[:], sum[:16]...)))
		}
		return lines
	}
	pem := func(kind, nl string) string {
		return "here is the key I use:" + nl + "-----BEGIN " + kind + "-----" + nl + strings.Join(body(3), nl) + nl + "-----END " + kind + "-----" + nl + "thanks"
	}
	for name, text := range map[string]string{
		"rsa":     pem("RSA PRIVATE KEY", "\n"),
		"crlf":    pem("RSA PRIVATE KEY", "\r\n"),
		"openssh": pem("OPENSSH PRIVATE KEY", "\n"),
		"oneline": strings.ReplaceAll(pem("RSA PRIVATE KEY", "\n"), "\n", " "),
		"indent":  "> " + strings.ReplaceAll(pem("EC PRIVATE KEY", "\n"), "\n", "\n> "),
	} {
		v := Decide(Event{Kind: Prompt, Text: text}, env)
		if !v.Deny || !strings.Contains(v.Reason, "private-key") {
			t.Errorf("%s: not refused: %+v", name, v)
		}
		for _, line := range body(3) {
			if strings.Contains(v.Reason, line) {
				t.Errorf("%s: the reason shows the key", name)
			}
		}
	}
	for name, text := range map[string]string{
		"public":   "-----BEGIN PUBLIC KEY-----\n" + strings.Join(body(3), "\n") + "\n-----END PUBLIC KEY-----",
		"cert":     "-----BEGIN CERTIFICATE-----\n" + strings.Join(body(3), "\n") + "\n-----END CERTIFICATE-----",
		"header":   "the file starts with -----BEGIN RSA PRIVATE KEY----- and ends with -----END RSA PRIVATE KEY-----, please parse it",
		"ordinary": "fix the failing test\nin commit 3fa2c9e1b07d4455aa01\nthanks",
	} {
		if v := Decide(Event{Kind: Prompt, Text: text}, env); v.Deny {
			t.Errorf("%s: refused: %s", name, v.Reason)
		}
	}
}

// When a cd cannot be followed, a relative sensitive name is refused only if
// the directory before it was a protected one; from an ordinary directory it
// passes, as it did before the cd.
func TestUnknownDirectory(t *testing.T) {
	shellVerdicts(t, []string{
		`cd ~/.config/passess && npm i && cd /tmp && echo x >> config.toml`,
		`cd ~/.config/passess; cd "$X"; echo x >> config.toml`,
		`cd ~/.aws; source ./go.sh; cat credentials`, `cd ~/.aws; eval "$(foo)"; cat < credentials`,
		`cd ~/.aws && ls && cd "$X"; cat credentials`,
		`cd ~/.config/passess; if x; then cd "$D"; fi; echo x >> config.toml`,
		`cd ~/.config/gh; for d in a b; do cd $d; done; cat hosts.yml`,
		`cd ~; cd "$X"; cat .npmrc`, `cd ~/.config; cd "$X"; echo x >> config.toml`,
		`cd ~/.local/state/passess; cd "$X"; cat auth.json`,
		// a branch that ends in a protected directory
		`if x; then cd ~/.config/passess; fi; echo x >> config.toml`, `false && cd ~/.aws; cat credentials`,
		`eval 'cd ~/.aws'; cat credentials`, `eval cd ~/.config/passess; echo x >> config.toml`,
		`cd /tmp; cd ~/.aws; cd "$X"; cat credentials`,
		// the cd moves into a protected directory after an unknown one
		`cd "$X"; cd ~/.aws && cat credentials`,
		// what runs inside keeps what is known about the directory
		`cd ~/.aws; cd "$X"; bash -c 'cat credentials'`, `cd ~/.aws; cd "$X"; find . -exec cat credentials \;`,
		`cd ~/.aws; pushd "$X"; popd; cat credentials`, `cd ~/.config; cd passess; echo x >> config.toml`,
	}, []string{
		`cd "$X"; bash -c 'cat credentials'`, `cd "$X"; pushd /tmp; popd; cat credentials`,
		`cd frontend && npm i && cd .. && echo x > config.toml`, `mkdir -p a && cd a && echo x > config.toml`,
		`cd "$(git rev-parse --show-toplevel)" && cat .npmrc`,
		`cd "$(git rev-parse --show-toplevel)" && echo x >> .cargo/config.toml`,
		`cd "$(dirname "$0")" && cat config.json`, `source .venv/bin/activate && jq . config.json`,
		`. ./env.sh; touch config.toml`, `eval "$(direnv export bash)"; cat config.json`,
		`if [ -d x ]; then cd x; fi; cat .npmrc`, `for d in a b; do cd $d; done; cat .npmrc`, `cd x || true; cat .npmrc`,
		`cd "$X" && cp config.toml.example config.toml`, `cd "$X" && grep config.toml Makefile`,
		`cd "$X" && diff config.toml config.toml.bak`,
		`cd /tmp; cd "$X"; echo x > config.toml`, `cd "$X"; cd /tmp; echo x > config.toml`,
		`if x; then cd /tmp; fi; cat credentials`, `eval 'cd /tmp'; cat credentials`,
	})
	env := testEnv(t)
	for _, c := range []string{`cd ~/.config/passess; cd "$X"; echo x >> config.toml`, `cd ~/.aws; cd "$X"; cat credentials`} {
		v := Decide(Event{Kind: Shell, Command: c, CWD: "/home/u/proj"}, env)
		if !strings.Contains(v.Reason, "could not follow") {
			t.Errorf("reason does not say the cd was not followed: %s: %s", c, v.Reason)
		}
	}
	// a shell started where nothing is known stays careful
	for _, c := range []string{`echo x >> config.toml`, `cat credentials`} {
		if v := Decide(Event{Kind: Shell, Command: c}, env); !v.Deny {
			t.Errorf("allowed with no directory: %s", c)
		}
	}
	if v := Decide(Event{Kind: Shell, Command: `cd "$X"; cat credentials`}, env); !v.Deny {
		t.Error("allowed after an unknown cd from no directory")
	}
}

// $'…' is static text the shell decodes; a brace expansion of static
// alternatives is every one of them.
func TestAnsiCQuotingAndBraces(t *testing.T) {
	shellVerdicts(t, []string{
		`cat $'.env'`, `cat .e$'n'v`, `cat $'\x2eenv'`, `cat $'\056env'`, `cat $'\u002eenv'`, `cat $'.e\156v'`,
		`cat $'\x2e\x65nv'`, `cat ~/.aws/$'credentials'`, `echo x > ~/.config/pass$'ess'/config.toml`, `$'passess' agent stop`,
		`passess $'\x61dd' X --ref keychain://passess/X`, `cat {.env,x}`, `cat .env{,}`, `cat {a,.env}`, `cat {x,{y,.env}}`,
		`cat {$X,.env}`, `cat .e{n,m}v`, `cat {.,x}env`, `tee {a,~/.config/passess/config.toml}`, `cat $'.env' $'x'`,
		`cat ~/.ssh/id_$'rsa'`, `cd ~/.aws; cat cred$'entials'`, `cat $'.e'nv`,
	}, []string{
		`echo $'a\tb' > out.txt`, `cat $'README.md'`, `cat {a,b}.txt`, `cat $'.env.example'`, `echo {1..3}`, `echo $'\e[0m'`,
		`cat $'.e\nv'`, `cat $'\\.env'`, `cat {a,b}{c,d}`, `echo $'it\'s'`, `cat $'\x2e'env.example`, `cat .en{x,y}`,
		`cat $'not-env'`, `passess exec -s API_KEY -- echo $'a\tb'`, `echo {a,b}`, `cat {x,y}.md`, `cat $'\e'.env.sample`,
	})
	if got, want := ansiC(`a\x41\101\u00e9\n\q\c`), "aAA\u00e9\n\\q\\c"; got != want {
		t.Errorf("ansiC decoded to %q, want %q", got, want)
	}
}

// A function body is checked where the function is called, with the
// directory in effect there; a coproc is a subshell.
func TestFunctionBodiesAndCoproc(t *testing.T) {
	shellVerdicts(t, []string{
		`f() { echo x >> config.toml; }; cd ~/.config/passess; f`, `f() { cat credentials; }; cd ~/.aws; f`,
		`cd ~/.config/passess; coproc cd /tmp; echo x >> config.toml`,
		`cd ~/.config/passess; coproc { cd /tmp; }; echo x >> config.toml`,
		`f() { cat credentials; }; cd ~/.aws && f`, `f() { cat credentials; }; cd ~/.aws; (f)`,
		`f() { echo x >> config.toml; }; g() { f; }; cd ~/.config/passess; g`,
		`function f { cat credentials; }; cd ~/.aws; f`, `f() { cat credentials; }; cd ~/.aws; echo $(f)`,
		`f() { cd ~/.aws; }; f; cat credentials`, `f() { echo x >> config.toml; }; cd ~/.config/passess; f; f`,
		`f() { cat credentials; }; cd ~/.aws; cat x | f`, `f() { cat credentials; }; if x; then cd ~/.aws; f; fi`,
		`f() { passess agent stop; }; f`, `f() { echo $GITHUB_TOKEN; }`,
	}, []string{
		`f() { echo x >> config.toml; }; f`, `f() { cat credentials; }; cd /tmp; f`, `f() { cd /tmp; }; f; echo x >> config.toml`,
		`coproc cd /tmp; echo x > config.toml`, `cd /tmp; coproc { cd /; }; cat credentials`, `f() { f; }; f`,
		`f() { g; }; g() { f; }; f`, `f() { cat README.md; }; cd ~/.aws; f`, `f() { cd /tmp; }; cd ~/.aws; f; cat credentials`,
		`f() { echo x >> config.toml; }; cd ~/.config/passess; (cd /tmp; f)`,
	})
}
