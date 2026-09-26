package scan

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Where harnesses keep MCP servers and settings, relative to HOME; ".config/…"
// follows XDG_CONFIG_HOME when it is set.
var configPaths = []string{
	".claude.json", ".claude/settings.json", ".claude/settings.local.json",
	".codex/config.toml",
	".config/opencode/opencode.json", ".config/opencode/opencode.jsonc",
	".kiro/settings/mcp.json",
	".gemini/settings.json", ".gemini/config/mcp_config.json",
	".cursor/mcp.json",
	".codeium/windsurf/mcp_config.json", ".config/devin/mcp_config.json",
	".config/zed/settings.json",
	".config/goose/config.yaml",
	"Library/Application Support/Claude/claude_desktop_config.json",
	"Library/Application Support/Code/User/mcp.json",
	"Library/Application Support/Code/User/settings.json",
	".config/Code/User/mcp.json",
	".config/Code/User/settings.json",
}

// Globs under HOME that hold more configs.
var configGlobs = []string{".kiro/agents/*.json"}

var dotfiles = []string{
	".zshrc", ".zprofile", ".zshenv", ".bashrc", ".bash_profile", ".profile",
	".config/fish/config.fish", ".netrc", ".npmrc", ".pypirc",
}

// Transcript roots under HOME and the files that matter in them.
var transcriptRoots = []struct {
	dir string
	ext []string
}{
	{".claude/projects", []string{".jsonl"}},
	{".codex/sessions", []string{".jsonl"}},
	{".codex", []string{"history.jsonl"}},
	{".gemini/tmp", []string{".json", ".jsonl"}},
	{".gemini/antigravity-cli", []string{"history.jsonl"}},
	{".local/share/opencode/storage", []string{".json"}},
}

// Transcript roots whose subdirectories hold other things.
var topLevelOnly = map[string]bool{".codex": true, ".gemini/antigravity-cli": true}

var (
	envFile      = regexp.MustCompile(`^\.env(\..+)?$`)
	envTemplate  = regexp.MustCompile(`(?i)\.(example|sample|template|dist|defaults?)$`)
	skipDirNames = map[string]bool{".git": true, "node_modules": true, "vendor": true, ".venv": true, "venv": true,
		"dist": true, "build": true, "target": true, ".next": true, ".cache": true, ".build": true, "__pycache__": true}
)

// CredentialFiles hold credentials by design (sign-in tokens the tools
// manage themselves). scan leaves them alone; audit and inventory list them.
var CredentialFiles = []struct{ Path, Holds string }{
	{".claude/.credentials.json", "Claude Code sign-in (macOS keeps it in the keychain)"},
	{".codex/auth.json", "Codex sign-in or OpenAI API key"},
	{".local/share/opencode/auth.json", "OpenCode provider keys"},
	{".gemini/oauth_creds.json", "Gemini CLI sign-in"},
	{".config/gh/hosts.yml", "GitHub CLI token (unless gh uses the keychain)"},
	{".aws/credentials", "AWS access keys"},
	{".config/gcloud/application_default_credentials.json", "Google Cloud application default credentials"},
	{".docker/config.json", "registry credentials (unless a credential helper is set)"},
	{".kube/config", "Kubernetes cluster credentials"},
	{".netrc", "machine passwords for curl, git and others"},
	{".npmrc", "npm registry token"},
	{".pypirc", "PyPI upload token"},
	{".gemini/jetski-standalone-oauth-token", "Antigravity sign-in"},
	{".gemini/antigravity-cli/antigravity-oauth-token", "Antigravity CLI sign-in"},
}

// under joins a HOME-relative path, moving ".config/…" to configHome when set.
func under(home, configHome, rel string) string {
	if rest, ok := strings.CutPrefix(rel, ".config/"); ok && configHome != "" {
		return filepath.Join(configHome, rest)
	}
	return filepath.Join(home, rel)
}

// KnownConfigs returns the harness config files that exist, each once even
// when one is a symlink to another.
func KnownConfigs(home, configHome string) []string {
	var out []string
	seen := map[string]bool{}
	add := func(p string) {
		real, err := filepath.EvalSymlinks(p)
		if err != nil || seen[real] || !isFile(p) {
			return
		}
		seen[real] = true
		out = append(out, p)
	}
	for _, p := range configPaths {
		add(under(home, configHome, p))
	}
	for _, g := range configGlobs {
		matches, _ := filepath.Glob(filepath.Join(home, g))
		for _, m := range matches {
			add(m)
		}
	}
	return out
}

func isFile(path string) bool {
	st, err := os.Stat(path)
	return err == nil && st.Mode().IsRegular()
}

// Where says what Discover looks at.
type Where struct {
	Home        string // harness configs, their backups and dotfiles
	ConfigHome  string // XDG_CONFIG_HOME, if set
	Dir         string // .env files under it
	Backups     string // passess's own backups, which keep the files migrate and install replaced
	Transcripts bool
}

// Discover lists what `passess scan` looks at by default: harness configs,
// copies of them the harnesses or passess kept, dotfiles, .env files under
// the working directory, and transcripts when asked.
func Discover(w Where) []Target {
	var out []Target
	add := func(path, category string) {
		if isFile(path) {
			out = append(out, Target{Path: path, Category: category})
		}
	}
	for _, p := range KnownConfigs(w.Home, w.ConfigHome) {
		add(p, "config")
	}
	// Harnesses (and people) keep copies next to a config: .claude.json.backup,
	// config.toml.bak-2026…; Claude Code also keeps ~/.claude/backups.
	for _, p := range configPaths {
		for _, suffix := range []string{".bak*", ".backup*", ".orig", ".old"} {
			matches, _ := filepath.Glob(under(w.Home, w.ConfigHome, p) + suffix)
			for _, m := range matches {
				add(m, "backup")
			}
		}
	}
	for _, root := range []string{filepath.Join(w.Home, ".claude", "backups"), w.Backups} {
		if root == "" {
			continue
		}
		_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err == nil && !d.IsDir() && d.Name() != "manifest.json" {
				add(p, "backup")
			}
			return nil
		})
	}
	for _, p := range dotfiles {
		add(under(w.Home, w.ConfigHome, p), "dotfile")
	}
	out = append(out, envFiles(w.Dir, 4)...)
	if w.Transcripts {
		home := w.Home
		for _, root := range transcriptRoots {
			base := filepath.Join(home, root.dir)
			_ = filepath.WalkDir(base, func(p string, d fs.DirEntry, err error) error {
				if err != nil {
					return nil
				}
				if d.IsDir() {
					if p != base && topLevelOnly[root.dir] {
						return filepath.SkipDir // only the top-level history file there
					}
					return nil
				}
				for _, ext := range root.ext {
					if strings.HasSuffix(d.Name(), ext) {
						out = append(out, Target{Path: p, Category: "transcript"})
						break
					}
				}
				return nil
			})
		}
	}
	return out
}

// envFiles finds .env files under dir, skipping templates and dependency trees.
func envFiles(dir string, depth int) []Target {
	var out []Target
	base := strings.Count(filepath.Clean(dir), string(filepath.Separator))
	_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if p != dir && (skipDirNames[d.Name()] || strings.Count(p, string(filepath.Separator))-base >= depth) {
				return filepath.SkipDir
			}
			return nil
		}
		if envFile.MatchString(d.Name()) && !envTemplate.MatchString(d.Name()) {
			out = append(out, Target{Path: p, Category: "env"})
		}
		return nil
	})
	return out
}

// Paths turns explicit command-line paths into targets, walking directories.
func Paths(paths []string) []Target {
	var out []Target
	for _, p := range paths {
		_ = filepath.WalkDir(p, func(q string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if d.IsDir() {
				if q != p && skipDirNames[d.Name()] {
					return filepath.SkipDir
				}
				return nil
			}
			if d.Type().IsRegular() {
				out = append(out, Target{Path: q, Category: "path"})
			}
			return nil
		})
	}
	return out
}
