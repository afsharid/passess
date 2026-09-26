package scan

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Where harnesses keep MCP servers and settings, relative to HOME.
var configPaths = []string{
	".claude.json", ".claude/settings.json", ".claude/settings.local.json",
	".codex/config.toml",
	".config/opencode/opencode.json", ".config/opencode/opencode.jsonc",
	".kiro/settings/mcp.json",
	".gemini/settings.json", ".gemini/config/mcp_config.json",
	".cursor/mcp.json",
	".codeium/windsurf/mcp_config.json",
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
	{".local/share/opencode/storage", []string{".json"}},
}

var (
	envFile      = regexp.MustCompile(`^\.env(\..+)?$`)
	envTemplate  = regexp.MustCompile(`(?i)\.(example|sample|template|dist|defaults?)$`)
	skipDirNames = map[string]bool{".git": true, "node_modules": true, "vendor": true, ".venv": true, "venv": true,
		"dist": true, "build": true, "target": true, ".next": true, ".cache": true, ".build": true, "__pycache__": true}
)

// Discover lists what `passess scan` looks at by default: harness configs and
// dotfiles under home, .env files under dir, and transcripts when asked.
func Discover(home, dir string, transcripts bool) []Target {
	var out []Target
	add := func(path, category string) {
		if st, err := os.Stat(path); err == nil && st.Mode().IsRegular() {
			out = append(out, Target{Path: path, Category: category})
		}
	}
	for _, p := range configPaths {
		add(filepath.Join(home, p), "config")
	}
	for _, g := range configGlobs {
		matches, _ := filepath.Glob(filepath.Join(home, g))
		for _, m := range matches {
			add(m, "config")
		}
	}
	for _, p := range dotfiles {
		add(filepath.Join(home, p), "dotfile")
	}
	out = append(out, envFiles(dir, 4)...)
	if transcripts {
		for _, root := range transcriptRoots {
			base := filepath.Join(home, root.dir)
			_ = filepath.WalkDir(base, func(p string, d fs.DirEntry, err error) error {
				if err != nil {
					return nil
				}
				if d.IsDir() {
					if p != base && root.dir == ".codex" {
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
