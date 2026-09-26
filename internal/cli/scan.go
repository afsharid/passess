package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/afsharid/passess/internal/config"
	"github.com/afsharid/passess/internal/redact"
	"github.com/afsharid/passess/internal/ref"
	"github.com/afsharid/passess/internal/resolve"
	"github.com/afsharid/passess/internal/scan"
	"github.com/afsharid/passess/internal/secret"
)

func init() {
	commands["scan"] = command{"find secrets stored in clear in configs, dotfiles, .env files and transcripts", runScan}
}

type scanOutput struct {
	Files      int            `json:"files"`
	Rules      string         `json:"rules"`
	Known      int            `json:"known_secrets"`
	Unresolved []string       `json:"unresolved"` // configured secrets whose values could not be searched for
	Findings   []scan.Finding `json:"findings"`
	Errors     []string       `json:"errors"`
}

func runScan(st *Streams, args []string) int {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(st.Stderr)
	asJSON := fs.Bool("json", false, "machine-readable output")
	transcripts := fs.Bool("transcripts", false, "also scan harness session transcripts (can be large)")
	noKnown := fs.Bool("no-known", false, "do not resolve configured secrets to search for their values")
	fs.Usage = func() {
		fmt.Fprintln(st.Stderr, "Usage: passess scan [--transcripts] [--no-known] [--json] [PATH...]")
		fmt.Fprintln(st.Stderr, "Without PATH: harness configs and dotfiles in your home, .env files under this directory.")
		fs.PrintDefaults()
	}
	paths, err := parseAnywhere(fs, args)
	if err != nil {
		return ExitUsage
	}
	augmentPath(st.Getenv)

	rules, err := scan.DefaultRules()
	if err != nil {
		return failf(st, ExitSoftware, "%v", err)
	}
	s := &scan.Scanner{Rules: rules, KnownFP: map[string]string{}}
	out := scanOutput{Rules: scan.RulesVersion, Unresolved: []string{}, Findings: []scan.Finding{}, Errors: []string{}}

	if !*noKnown {
		if path, err := config.UserPath(st.Getenv); err == nil {
			if u, err := config.LoadUser(path); err == nil {
				rd, zero, known, unresolved := knownSecrets(st, u)
				defer zero()
				s.Known, out.Known, out.Unresolved = rd, len(known), unresolved
				for name, v := range known {
					s.KnownFP[name] = s.Fingerprint(v.Bytes())
				}
			} else if !errors.Is(err, config.ErrNoConfig) {
				return failf(st, ExitConfig, "%v", err)
			}
		}
	}

	var targets []scan.Target
	if len(paths) > 0 {
		targets = scan.Paths(paths)
	} else {
		wd, _ := os.Getwd()
		targets = scan.Discover(scan.Where{Home: st.Getenv("HOME"), Dir: wd,
			Backups: filepath.Join(stateDir(st.Getenv), "backups"), Transcripts: *transcripts})
	}
	out.Files = len(targets)
	findings, errs := s.All(targets, runtime.NumCPU())
	out.Findings = append(out.Findings, findings...)
	for _, e := range errs {
		out.Errors = append(out.Errors, e.Error())
	}

	if *asJSON {
		if code := writeJSON(st, out); code != ExitOK {
			return code
		}
	} else {
		printScan(st, out)
	}
	if len(out.Findings) > 0 {
		return 1
	}
	return ExitOK
}

// knownSecrets resolves every configured secret, plus the backends' own
// credentials, so their exact values can be searched for.
func knownSecrets(st *Streams, u *config.User) (*redact.Redactor, func(), map[string]secret.Value, []string) {
	res, zero := newResolver(st, u)
	known := map[string]secret.Value{}
	var unresolved []string
	for _, name := range u.SortedNames() {
		v, err := res.Secret(context.Background(), u.Secrets[name])
		if err != nil {
			unresolved = append(unresolved, name)
			continue
		}
		known[name] = v
	}
	boot := resolve.New(newBootProviders(st)...)
	for name, r := range map[string]*ref.Ref{
		"BWS_ACCESS_TOKEN": u.Backends.BWS.AccessToken,
		"VAULT_TOKEN":      u.Backends.Vault.Token,
		"BW_SESSION":       u.Backends.BW.Session,
	} {
		if r == nil {
			continue
		}
		if v, err := boot.Secret(context.Background(), config.Secret{Name: name, Refs: []ref.Ref{*r}}); err == nil {
			known[name] = v
		}
	}
	var named []redact.Secret
	for name, v := range known {
		if v.Len() >= redact.HardMinLen {
			named = append(named, redact.Secret{Name: name, Value: v})
		}
	}
	rd, _, err := redact.New(named, redact.Options{})
	if err != nil {
		rd = nil
	}
	return rd, func() {
		zero()
		boot.Zero()
		if rd != nil {
			rd.Zero()
		}
	}, known, nonNil(unresolved)
}

func printScan(st *Streams, out scanOutput) {
	home := st.Getenv("HOME")
	short := func(p string) string {
		if home != "" && strings.HasPrefix(p, home+"/") {
			return "~" + p[len(home):]
		}
		return p
	}
	byCategory := map[string][]scan.Finding{}
	for _, f := range out.Findings {
		byCategory[f.Category] = append(byCategory[f.Category], f)
	}
	for _, cat := range []string{"config", "backup", "dotfile", "env", "transcript", "path"} {
		fs := byCategory[cat]
		if len(fs) == 0 {
			continue
		}
		fmt.Fprintf(st.Stdout, "%s\n", cat)
		for _, f := range fs {
			if f.Kind == "rule" {
				fmt.Fprintf(st.Stdout, "  %s:%d  rule %s  fp %s (%d chars)\n", short(f.Path), f.Line, f.Rule, f.Fingerprint, f.Length)
			} else {
				fmt.Fprintf(st.Stdout, "  %s:%d  known %s  fp %s\n", short(f.Path), f.Line, f.Secret, f.Fingerprint)
			}
		}
	}
	fmt.Fprintf(st.Stdout, "\n%d finding(s) in %d file(s) scanned; rules: %s; %d configured value(s) searched for.\n",
		len(out.Findings), out.Files, out.Rules, out.Known)
	if len(out.Findings) > 0 {
		fmt.Fprintln(st.Stdout, "Equal fingerprints mean the same value within this scan; they are keyed per run and prove nothing about a guess.")
	}
	if len(out.Unresolved) > 0 {
		fmt.Fprintf(st.Stdout, "Not searched (could not be resolved): %s\n", strings.Join(out.Unresolved, ", "))
	}
	if len(byCategory["transcript"]) > 0 || len(byCategory["config"]) > 0 {
		fmt.Fprintln(st.Stdout, "Rotate anything found in a transcript first: that value has already left this machine.")
		fmt.Fprintln(st.Stdout, "Then move it into your vault and out of the file (`passess migrate`).")
	}
	if b := byCategory["backup"]; len(b) > 0 {
		dirs := map[string]bool{}
		for _, f := range b {
			dirs[filepath.Dir(f.Path)] = true
		}
		fmt.Fprintln(st.Stdout, "Backups keep the values they were taken with. Once you no longer need them, remove them:")
		for _, d := range sortedKeys(dirs) {
			fmt.Fprintf(st.Stdout, "  %s\n", short(d))
		}
	}
	for _, e := range out.Errors {
		fmt.Fprintf(st.Stdout, "could not read: %s\n", e)
	}
}
