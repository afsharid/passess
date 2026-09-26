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
	"time"

	"github.com/afsharid/passess/internal/config"
	"github.com/afsharid/passess/internal/harness"
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
	Notes      []string       `json:"notes,omitempty"`
	// With --scrub: what was done to each transcript, and where the
	// originals went (--apply).
	Scrubbed []scan.Scrubbed `json:"scrubbed,omitempty"`
	Backup   string          `json:"backup,omitempty"`
}

func runScan(st *Streams, args []string) int {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(st.Stderr)
	asJSON := fs.Bool("json", false, "machine-readable output")
	transcripts := fs.Bool("transcripts", false, "also search harness session transcripts for your configured values")
	transcriptRules := fs.Bool("transcript-rules", false, "with --transcripts, also run the rules on them (slow on a large history)")
	noKnown := fs.Bool("no-known", false, "do not resolve configured secrets to search for their values")
	scrub := fs.Bool("scrub", false, "replace your configured values in the transcripts found holding them (a dry run without --apply; implies --transcripts)")
	apply := fs.Bool("apply", false, "with --scrub, back the transcripts up and rewrite them")
	fs.Usage = func() {
		fmt.Fprintln(st.Stderr, "Usage: passess scan [--transcripts [--transcript-rules]] [--scrub [--apply]] [--no-known] [--json] [PATH...]")
		fmt.Fprintln(st.Stderr, "Without PATH: harness configs and dotfiles in your home, .env files under this directory.")
		fs.PrintDefaults()
	}
	paths, err := parseAnywhere(fs, args)
	if err != nil {
		return ExitUsage
	}
	switch {
	case *apply && !*scrub:
		return failf(st, ExitUsage, "--apply goes with --scrub")
	case *scrub && (len(paths) > 0 || *noKnown):
		return failf(st, ExitUsage, "--scrub works on the transcripts a scan finds, with your configured values; drop the paths and --no-known")
	case *scrub:
		*transcripts = true
	}
	augmentPath(st.Getenv)

	rules, err := scan.DefaultRules()
	if err != nil {
		return failf(st, ExitSoftware, "%v", err)
	}
	s := &scan.Scanner{Rules: rules, KnownFP: map[string]string{}, TranscriptRules: *transcriptRules}
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
		targets = scan.Discover(scan.Where{Home: st.Getenv("HOME"), ConfigHome: st.Getenv("XDG_CONFIG_HOME"), Dir: wd,
			Backups: filepath.Join(stateDir(st.Getenv), "backups"), Transcripts: *transcripts})
	}
	out.Files = len(targets)
	if *transcripts && !*transcriptRules {
		out.Notes = append(out.Notes, "transcripts were searched for your configured values only; --transcript-rules also looks for other secret-shaped strings (slow)")
		if out.Known == 0 {
			out.Notes = append(out.Notes, "no configured value could be searched for, so transcripts were not checked at all")
		}
	}
	findings, errs := s.All(targets, runtime.NumCPU())
	out.Findings = append(out.Findings, findings...)
	for _, e := range errs {
		out.Errors = append(out.Errors, e.Error())
	}
	if *scrub {
		if code := scrubTranscripts(st, s.Known, *apply, &out); code != ExitOK {
			return code
		}
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

// scrubTranscripts replaces the configured values in the transcripts the scan
// found holding them. It is a dry run unless apply; with apply the files are
// backed up first, in one directory, and the backup keeps the values: its
// removal is the user's call, like every backup's.
func scrubTranscripts(st *Streams, known *redact.Redactor, apply bool, out *scanOutput) int {
	if known == nil {
		out.Notes = append(out.Notes, "nothing to scrub with: no configured value could be resolved")
		return ExitOK
	}
	now := time.Now()
	seen := map[string]bool{}
	var paths, live []string
	for _, f := range out.Findings {
		if f.Category != "transcript" || f.Kind != "known" || seen[f.Path] {
			continue
		}
		seen[f.Path] = true
		if fi, err := os.Stat(f.Path); err == nil && now.Sub(fi.ModTime()) < scan.InUse {
			live = append(live, f.Path) // Scrub leaves it alone; no copy needed
		} else {
			paths = append(paths, f.Path)
		}
	}
	if apply && len(paths) > 0 {
		dir, err := harness.Backup(filepath.Join(stateDir(st.Getenv), "backups"), paths, now)
		if err != nil {
			return failf(st, ExitSoftware, "backing the transcripts up: %v; nothing was changed", err)
		}
		out.Backup = dir
	}
	for _, p := range append(paths, live...) {
		res, err := scan.Scrub(p, known, apply, now)
		if err != nil {
			out.Errors = append(out.Errors, err.Error())
			continue
		}
		out.Scrubbed = append(out.Scrubbed, res)
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
	printScrubbed(st, out, short)
	for _, e := range out.Errors {
		fmt.Fprintf(st.Stdout, "could not read: %s\n", e)
	}
	for _, n := range out.Notes {
		fmt.Fprintf(st.Stdout, "note: %s\n", n)
	}
}

func printScrubbed(st *Streams, out scanOutput, short func(string) string) {
	if len(out.Scrubbed) == 0 {
		return
	}
	if out.Backup == "" {
		fmt.Fprintln(st.Stdout, "\nWould scrub (a dry run; --apply backs the files up and rewrites them):")
	} else {
		fmt.Fprintln(st.Stdout, "\nScrubbed:")
	}
	for _, r := range out.Scrubbed {
		var parts []string
		for _, name := range sortedKeys(r.Replaced) {
			parts = append(parts, fmt.Sprintf("%s ×%d", name, r.Replaced[name]))
		}
		switch {
		case r.Skipped != "":
			fmt.Fprintf(st.Stdout, "  %s  left as it is: %s\n", short(r.Path), r.Skipped)
		default:
			fmt.Fprintf(st.Stdout, "  %s  %s\n", short(r.Path), strings.Join(parts, ", "))
		}
	}
	if out.Backup != "" {
		fmt.Fprintf(st.Stdout, "The originals are in %s, and they still hold the values. Once the sessions look right, remove it:\n  rm -r %s\n",
			short(out.Backup), out.Backup)
		fmt.Fprintln(st.Stdout, "Scrubbing a transcript does not unsend it: rotate what it held at the provider.")
	}
}
