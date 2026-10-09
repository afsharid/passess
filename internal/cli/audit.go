package cli

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/afsharid/passess/internal/audit"
	"github.com/afsharid/passess/internal/config"
	"github.com/afsharid/passess/internal/detect"
)

func init() {
	commands["audit"] = command{"find harness settings and files that hand credentials to agents, with the fix for each", runAudit}
}

type auditOutput struct {
	Findings []audit.Finding `json:"findings"`
	Errors   []string        `json:"errors"`
}

func runAudit(st *Streams, args []string) int {
	fs := flag.NewFlagSet("audit", flag.ContinueOnError)
	fs.SetOutput(st.Stderr)
	asJSON := fs.Bool("json", false, "machine-readable output")
	fs.Usage = func() {
		fmt.Fprintln(st.Stderr, "Usage: passess audit [--json]")
		fmt.Fprintln(st.Stderr, "Reads harness configs, shell startup files and file modes; changes nothing.")
		fs.PrintDefaults()
	}
	if rest, err := parseAnywhere(fs, args); err != nil || len(rest) > 0 {
		fs.Usage()
		return ExitUsage
	}
	augmentPath(st.Getenv)
	cfg, _ := config.UserPath(st.Getenv)
	wd, _ := os.Getwd()
	findings, errs := audit.Run(audit.Input{
		Home: st.Getenv("HOME"), ConfigHome: st.Getenv("XDG_CONFIG_HOME"), Dir: wd, Environ: os.Environ(), Harness: detect.Harness(st.Getenv),
		Adapters: adapters(st), Config: cfg,
	})
	out := auditOutput{Findings: findings, Errors: []string{}}
	if out.Findings == nil {
		out.Findings = []audit.Finding{}
	}
	for _, e := range errs {
		out.Errors = append(out.Errors, e.Error())
	}
	if *asJSON {
		if code := writeJSON(st, out); code != ExitOK {
			return code
		}
	} else {
		printAudit(st, out)
	}
	if len(out.Findings) > 0 {
		return 1
	}
	return ExitOK
}

func printAudit(st *Streams, out auditOutput) {
	home := st.Getenv("HOME")
	short := func(p string) string {
		if home != "" && strings.HasPrefix(p, home+"/") {
			return "~" + p[len(home):]
		}
		return p
	}
	var areas []string
	byArea := map[string][]audit.Finding{}
	for _, f := range out.Findings {
		if _, ok := byArea[f.Area]; !ok {
			areas = append(areas, f.Area)
		}
		byArea[f.Area] = append(byArea[f.Area], f)
	}
	for _, area := range areas {
		fmt.Fprintln(st.Stdout, area)
		for _, f := range byArea[area] {
			where := short(f.Path)
			if f.Line > 0 {
				where = fmt.Sprintf("%s:%d", where, f.Line)
			}
			if where != "" {
				where += ": "
			}
			fmt.Fprintf(st.Stdout, "  %s%s\n", printable(where), printable(f.Detail))
			lines := strings.Split(f.Fix, "\n")
			fmt.Fprintf(st.Stdout, "    fix: %s\n", printable(lines[0]))
			for _, l := range lines[1:] {
				fmt.Fprintf(st.Stdout, "         %s\n", printable(l))
			}
		}
		fmt.Fprintln(st.Stdout)
	}
	for _, e := range out.Errors {
		fmt.Fprintf(st.Stdout, "could not check: %s\n", printable(e))
	}
	if len(out.Findings) == 0 {
		fmt.Fprintln(st.Stdout, "Nothing found: no harness setting or file checked here hands credentials to agents.")
		return
	}
	fmt.Fprintf(st.Stdout, "%d finding(s). passess changed nothing; each fix is yours to run. `passess scan` finds values in clear line by line.\n", len(out.Findings))
}

// printable drops control characters but tab from one line of the report.
// Findings quote names they read from files already; this keeps any that
// slip through from moving the cursor, retitling the terminal or starting a
// line of their own.
func printable(s string) string {
	return strings.Map(func(r rune) rune {
		if (r < 0x20 && r != '\t') || (r >= 0x7f && r <= 0x9f) { // C0, DEL and C1 (0x9b starts a sequence too)
			return -1
		}
		return r
	}, s)
}
