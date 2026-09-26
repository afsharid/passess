package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"text/tabwriter"

	"github.com/afsharid/passess/internal/provider"
)

func init() {
	commands["check"] = command{"resolve secrets and report which work, never their values", runCheck}
}

// Check states for a secret.
const (
	stateOK          = "ok"
	stateMissing     = "missing"     // every candidate answered "not found"
	stateUnavailable = "unavailable" // a backend could not be asked
	stateUndefined   = "undefined"   // named on the command line or by the project, not in user config
)

type checked struct {
	Name   string `json:"name"`
	State  string `json:"state"`
	From   string `json:"from,omitempty"`   // the reference that resolved
	Detail string `json:"detail,omitempty"` // why it did not
}

type checkOutput struct {
	Config  string    `json:"config"`
	OK      bool      `json:"ok"`
	Secrets []checked `json:"secrets"`
}

func runCheck(st *Streams, args []string) int {
	fs := flag.NewFlagSet("check", flag.ContinueOnError)
	fs.SetOutput(st.Stderr)
	asJSON := fs.Bool("json", false, "machine-readable output")
	fs.Usage = func() {
		fmt.Fprintln(st.Stderr, "Usage: passess check [--json] [NAME...]")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}
	u, proj, code := loadConfig(st)
	if code != 0 {
		return code
	}
	names := fs.Args()
	if len(names) == 0 {
		names = u.SortedNames()
		if proj != nil {
			for n := range proj.Needs {
				if _, ok := u.Secrets[n]; !ok {
					names = append(names, n)
				}
			}
		}
	}

	res, zero := newResolver(st, u)
	defer zero()
	out := checkOutput{Config: u.Path, OK: true, Secrets: []checked{}}
	for _, n := range names {
		c := checked{Name: n}
		s, ok := u.Secrets[n]
		switch {
		case !ok:
			c.State, c.Detail = stateUndefined, fmt.Sprintf("add a [secrets.%s] table to %s", n, u.Path)
		default:
			_, from, err := res.SecretFrom(context.Background(), s)
			switch {
			case err == nil:
				c.State, c.From = stateOK, from.String()
			case errors.Is(err, provider.ErrUnavailable):
				c.State, c.Detail = stateUnavailable, err.Error()
			default:
				c.State, c.Detail = stateMissing, err.Error()
			}
		}
		if c.State != stateOK {
			out.OK = false
		}
		out.Secrets = append(out.Secrets, c)
	}

	if *asJSON {
		if code := writeJSON(st, out); code != ExitOK {
			return code
		}
	} else {
		w := tabwriter.NewWriter(st.Stdout, 0, 4, 2, ' ', 0)
		for _, c := range out.Secrets {
			detail := c.From
			if detail == "" {
				detail = c.Detail
			}
			fmt.Fprintf(w, "%s\t%s\t%s\n", c.Name, c.State, detail)
		}
		_ = w.Flush()
	}
	if !out.OK {
		return 1
	}
	return ExitOK
}
