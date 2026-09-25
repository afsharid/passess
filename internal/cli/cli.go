// Package cli implements the passess command line.
package cli

import (
	"fmt"
	"io"
	"os"
	"sort"

	"github.com/afsharid/passess/internal/buildinfo"
)

// Exit codes follow sysexits(3) for passess's own failures, so a caller can
// tell them apart from the exit status of a wrapped command.
const (
	ExitOK          = 0
	ExitUsage       = 64 // EX_USAGE: bad invocation
	ExitUnavailable = 69 // EX_UNAVAILABLE: a backend or its CLI is not usable
	ExitSoftware    = 70 // EX_SOFTWARE: internal error
	ExitNoPerm      = 77 // EX_NOPERM: refused by policy
	ExitConfig      = 78 // EX_CONFIG: configuration error
	ExitNotExec     = 126
	ExitNotFound    = 127
)

// Streams carries the process environment so commands can be tested in-process.
type Streams struct {
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer
	Getenv func(string) string
}

type command struct {
	summary string
	run     func(st *Streams, args []string) int
}

var commands = map[string]command{
	"version": {"print the passess version", runVersion},
}

// Main runs passess with args (without the program name) and returns the exit code.
func Main(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	st := &Streams{Stdin: stdin, Stdout: stdout, Stderr: stderr, Getenv: os.Getenv}
	if len(args) == 0 {
		usage(st.Stderr)
		return ExitUsage
	}
	switch args[0] {
	case "-h", "--help", "help":
		usage(st.Stdout)
		return ExitOK
	case "--version":
		return runVersion(st, nil)
	}
	cmd, ok := commands[args[0]]
	if !ok {
		fmt.Fprintf(st.Stderr, "passess: unknown command %q\n\n", args[0])
		usage(st.Stderr)
		return ExitUsage
	}
	return cmd.run(st, args[1:])
}

func runVersion(st *Streams, _ []string) int {
	fmt.Fprintf(st.Stdout, "passess %s\n", buildinfo.String())
	return ExitOK
}

func usage(w io.Writer) {
	fmt.Fprintln(w, "passess brokers secrets from your password manager to AI coding agents")
	fmt.Fprintln(w, "without putting secret values in their context.")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Usage: passess <command> [arguments]")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Commands:")
	names := make([]string, 0, len(commands))
	for name := range commands {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		fmt.Fprintf(w, "  %-10s %s\n", name, commands[name].summary)
	}
}
