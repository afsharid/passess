// Command passess brokers secrets from an existing password manager to AI
// coding agents without putting secret values in their context.
package main

import (
	"os"

	"github.com/afsharid/passess/internal/cli"
)

func main() {
	os.Exit(cli.Main(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}
