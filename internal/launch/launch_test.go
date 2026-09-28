package launch

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/afsharid/passess/internal/redact"
)

// Start refuses without running anything when Verify fails.
func TestStartRefusesWhenVerifyFails(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "ran")
	rd, _, err := redact.New(nil, redact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	_, status, err := Start(Spec{
		Path: "/bin/sh", Argv: []string{"sh", "-c", "touch " + marker}, Stdout: &out, Stderr: &out,
		Redactor: rd, Verify: func() error { return errors.New("changed") },
	})
	if err == nil || status != NotExecutable {
		t.Fatalf("Start = %d, %v; want a refusal", status, err)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("the child ran")
	}
}
