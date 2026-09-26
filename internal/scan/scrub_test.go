package scan

import (
	"bufio"
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/afsharid/passess/internal/redact"
	"github.com/afsharid/passess/internal/secret"
)

const scrubValue = "passess-fake-scrub-value-0123456789"

func scrubRedactor(t *testing.T) *redact.Redactor {
	t.Helper()
	rd, _, err := redact.New([]redact.Secret{{Name: "X", Value: secret.FromString(scrubValue)}}, redact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	return rd
}

// transcript writes a JSONL session with the value in two lines, one of
// them JSON-escaped inside a string, and dates it an hour back.
func transcript(t *testing.T) (string, time.Time) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "session.jsonl")
	body := `{"type":"user","message":"the key is ` + scrubValue + `"}` + "\n" +
		`{"type":"tool","output":"nothing here"}` + "\n" +
		`{"type":"tool","output":"export X=\"` + scrubValue + `\""}` + "\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-time.Hour).Truncate(time.Second)
	if err := os.Chtimes(path, old, old); err != nil {
		t.Fatal(err)
	}
	return path, old
}

func TestScrubCountsThenWrites(t *testing.T) {
	path, old := transcript(t)
	rd := scrubRedactor(t)
	orig, _ := os.ReadFile(path)

	res, err := Scrub(path, rd, false, time.Now())
	if err != nil || res.Written || res.Replaced["X"] != 2 || res.Skipped != "" {
		t.Fatalf("dry run: %+v, %v", res, err)
	}
	if now, _ := os.ReadFile(path); !bytes.Equal(now, orig) {
		t.Fatal("a dry run changed the file")
	}

	res, err = Scrub(path, rd, true, time.Now())
	if err != nil || !res.Written || res.Replaced["X"] != 2 {
		t.Fatalf("apply: %+v, %v", res, err)
	}
	got, _ := os.ReadFile(path)
	if bytes.Contains(got, []byte(scrubValue)) || !bytes.Contains(got, []byte("[REDACTED:X]")) || !bytes.Contains(got, []byte("nothing here")) {
		t.Fatalf("scrubbed file:\n%s", got)
	}
	sc := bufio.NewScanner(bytes.NewReader(got))
	for sc.Scan() {
		if !json.Valid(sc.Bytes()) {
			t.Fatalf("a line is no longer JSON: %s", sc.Text())
		}
	}
	fi, _ := os.Stat(path)
	if fi.Mode().Perm() != 0o600 || !fi.ModTime().Equal(old) {
		t.Fatalf("mode %v, time %v; want 0600 and %v", fi.Mode().Perm(), fi.ModTime(), old)
	}
	if entries, _ := os.ReadDir(filepath.Dir(path)); len(entries) != 1 {
		t.Fatalf("left %d files behind", len(entries))
	}
}

func TestScrubLeavesALiveSessionAlone(t *testing.T) {
	path, _ := transcript(t)
	now := time.Now()
	if err := os.Chtimes(path, now, now); err != nil {
		t.Fatal(err)
	}
	res, err := Scrub(path, scrubRedactor(t), true, time.Now())
	if err != nil || res.Written || !strings.Contains(res.Skipped, "10 minutes") {
		t.Fatalf("%+v, %v", res, err)
	}
	if got, _ := os.ReadFile(path); !bytes.Contains(got, []byte(scrubValue)) {
		t.Fatal("a live session was rewritten")
	}
}

func TestScrubFollowsASymlink(t *testing.T) {
	path, _ := transcript(t)
	link := filepath.Join(t.TempDir(), "link.jsonl")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if res, err := Scrub(link, scrubRedactor(t), true, time.Now()); err != nil || !res.Written {
		t.Fatalf("%+v, %v", res, err)
	}
	if fi, err := os.Lstat(link); err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Fatal("the symlink was replaced by a file")
	}
	if got, _ := os.ReadFile(path); bytes.Contains(got, []byte(scrubValue)) {
		t.Fatal("the file the symlink points to still holds the value")
	}
}
