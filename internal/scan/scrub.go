package scan

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/afsharid/passess/internal/redact"
)

// InUse is how recently a transcript may have been written and still be
// scrubbed: a harness keeps appending to the transcript of a live session,
// and a rewrite would lose what it adds meanwhile.
const InUse = 10 * time.Minute

// Scrubbed is what Scrub did to one file, or would do.
type Scrubbed struct {
	Path     string         `json:"path"`
	Replaced map[string]int `json:"replaced"`          // secret name -> values replaced
	Skipped  string         `json:"skipped,omitempty"` // why the file was left as it was
	Written  bool           `json:"written"`
}

// Scrub replaces every value the redactor knows, in each encoding it knows,
// with [REDACTED:NAME] throughout path. With write false it only counts. It
// writes a new file beside the old one and renames it over, with the old
// mode and modification time: harnesses sort sessions by that time. It leaves
// alone a file written within InUse, one that changes while it works, and one
// in which a line that was JSON would stop being JSON.
func Scrub(path string, known *redact.Redactor, write bool, now time.Time) (Scrubbed, error) {
	res := Scrubbed{Path: path, Replaced: map[string]int{}}
	real, err := filepath.EvalSymlinks(path)
	if err != nil {
		return res, err
	}
	before, err := os.Stat(real)
	if err != nil {
		return res, err
	}
	if now.Sub(before.ModTime()) < InUse {
		res.Skipped = "written in the last 10 minutes; its session may still be adding to it"
		return res, nil
	}
	in, err := os.Open(real)
	if err != nil {
		return res, err
	}
	defer in.Close()

	var out *os.File
	if write {
		if out, err = os.CreateTemp(filepath.Dir(real), ".passess-scrub-*"); err != nil {
			return res, err
		}
		defer func() {
			if out != nil { // not renamed into place
				_ = out.Close()
				_ = os.Remove(out.Name())
			}
		}()
	}
	jsonLines := strings.HasSuffix(real, ".jsonl") || strings.HasSuffix(real, ".json")
	w := bufio.NewWriterSize(io.Discard, 64<<10)
	if out != nil {
		w.Reset(out)
	}
	r := bufio.NewReaderSize(in, 64<<10)
	for {
		line, rerr := r.ReadBytes('\n')
		if len(line) > 0 {
			masked, hit := line, false
			known.Each(line, func(_, _ int, name string) {
				res.Replaced[name]++
				hit = true
			})
			if hit {
				masked = known.Redact(line)
				if jsonLines && json.Valid(bytes.TrimSpace(line)) && !json.Valid(bytes.TrimSpace(masked)) {
					res.Skipped = "a line that is JSON would stop being JSON"
					res.Replaced = map[string]int{}
					return res, nil
				}
			}
			if _, err := w.Write(masked); err != nil {
				return res, err
			}
			clear(line)
		}
		if errors.Is(rerr, io.EOF) {
			break
		}
		if rerr != nil {
			return res, rerr
		}
	}
	if !write || len(res.Replaced) == 0 {
		return res, nil
	}
	if err := w.Flush(); err != nil {
		return res, err
	}
	if err := out.Sync(); err != nil {
		return res, err
	}
	if err := out.Chmod(before.Mode().Perm()); err != nil {
		return res, err
	}
	if err := out.Close(); err != nil {
		return res, err
	}
	if after, err := os.Stat(real); err != nil || after.Size() != before.Size() || !after.ModTime().Equal(before.ModTime()) {
		res.Skipped = "it changed while being scrubbed"
		return res, nil
	}
	if err := os.Rename(out.Name(), real); err != nil {
		return res, err
	}
	out = nil
	res.Written = true
	return res, os.Chtimes(real, now, before.ModTime())
}
