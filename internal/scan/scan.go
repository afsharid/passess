// Package scan looks for secrets stored in clear: in harness configs,
// dotfiles, .env files and harness transcripts. It reports where and what
// kind, never the value: a finding carries a fingerprint (a truncated SHA-256)
// so the same secret can be recognized across files without being shown.
package scan

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"sort"
	"sync"

	"github.com/afsharid/passess/internal/redact"
)

// Finding is one secret found in clear.
type Finding struct {
	Path        string `json:"path"`
	Line        int    `json:"line"`
	Category    string `json:"category"` // config | dotfile | env | transcript | path
	Kind        string `json:"kind"`     // known (a value passess manages) | rule (a secret-shaped string)
	Secret      string `json:"secret,omitempty"`
	Rule        string `json:"rule,omitempty"`
	Fingerprint string `json:"fingerprint"`
	Length      int    `json:"length"`
}

// Target is a file to scan.
type Target struct {
	Path     string
	Category string
}

// Scanner combines known-value matching with the rule set. Either may be nil.
type Scanner struct {
	Known   *redact.Redactor
	KnownFP map[string]string // secret name -> fingerprint of its value
	Rules   *Rules
}

// Fingerprint identifies a value without revealing it.
func Fingerprint(v []byte) string {
	sum := sha256.Sum256(v)
	return hex.EncodeToString(sum[:6])
}

// File scans one file line by line. Binary files are skipped.
func (s *Scanner) File(t Target) ([]Finding, error) {
	f, err := os.Open(t.Path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	r := bufio.NewReaderSize(f, 64<<10)
	if head, _ := r.Peek(8 << 10); bytes.IndexByte(head, 0) >= 0 {
		return nil, nil
	}
	var out []Finding
	for n := 1; ; n++ {
		line, err := r.ReadBytes('\n')
		if len(line) > 0 {
			out = append(out, s.line(t, n, line)...)
		}
		clear(line)
		if errors.Is(err, io.EOF) {
			return out, nil
		}
		if err != nil {
			return out, err
		}
	}
}

func (s *Scanner) line(t Target, n int, line []byte) []Finding {
	var out []Finding
	type span struct{ start, end int }
	var known []span
	if s.Known != nil {
		s.Known.Each(line, func(start, end int, name string) {
			known = append(known, span{start, end})
			out = append(out, Finding{Path: t.Path, Line: n, Category: t.Category, Kind: "known",
				Secret: name, Fingerprint: s.KnownFP[name], Length: end - start})
		})
	}
	if s.Rules != nil {
		for _, m := range s.Rules.Line(t.Path, string(line)) {
			overlaps := false
			for _, k := range known {
				overlaps = overlaps || (m.Start < k.end && m.Start+len(m.Secret) > k.start)
			}
			if overlaps {
				continue // already reported by name
			}
			out = append(out, Finding{Path: t.Path, Line: n, Category: t.Category, Kind: "rule",
				Rule: m.Rule, Fingerprint: Fingerprint([]byte(m.Secret)), Length: len(m.Secret)})
		}
	}
	return out
}

// All scans targets in parallel and returns the findings sorted by path and
// line, plus the files that could not be read.
func (s *Scanner) All(targets []Target, workers int) ([]Finding, []error) {
	if workers < 1 {
		workers = 1
	}
	jobs := make(chan Target)
	var mu sync.Mutex
	var findings []Finding
	var errs []error
	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for t := range jobs {
				f, err := s.File(t)
				mu.Lock()
				findings = append(findings, f...)
				if err != nil && !errors.Is(err, os.ErrNotExist) {
					errs = append(errs, err)
				}
				mu.Unlock()
			}
		}()
	}
	for _, t := range targets {
		jobs <- t
	}
	close(jobs)
	wg.Wait()
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].Path != findings[j].Path {
			return findings[i].Path < findings[j].Path
		}
		return findings[i].Line < findings[j].Line
	})
	return findings, errs
}
