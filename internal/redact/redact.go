// Package redact removes known secret values, and their common encodings, from
// byte streams.
//
// Matching is exact: the redactor knows the values it looks for. Each value is
// expanded into variants (raw, JSON-escaped, URL-encoded, base64 at every byte
// alignment) and occurrences are replaced leftmost-longest with
// "[REDACTED:NAME]", a token without quotes or backslashes that stays valid
// inside JSON, TOML and YAML strings.
//
// A value that is transformed in any other way — split, reversed, hashed — is
// not recognized. Redaction is a net, not a boundary.
package redact

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"unsafe"

	"github.com/afsharid/passess/internal/secret"
)

// Secret is a named value to redact.
type Secret struct {
	Name  string
	Value secret.Value
}

// Options tune a Redactor. The zero Options apply the defaults.
type Options struct {
	// MinLen is the length below which a value draws a warning (default 8).
	// Values shorter than HardMinLen are refused outright.
	MinLen int
}

// HardMinLen is the shortest value passess agrees to redact: anything shorter
// would match ordinary text all the time.
const HardMinLen = 4

// minBase64 is the shortest base64 fragment kept as a variant.
const minBase64 = 16

var nameRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// ErrTooShort is returned for values shorter than HardMinLen.
var ErrTooShort = errors.New("secret value too short to redact safely")

// Redactor holds the patterns for a set of secrets and is safe for concurrent
// use by several Writers. Its state sits behind an unsafe.Pointer so that no
// reflection-based printing of a struct holding a Redactor can reach the
// patterns, which are copies of secret values.
type Redactor struct{ s unsafe.Pointer }

type state struct {
	pats    [][]byte // every variant of every value
	repl    [][]byte // replacement for pats[i]
	m       matcher
	secrets int
}

func (r *Redactor) st() *state { return (*state)(r.s) }

// New builds a Redactor. Warnings name secrets whose value is shorter than
// Options.MinLen; neither warnings nor errors include a value.
func New(secrets []Secret, opt Options) (*Redactor, []string, error) {
	if opt.MinLen == 0 {
		opt.MinLen = 8
	}
	sorted := append([]Secret(nil), secrets...)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].Name < sorted[j].Name })

	st := &state{}
	seen := map[string]bool{}
	var warnings []string
	for _, s := range sorted {
		if !nameRe.MatchString(s.Name) {
			return nil, nil, fmt.Errorf("secret name %q is not a valid identifier", s.Name)
		}
		v := s.Value.Bytes()
		if len(v) == 0 {
			continue
		}
		if len(v) < HardMinLen {
			return nil, nil, fmt.Errorf("%s: %w (%d bytes, minimum %d)", s.Name, ErrTooShort, len(v), HardMinLen)
		}
		if len(v) < opt.MinLen {
			warnings = append(warnings, fmt.Sprintf("%s is only %d bytes long; redacting it may also hide unrelated text", s.Name, len(v)))
		}
		st.secrets++
		repl := []byte("[REDACTED:" + s.Name + "]")
		for _, p := range variants(v) {
			if seen[string(p)] {
				continue // an identical pattern from an earlier secret keeps its name
			}
			seen[string(p)] = true
			st.pats = append(st.pats, p)
			st.repl = append(st.repl, repl)
		}
	}
	st.m = newMatcher(st.pats)
	return &Redactor{unsafe.Pointer(st)}, warnings, nil //nolint:gosec // G103: opaque to reflection, see Redactor
}

// variants returns the raw value and the encodings in which it commonly
// appears in program output.
func variants(v []byte) [][]byte {
	out := [][]byte{bytes.Clone(v)}
	add := func(p []byte) {
		if len(p) >= HardMinLen && !bytes.Equal(p, v) {
			out = append(out, p)
		}
	}

	var buf bytes.Buffer
	for _, html := range []bool{true, false} {
		buf.Reset()
		enc := json.NewEncoder(&buf)
		enc.SetEscapeHTML(html)
		if enc.Encode(string(v)) == nil {
			j := bytes.TrimSuffix(buf.Bytes(), []byte("\n"))
			add(bytes.Clone(j[1 : len(j)-1]))
		}
	}

	for _, esc := range []string{url.QueryEscape(string(v)), url.PathEscape(string(v))} {
		add([]byte(esc))
		add([]byte(lowerPercent(esc)))
	}

	for _, enc := range []*base64.Encoding{base64.RawStdEncoding, base64.RawURLEncoding} {
		for off := range 3 {
			in := append(make([]byte, off), v...)
			e := enc.EncodeToString(in)
			start := (off*8 + 5) / 6 // first character that encodes only value bits
			end := len(in) * 8 / 6   // later characters also encode whatever follows
			if end-start >= minBase64 {
				add([]byte(e[start:end]))
			}
		}
	}
	return out
}

func lowerPercent(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) {
			b.WriteByte('%')
			b.WriteString(strings.ToLower(s[i+1 : i+3]))
			i += 2
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// Redact returns b with every occurrence of every pattern replaced. The result
// is b itself when nothing matched.
func (r *Redactor) Redact(b []byte) []byte {
	out, n := r.process(nil, b, true)
	if out == nil {
		return b[:n]
	}
	return out
}

// process redacts b into dst. Unless final, it stops before the longest suffix
// of b that could still grow into a match. It returns the redacted bytes and
// how many bytes of b they cover; the redacted bytes are nil when nothing in
// the covered part matched, so the caller can pass b[:n] on unchanged.
func (r *Redactor) process(dst, b []byte, final bool) (out []byte, n int) {
	st := r.st()
	limit := len(b)
	if !final {
		limit -= st.holdBack(b)
	}
	i, copied, matched := 0, 0, false
	for i < limit {
		start, idx := st.m.next(b, i, limit)
		if idx < 0 {
			break
		}
		matched = true
		dst = append(dst, b[copied:start]...)
		dst = append(dst, st.repl[idx]...)
		i = start + len(st.pats[idx])
		copied = i
	}
	end := max(limit, copied)
	if !matched {
		return nil, end
	}
	return append(dst, b[copied:end]...), end
}

// holdBack is the length of the longest suffix of b that is a proper prefix of
// some pattern: those bytes may be the start of a secret still being written.
func (st *state) holdBack(b []byte) int {
	longest := 0
	for _, p := range st.pats {
		for k := min(len(p)-1, len(b)); k > longest; k-- {
			if b[len(b)-k] == p[0] && bytes.Equal(b[len(b)-k:], p[:k]) {
				longest = k
				break
			}
		}
	}
	return longest
}

// Len reports how many distinct secrets the Redactor knows.
func (r *Redactor) Len() int { return r.st().secrets }

// Zero overwrites the patterns, which are copies of secret values. The
// Redactor must not be used afterwards.
func (r *Redactor) Zero() {
	st := r.st()
	for _, p := range st.pats {
		clear(p)
	}
	*st = state{}
}

// String never shows patterns.
func (r *Redactor) String() string {
	st := r.st()
	return fmt.Sprintf("redact.Redactor{%d secrets, %d patterns}", st.secrets, len(st.pats))
}
