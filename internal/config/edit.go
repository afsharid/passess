package config

import (
	"bytes"
	"errors"
	"fmt"
	"maps"
	"reflect"
	"regexp"

	"github.com/pelletier/go-toml/v2"
)

// Field is one key of a [secrets.NAME] table to set: Value is the TOML
// literal to write (`["codex"]`, `true`), or nil to remove the key.
type Field struct {
	Key   string
	Value *string
}

// SetSecretFields returns data with the [secrets.NAME] table's keys set as
// fields say. Every other byte stays as it was: comments, order and layout
// are the user's. The result is checked by parsing both versions; an edit
// that would change anything else is refused, never written.
func SetSecretFields(data []byte, name string, fields []Field) ([]byte, error) {
	lines := bytes.SplitAfter(data, []byte("\n"))
	start, end, err := secretTable(lines, name)
	if err != nil {
		return nil, err
	}
	for _, f := range fields {
		if !keyRe.MatchString(f.Key) {
			return nil, fmt.Errorf("%q is not a key passess edits", f.Key)
		}
		line := []byte(nil)
		if f.Value != nil {
			line = []byte(f.Key + " = " + *f.Value + "\n")
		}
		at, to, found, err := findKey(lines[start+1:end], f.Key)
		if err != nil {
			return nil, fmt.Errorf("secrets.%s.%s: %w", name, f.Key, err)
		}
		switch {
		case found && line == nil:
			lines = splice(lines, start+1+at, start+1+to, nil)
			end -= to - at
		case found:
			lines = splice(lines, start+1+at, start+1+to, [][]byte{line})
			end -= to - at - 1
		case line != nil:
			// After the table's last key, before the blank lines that part it
			// from the next table.
			at := start + 1
			for i := start + 1; i < end; i++ {
				if t := bytes.TrimSpace(lines[i]); len(t) > 0 && t[0] != '#' {
					at = i + 1
				}
			}
			if at > 0 && !bytes.HasSuffix(lines[at-1], []byte("\n")) {
				lines[at-1] = append(append([]byte{}, lines[at-1]...), '\n')
			}
			lines = splice(lines, at, at, [][]byte{line})
			end++
		}
	}
	out := bytes.Join(lines, nil)
	err = checkEdit(data, out, name, func(old map[string]any) (map[string]any, error) {
		next := maps.Clone(old)
		for _, f := range fields {
			if f.Value == nil {
				delete(next, f.Key)
				continue
			}
			var v map[string]any
			if err := toml.Unmarshal([]byte("v = "+*f.Value), &v); err != nil {
				return nil, fmt.Errorf("%s: not a TOML value", f.Key)
			}
			next[f.Key] = v["v"]
		}
		return next, nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// RemoveSecret returns data without the [secrets.NAME] table, checked the
// same way.
func RemoveSecret(data []byte, name string) ([]byte, error) {
	lines := bytes.SplitAfter(data, []byte("\n"))
	start, end, err := secretTable(lines, name)
	if err != nil {
		return nil, err
	}
	// Comments right above the header are the table's own.
	for start > 0 && bytes.HasPrefix(bytes.TrimSpace(lines[start-1]), []byte("#")) {
		start--
	}
	rest := splice(lines, start, end, nil)
	// The table's trailing blank lines went with it, so a blank line before it
	// now parts its neighbors; at the end of the file it parts nothing.
	if start > 0 && len(bytes.TrimSpace(rest[start-1])) == 0 && (start == len(rest) || start == len(rest)-1 && len(rest[start]) == 0) {
		rest = splice(rest, start-1, start, nil)
	}
	out := bytes.Join(rest, nil)
	if err := checkEdit(data, out, name, nil); err != nil {
		return nil, err
	}
	return out, nil
}

var keyRe = regexp.MustCompile(`^[a-z_]+$`)

// tableHeader is a line that opens a table or an array of tables.
var tableHeader = regexp.MustCompile(`^\s*\[`)

// secretTable finds the [secrets.NAME] header line and the line after the
// table's last line.
func secretTable(lines [][]byte, name string) (start, end int, err error) {
	q := regexp.QuoteMeta(name)
	header := regexp.MustCompile(`^\s*\[\s*secrets\s*\.\s*(` + q + `|"` + q + `"|'` + q + `')\s*\]\s*(#.*)?$`)
	start = -1
	for i, l := range lines {
		if header.Match(bytes.TrimRight(l, "\r\n")) {
			start = i
			break
		}
	}
	if start < 0 {
		return 0, 0, fmt.Errorf("secrets.%s is not written as a [secrets.%s] table, the only form passess edits; change it in the file yourself", name, name)
	}
	end = len(lines)
	for i := start + 1; i < len(lines); i++ {
		if tableHeader.Match(lines[i]) {
			end = i
			break
		}
	}
	return start, end, nil
}

// findKey finds key's assignment among body's lines: the line it starts on
// and the line after its value ends.
func findKey(body [][]byte, key string) (at, to int, found bool, err error) {
	assign := regexp.MustCompile(`^\s*` + regexp.QuoteMeta(key) + `\s*=`)
	for i, l := range body {
		if !assign.Match(l) {
			continue
		}
		depth := 0
		for j := i; j < len(body); j++ {
			d, err := bracketDepth(body[j], j == i)
			if err != nil {
				return 0, 0, false, err
			}
			depth += d
			if depth <= 0 {
				return i, j + 1, true, nil
			}
		}
		return 0, 0, false, errors.New("its value never ends")
	}
	return 0, 0, false, nil
}

// bracketDepth is how many brackets a line opens minus how many it closes,
// outside strings and comments. Multi-line strings are refused: passess does
// not edit what it cannot read with certainty.
func bracketDepth(line []byte, first bool) (int, error) {
	s := line
	if first {
		_, s, _ = bytes.Cut(line, []byte("="))
	}
	if bytes.Contains(s, []byte(`"""`)) || bytes.Contains(s, []byte(`'''`)) {
		return 0, errors.New("multi-line strings are not edited; change it in the file yourself")
	}
	depth := 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '#':
			return depth, nil
		case '[', '{':
			depth++
		case ']', '}':
			depth--
		case '"':
			for i++; i < len(s) && s[i] != '"'; i++ {
				if s[i] == '\\' {
					i++
				}
			}
		case '\'':
			for i++; i < len(s) && s[i] != '\''; i++ {
			}
		}
	}
	return depth, nil
}

func splice(lines [][]byte, from, to int, with [][]byte) [][]byte {
	out := make([][]byte, 0, len(lines)-(to-from)+len(with))
	out = append(out, lines[:from]...)
	out = append(out, with...)
	return append(out, lines[to:]...)
}

// checkEdit parses both versions and checks that secrets.NAME came out as
// expect says (nil: gone) and that nothing else changed.
func checkEdit(before, after []byte, name string, expect func(map[string]any) (map[string]any, error)) error {
	var b, a map[string]any
	if err := toml.Unmarshal(before, &b); err != nil {
		return errors.New("the config does not parse as it is; fix it first")
	}
	if err := toml.Unmarshal(after, &a); err != nil {
		return errors.New("the edit would not parse; config left unchanged")
	}
	bs, _ := b["secrets"].(map[string]any)
	as, _ := a["secrets"].(map[string]any)
	old, _ := bs[name].(map[string]any)
	got, kept := as[name].(map[string]any)
	switch {
	case expect == nil && as[name] != nil:
		return errors.New("the table is still there after removing it; config left unchanged")
	case expect != nil && !kept:
		return errors.New("the edit lost the table; config left unchanged")
	case expect != nil:
		want, err := expect(old)
		if err != nil {
			return err
		}
		if !reflect.DeepEqual(got, want) {
			return errors.New("the edit did not come out as intended; config left unchanged")
		}
	}
	for _, m := range []map[string]any{a, b} {
		if s, ok := m["secrets"].(map[string]any); ok {
			delete(s, name)
			if len(s) == 0 {
				delete(m, "secrets")
			}
		}
	}
	if !reflect.DeepEqual(a, b) {
		return errors.New("the edit would change more than this secret; config left unchanged")
	}
	return nil
}
