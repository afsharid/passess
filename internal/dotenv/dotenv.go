// Package dotenv reads .env files well enough to move their secrets out: it
// knows KEY=value, export KEY=value, single- and double-quoted values and
// comments, and it can write the file back without chosen lines.
package dotenv

import (
	"regexp"
	"strings"
)

// Entry is one assignment.
type Entry struct {
	Line  int // 1-based
	Key   string
	Value string
}

var assign = regexp.MustCompile(`^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_.]*)\s*=\s*(.*)$`)

// Parse returns the assignments in content. Lines it does not understand are
// ignored; multi-line quoted values are not supported and are skipped.
func Parse(content string) []Entry {
	var out []Entry
	for i, line := range strings.Split(content, "\n") {
		m := assign.FindStringSubmatch(strings.TrimRight(line, "\r"))
		if m == nil {
			continue
		}
		v, ok := value(m[2])
		if !ok {
			continue
		}
		out = append(out, Entry{Line: i + 1, Key: m[1], Value: v})
	}
	return out
}

func value(raw string) (string, bool) {
	raw = strings.TrimSpace(raw)
	switch {
	case strings.HasPrefix(raw, `"`):
		end := closing(raw[1:], '"')
		if end < 0 {
			return "", false
		}
		r := strings.NewReplacer(`\n`, "\n", `\t`, "\t", `\"`, `"`, `\\`, `\`)
		return r.Replace(raw[1 : 1+end]), true
	case strings.HasPrefix(raw, `'`):
		end := strings.IndexByte(raw[1:], '\'')
		if end < 0 {
			return "", false
		}
		return raw[1 : 1+end], true
	default:
		if i := strings.Index(raw, " #"); i >= 0 {
			raw = raw[:i]
		}
		return strings.TrimSpace(raw), true
	}
}

// closing finds the unescaped quote q in s.
func closing(s string, q byte) int {
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\\':
			i++
		case q:
			return i
		}
	}
	return -1
}

// Without returns content without the given line numbers.
func Without(content string, lines map[int]bool) string {
	parts := strings.Split(content, "\n")
	kept := parts[:0]
	for i, p := range parts {
		if !lines[i+1] {
			kept = append(kept, p)
		}
	}
	return strings.Join(kept, "\n")
}
