package cli

import (
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// u turns {200d} into that rune, so the test table shows each invisible
// character by name instead of holding it.
func u(s string) string {
	return regexp.MustCompile(`\{([0-9a-f]+)\}`).ReplaceAllStringFunc(s, func(m string) string {
		n, _ := strconv.ParseInt(m[1:len(m)-1], 16, 32)
		return string(rune(n))
	})
}

// both turns the {hex} marks in want into the runes and the <hex> marks into
// the spelled-out form, \uXXXX or \UXXXXXXXX.
func spelled(s string) string {
	s = regexp.MustCompile(`<([0-9a-f]+)>`).ReplaceAllStringFunc(s, func(m string) string {
		n, _ := strconv.ParseInt(m[1:len(m)-1], 16, 32)
		switch {
		case n > 0xffff:
			return `\U` + strings.Repeat("0", 8-len(m[1:len(m)-1])) + m[1:len(m)-1]
		case n >= 0x100:
			return `\u` + strings.Repeat("0", 4-len(m[1:len(m)-1])) + m[1:len(m)-1]
		}
		return `\x` + m[1:len(m)-1]
	})
	return u(s)
}

// Both views pass ordinary text of any script.
func TestSpellingKeepsOrdinaryText(t *testing.T) {
	for name, s := range map[string]string{
		"turkish":        "İstanbul/ığşüöç/dosya",
		"persian zwnj":   "می{200c}خواهم",
		"persian digit":  "۲{200c}تا",
		"hebrew rlm":     "שלום{200f}/x",
		"ltr mark":       "a{200e}b",
		"zwj family":     "{1f468}{200d}{1f469}{200d}{1f467}/a",
		"zwj with vs16":  "{1f3f3}{fe0f}{200d}{1f308}",
		"england flag":   "{1f3f4}{e0067}{e0062}{e0065}{e006e}{e0067}{e007f}/x",
		"cjk and arabic": "日本語/项目/مرحبا",
		"combining mark": "e{301}x",
	} {
		s = u(s)
		if got := visible(s); got != s {
			t.Errorf("visible(%s) = %q, want %q", name, got, s)
		}
		if got := printable(s); got != s {
			t.Errorf("printable(%s) = %q, want %q", name, got, s)
		}
	}
}

// What can mislead a reader is spelled out, never dropped, in both views.
func TestSpellingEscapesWhatMisleads(t *testing.T) {
	for in, want := range map[string]string{
		"a\x1b[2Jb":                    `a\x1b[2Jb`,
		"a\x7fb{9b}c":                  `a\x7fb\x9bc`,
		"a{202e}b{2069}c":              "a<202e>b<2069>c",
		"a{2028}b{2029}c":              "a<2028>b<2029>c",
		"a{200b}b":                     "a<200b>b",
		"a{ad}b{feff}c":                "a<ad>b<feff>c",
		"a{2060}b":                     "a<2060>b",
		"a{200d}":                      "a<200d>",
		"{200c}b":                      "<200c>b",
		"a {200d} b":                   "a <200d> b",
		"a{200d}{200d}b":               "a<200d><200d>b",
		"a{e0067}b":                    "a<e0067>b",
		"{1f3f4}{e0067}{e0062}":        "{1f3f4}<e0067><e0062>",        // no cancel tag: not a flag
		"{1f3f4}{e0067}{e007f}{e0067}": "{1f3f4}<e0067><e007f><e0067>", // the run must end at its cancel tag
		"x{e0067}{e007f}":              "x<e0067><e007f>",
		"{1f3f4}{e0067}A{e007f}":       "{1f3f4}<e0067>A<e007f>",
	} {
		if got := visible(u(in)); got != spelled(want) {
			t.Errorf("visible(%q) = %q, want %q", in, got, spelled(want))
		}
		if got := printable(u(in)); got != spelled(want) {
			t.Errorf("printable(%q) = %q, want %q", in, got, spelled(want))
		}
	}
	if got := visible("a\nb\rc\td"); got != `a\nb\rc\td` {
		t.Errorf("visible = %q", got)
	}
	// printable is for a line: a line feed is spelled, a tab is kept.
	if got := printable("a\nb\rc\td"); got != "a\\nb\\rc\td" {
		t.Errorf("printable = %q", got)
	}
	if got := printableLines(u("a{200b}b\nc\x1bd")); got != "a\\u200bb\nc\\x1bd" {
		t.Errorf("printableLines = %q", got)
	}
}

// A directory name shows as it is named, and a line feed in a name does not
// read as the name without it.
func TestScanPathShowsWhatTheNameHolds(t *testing.T) {
	noHarness(t)
	for _, tc := range []struct{ dir, shown string }{
		{u("می{200c}خواهم"), u("می{200c}خواهم")},
		{u("{1f468}{200d}{1f469}{200d}{1f467}"), u("{1f468}{200d}{1f469}{200d}{1f467}")},
		{"a\nb", `a\nb`},
	} {
		env := scanFixture(t, tc.dir)
		clone := strings.TrimSuffix(env, "/"+tc.dir+"/.env")
		out, errOut, _ := run(t, "scan", "--dir", clone)
		if !strings.Contains(out, "/"+tc.shown+"/.env") {
			t.Errorf("%q: the path is not shown as named:\n%s%s", tc.dir, out, errOut)
		}
	}
}
