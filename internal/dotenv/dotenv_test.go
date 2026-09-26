package dotenv

import (
	"reflect"
	"testing"
)

func TestParse(t *testing.T) {
	content := "# comment\n" +
		"PLAIN=value\n" +
		"export EXPORTED=exp # trailing comment\n" +
		"DOUBLE=\"with \\\"quotes\\\" and\\nnewline\"\n" +
		"SINGLE='lit $HOME \\n'\n" +
		"  SPACED = padded  \n" +
		"BROKEN=\"never closed\n" +
		"not an assignment\n" +
		"EMPTY=\n"
	got := Parse(content)
	want := []Entry{
		{2, "PLAIN", "value"},
		{3, "EXPORTED", "exp"},
		{4, "DOUBLE", "with \"quotes\" and\nnewline"},
		{5, "SINGLE", `lit $HOME \n`},
		{6, "SPACED", "padded"},
		{9, "EMPTY", ""},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got  %+v\nwant %+v", got, want)
	}
}

func TestWithout(t *testing.T) {
	if got := Without("A=1\nB=2\nC=3\n", map[int]bool{2: true}); got != "A=1\nC=3\n" {
		t.Fatalf("%q", got)
	}
}
