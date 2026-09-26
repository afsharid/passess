// Package jsonedit changes one member of a JSON or JSONC document and leaves
// every other byte alone: comments, trailing commas, key order and the file's
// own indentation survive. passess uses it to register MCP servers with
// harnesses that have no command for it. Adding a member and deleting it again
// gives back the original bytes.
package jsonedit

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/tailscale/hujson"
)

// Decode parses a JSON or JSONC document into out. src is not modified.
func Decode(src []byte, out any) error {
	v, err := hujson.Parse(bytes.Clone(src)) // Standardize rewrites the bytes it parsed
	if err != nil {
		return err
	}
	v.Standardize()
	return json.Unmarshal(v.Pack(), out)
}

// Set returns src with member name of the object at path set to value. The
// member, and any object on the way, is created when missing. An empty
// document counts as {}.
func Set(src []byte, path []string, name string, value any) ([]byte, error) {
	if len(bytes.TrimSpace(src)) == 0 {
		src = []byte("{}\n")
	}
	root, err := hujson.Parse(src)
	if err != nil {
		return nil, err
	}
	unit := indentUnit(src)
	at := &root
	for i, key := range path {
		obj, ok := at.Value.(*hujson.Object)
		if !ok {
			return nil, fmt.Errorf("%s is not an object", pointer(path[:i]))
		}
		m := member(obj, key)
		if m == nil {
			// Build the rest of the path around the new member.
			var nested any = map[string]any{name: value}
			for j := len(path) - 1; j > i; j-- {
				nested = map[string]any{path[j]: nested}
			}
			return insert(src, at, key, nested, unit)
		}
		at = &m.Value
	}
	obj, ok := at.Value.(*hujson.Object)
	if !ok {
		return nil, fmt.Errorf("%s is not an object", pointer(path))
	}
	if m := member(obj, name); m != nil {
		text, err := render(value, lineIndent(src, m.Name.StartOffset), unit)
		if err != nil {
			return nil, err
		}
		return splice(src, m.Value.StartOffset, m.Value.EndOffset, text), nil
	}
	return insert(src, at, name, value, unit)
}

// Delete returns src without member name of the object at path. A missing
// member or path leaves src as it is.
func Delete(src []byte, path []string, name string) ([]byte, error) {
	if len(bytes.TrimSpace(src)) == 0 {
		return src, nil
	}
	root, err := hujson.Parse(src)
	if err != nil {
		return nil, err
	}
	at := &root
	for _, key := range append(append([]string{}, path...), "") {
		obj, ok := at.Value.(*hujson.Object)
		if !ok {
			return src, nil
		}
		if key == "" { // reached the object that holds name
			return remove(src, at, obj, name), nil
		}
		m := member(obj, key)
		if m == nil {
			return src, nil
		}
		at = &m.Value
	}
	return src, nil
}

func member(obj *hujson.Object, key string) *hujson.ObjectMember {
	for i := range obj.Members {
		if lit, ok := obj.Members[i].Name.Value.(hujson.Literal); ok && lit.String() == key {
			return &obj.Members[i]
		}
	}
	return nil
}

func insert(src []byte, at *hujson.Value, name string, value any, unit string) ([]byte, error) {
	obj := at.Value.(*hujson.Object)
	open, closing := at.StartOffset, at.EndOffset-1
	key, err := marshal(name)
	if err != nil {
		return nil, err
	}
	base := lineIndent(src, open)
	if len(obj.Members) == 0 {
		text, err := render(value, base+unit, unit)
		if err != nil {
			return nil, err
		}
		inner := strings.TrimRight(string(src[open+1:closing]), " \t\r\n") // keep comments, if any
		return splice(src, open+1, closing, inner+"\n"+base+unit+key+": "+text+"\n"+base), nil
	}
	first, last := obj.Members[0].Name, &obj.Members[len(obj.Members)-1].Value
	if sameLine(src, open, closing) { // a one-line object stays one line
		text, err := marshal(value)
		if err != nil {
			return nil, err
		}
		return splice(src, last.EndOffset, last.EndOffset, ", "+key+": "+text), nil
	}
	indent := lineIndent(src, first.StartOffset)
	text, err := render(value, indent, unit)
	if err != nil {
		return nil, err
	}
	trailing := last.AfterExtra != nil // the last member already has a comma after it
	entry := indent + key + ": " + text
	if trailing {
		entry += ","
	}
	var edits []edit
	if !trailing {
		edits = append(edits, edit{last.EndOffset, last.EndOffset, ","})
	}
	if ls := lineStart(src, closing); strings.TrimSpace(string(src[ls:closing])) == "" {
		edits = append(edits, edit{ls, ls, entry + "\n"}) // the brace has its own line
	} else {
		edits = append(edits, edit{closing, closing, "\n" + entry + "\n" + base})
	}
	return apply(src, edits), nil
}

func remove(src []byte, at *hujson.Value, obj *hujson.Object, name string) []byte {
	idx := -1
	for i := range obj.Members {
		if lit, ok := obj.Members[i].Name.Value.(hujson.Literal); ok && lit.String() == name {
			idx = i
		}
	}
	if idx < 0 {
		return src
	}
	m := obj.Members[idx]
	from := m.Name.StartOffset
	ownLine := false
	if ls := lineStart(src, from); strings.TrimSpace(string(src[ls:from])) == "" {
		from, ownLine = ls, true // the member starts its line: take the whole line
	}
	comma := m.Value.EndOffset + len(m.Value.AfterExtra) // where a comma after the value sits
	last := idx == len(obj.Members)-1
	switch {
	case !last:
		next := obj.Members[idx+1].Name.StartOffset
		to := comma + 1
		if sameLine(src, to, next) {
			to = next // members share a line
		} else {
			to = lineEnd(src, to)
		}
		return splice(src, from, to, "")
	case idx > 0 && m.Value.AfterExtra == nil:
		// The last member, no trailing comma: the comma before it goes too,
		// but not a comment that follows that comma.
		prev := obj.Members[idx-1].Value
		prevComma := prev.EndOffset + len(prev.AfterExtra)
		if !ownLine {
			return splice(src, prevComma, m.Value.EndOffset, "")
		}
		return apply(src, []edit{{prevComma, prevComma + 1, ""}, {from, lineEnd(src, m.Value.EndOffset), ""}})
	case idx > 0:
		return splice(src, from, lineEnd(src, comma+1), "")
	default: // the only member
		to := m.Value.EndOffset
		if m.Value.AfterExtra != nil {
			to = comma + 1
		}
		out := splice(src, from, lineEnd(src, to), "")
		open := at.StartOffset
		closing := bytes.IndexByte(out[open:], '}') + open
		if strings.TrimSpace(string(out[open+1:closing])) == "" {
			out = splice(out, open+1, closing, "") // {} again
		}
		return out
	}
}

type edit struct {
	from, to int
	text     string
}

// apply makes non-overlapping edits given in ascending order.
func apply(src []byte, edits []edit) []byte {
	var b bytes.Buffer
	pos := 0
	for _, e := range edits {
		b.Write(src[pos:e.from])
		b.WriteString(e.text)
		pos = e.to
	}
	b.Write(src[pos:])
	return b.Bytes()
}

func splice(src []byte, from, to int, text string) []byte {
	return apply(src, []edit{{from, to, text}})
}

func marshal(v any) (string, error) {
	return render(v, "", "")
}

// render encodes v as JSON; with a unit, nested lines start with indent.
func render(v any, indent, unit string) (string, error) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if unit != "" {
		enc.SetIndent(indent, unit)
	}
	if err := enc.Encode(v); err != nil {
		return "", err
	}
	return strings.TrimSuffix(b.String(), "\n"), nil
}

func lineStart(src []byte, off int) int {
	return bytes.LastIndexByte(src[:off], '\n') + 1
}

// lineEnd is the offset after the newline ending the line at off, if only
// whitespace or a comment is left on it; otherwise off.
func lineEnd(src []byte, off int) int {
	nl := bytes.IndexByte(src[off:], '\n')
	if nl < 0 {
		if strings.TrimSpace(string(src[off:])) == "" {
			return len(src)
		}
		return off
	}
	rest := strings.TrimSpace(string(src[off : off+nl]))
	if rest == "" || strings.HasPrefix(rest, "//") || (strings.HasPrefix(rest, "/*") && strings.HasSuffix(rest, "*/")) {
		return off + nl + 1
	}
	return off
}

func lineIndent(src []byte, off int) string {
	ls := lineStart(src, off)
	end := ls
	for end < len(src) && (src[end] == ' ' || src[end] == '\t') {
		end++
	}
	return string(src[ls:end])
}

func sameLine(src []byte, a, b int) bool {
	if a > b {
		a, b = b, a
	}
	return !bytes.Contains(src[a:b], []byte{'\n'})
}

// indentUnit guesses the document's indentation from its first indented line.
func indentUnit(src []byte) string {
	for _, line := range strings.Split(string(src), "\n") {
		trimmed := strings.TrimLeft(line, " \t")
		if trimmed == "" || len(trimmed) == len(line) {
			continue
		}
		if line[0] == '\t' {
			return "\t"
		}
		return line[:len(line)-len(trimmed)]
	}
	return "  "
}

func pointer(path []string) string {
	if len(path) == 0 {
		return "the document"
	}
	return "/" + strings.Join(path, "/")
}
