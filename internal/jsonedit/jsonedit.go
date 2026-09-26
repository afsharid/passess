// Package jsonedit changes one member of a JSON or JSONC object, or one
// element of an array, and leaves every other byte alone: comments, trailing
// commas, key order and the file's own indentation survive. passess uses it to
// register MCP servers and hooks with harnesses that have no command for it.
// Adding something and removing it again gives back the original bytes.
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

// Append returns src with value added as the last element of the array at
// path; the array, and any object on the way, is created when missing.
func Append(src []byte, path []string, value any) ([]byte, error) {
	if len(path) == 0 {
		return nil, fmt.Errorf("append needs a path to an array")
	}
	if len(bytes.TrimSpace(src)) == 0 {
		src = []byte("{}\n")
	}
	root, err := hujson.Parse(src)
	if err != nil {
		return nil, err
	}
	at, ok := find(&root, path)
	if !ok {
		return Set(src, path[:len(path)-1], path[len(path)-1], []any{value})
	}
	if _, isArray := at.Value.(*hujson.Array); !isArray {
		return nil, fmt.Errorf("%s is not an array", pointer(path))
	}
	return insertItem(src, at, "", value, indentUnit(src))
}

// RemoveWhere returns src without the elements of the array at path for which
// match, given the element decoded, reports true. A missing path leaves src as
// it is.
func RemoveWhere(src []byte, path []string, match func(any) bool) ([]byte, error) {
	for {
		if len(bytes.TrimSpace(src)) == 0 {
			return src, nil
		}
		root, err := hujson.Parse(src)
		if err != nil {
			return nil, err
		}
		at, ok := find(&root, path)
		if !ok {
			return src, nil
		}
		arr, ok := at.Value.(*hujson.Array)
		if !ok {
			return nil, fmt.Errorf("%s is not an array", pointer(path))
		}
		idx := -1
		for i := range arr.Elements {
			var v any
			if Decode(src[arr.Elements[i].StartOffset:arr.Elements[i].EndOffset], &v) == nil && match(v) {
				idx = i
				break
			}
		}
		if idx < 0 {
			return src, nil
		}
		src = removeItem(src, at, idx)
	}
}

// find walks path through objects.
func find(root *hujson.Value, path []string) (*hujson.Value, bool) {
	at := root
	for _, key := range path {
		obj, ok := at.Value.(*hujson.Object)
		if !ok {
			return nil, false
		}
		m := member(obj, key)
		if m == nil {
			return nil, false
		}
		at = &m.Value
	}
	return at, true
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
			for i := range obj.Members {
				if lit, ok := obj.Members[i].Name.Value.(hujson.Literal); ok && lit.String() == name {
					return removeItem(src, at, i), nil
				}
			}
			return src, nil
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
	key, err := marshal(name)
	if err != nil {
		return nil, err
	}
	return insertItem(src, at, key+": ", value, unit)
}

// item is one member of an object or one element of an array: where its text
// starts (at the name, for a member) and its value.
type item struct {
	start int
	val   *hujson.Value
}

func items(at *hujson.Value) (list []item, closer byte) {
	switch c := at.Value.(type) {
	case *hujson.Object:
		for i := range c.Members {
			list = append(list, item{c.Members[i].Name.StartOffset, &c.Members[i].Value})
		}
		return list, '}'
	case *hujson.Array:
		for i := range c.Elements {
			list = append(list, item{c.Elements[i].StartOffset, &c.Elements[i]})
		}
		return list, ']'
	}
	return nil, 0
}

// insertItem adds prefix+value (prefix is `"name": ` for a member, "" for an
// element) after the last item of the object or array at.
func insertItem(src []byte, at *hujson.Value, prefix string, value any, unit string) ([]byte, error) {
	list, _ := items(at)
	open, closing := at.StartOffset, at.EndOffset-1
	base := lineIndent(src, open)
	if len(list) == 0 {
		text, err := render(value, base+unit, unit)
		if err != nil {
			return nil, err
		}
		inner := strings.TrimRight(string(src[open+1:closing]), " \t\r\n") // keep comments, if any
		return splice(src, open+1, closing, inner+"\n"+base+unit+prefix+text+"\n"+base), nil
	}
	first, last := list[0], list[len(list)-1].val
	if sameLine(src, open, closing) { // a one-line container stays one line
		text, err := marshal(value)
		if err != nil {
			return nil, err
		}
		return splice(src, last.EndOffset, last.EndOffset, ", "+prefix+text), nil
	}
	indent := lineIndent(src, first.start)
	text, err := render(value, indent, unit)
	if err != nil {
		return nil, err
	}
	trailing := last.AfterExtra != nil // the last item already has a comma after it
	entry := indent + prefix + text
	if trailing {
		entry += ","
	}
	var edits []edit
	if !trailing {
		edits = append(edits, edit{last.EndOffset, last.EndOffset, ","})
	}
	if ls := lineStart(src, closing); strings.TrimSpace(string(src[ls:closing])) == "" {
		edits = append(edits, edit{ls, ls, entry + "\n"}) // the closer has its own line
	} else {
		edits = append(edits, edit{closing, closing, "\n" + entry + "\n" + base})
	}
	return apply(src, edits), nil
}

// removeItem deletes item idx of the object or array at.
func removeItem(src []byte, at *hujson.Value, idx int) []byte {
	list, closer := items(at)
	m := list[idx]
	from := m.start
	ownLine := false
	if ls := lineStart(src, from); strings.TrimSpace(string(src[ls:from])) == "" {
		from, ownLine = ls, true // the item starts its line: take the whole line
	}
	comma := m.val.EndOffset + len(m.val.AfterExtra) // where a comma after the value sits
	last := idx == len(list)-1
	switch {
	case !last:
		next := list[idx+1].start
		to := comma + 1
		if sameLine(src, to, next) {
			to = next // items share a line
		} else {
			to = lineEnd(src, to)
		}
		return splice(src, from, to, "")
	case idx > 0 && m.val.AfterExtra == nil:
		// The last item, no trailing comma: the comma before it goes too,
		// but not a comment that follows that comma.
		prev := list[idx-1].val
		prevComma := prev.EndOffset + len(prev.AfterExtra)
		if !ownLine {
			return splice(src, prevComma, m.val.EndOffset, "")
		}
		return apply(src, []edit{{prevComma, prevComma + 1, ""}, {from, lineEnd(src, m.val.EndOffset), ""}})
	case idx > 0:
		return splice(src, from, lineEnd(src, comma+1), "")
	default: // the only item
		to := m.val.EndOffset
		if m.val.AfterExtra != nil {
			to = comma + 1
		}
		out := splice(src, from, lineEnd(src, to), "")
		open := at.StartOffset
		closing := bytes.IndexByte(out[open:], closer) + open
		if strings.TrimSpace(string(out[open+1:closing])) == "" {
			out = splice(out, open+1, closing, "") // {} or [] again
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
