package harness

import "strings"

// Markers around the block passess owns in an instructions file.
const (
	BlockStart = "<!-- passess start -->"
	BlockEnd   = "<!-- passess end -->"
)

// Instructions is what every harness tells its model about secrets.
const Instructions = BlockStart + `
## Secrets (passess)

Secret values never enter this conversation, and that is deliberate.

- See which secrets exist: ` + "`passess list`" + `.
- Run a command that needs one through passess:
  ` + "`passess exec -s NAME -- command args`" + `. The value goes into that command's
  environment only and is redacted from its output.
- For HTTP, let passess send the request; it takes the value only to the hosts the
  secret lists: ` + "`passess http -s TOKEN -H 'Authorization: Bearer {{TOKEN}}' https://…`" + `.
  If it refuses the host, ask the user to add it in Passess.app or with
  ` + "`passess set TOKEN --hosts HOST`" + `; never edit the passess config yourself.
- ` + "`$NAME`" + ` in your own shell is empty; never put a secret in an argument.
- Never read ` + "`.env`" + ` files or credential files, and never ask the user to paste a
  secret. If one is missing, ask the user to run ` + "`passess add NAME --ref <reference>`" + `
  or ` + "`passess add NAME --keychain`" + `.
` + BlockEnd

// Block states.
const (
	BlockOK      = "ok"
	BlockMissing = "missing"
	BlockDrift   = "drift" // present, but not the current text
	BlockNone    = "none"  // the harness reads no user-level instructions file
)

// span locates the block in doc; ok is false when either marker is missing.
func span(doc string) (start, end int, ok bool) {
	start = strings.Index(doc, BlockStart)
	if start < 0 {
		return 0, 0, false
	}
	rel := strings.Index(doc[start:], BlockEnd)
	if rel < 0 {
		return 0, 0, false
	}
	return start, start + rel + len(BlockEnd), true
}

// BlockState reports whether doc carries the current block.
func BlockState(doc string) string {
	s, e, ok := span(doc)
	switch {
	case !ok:
		return BlockMissing
	case doc[s:e] == Instructions:
		return BlockOK
	default:
		return BlockDrift
	}
}

// Splice returns doc with the block replaced or appended.
func Splice(doc string) string {
	if s, e, ok := span(doc); ok {
		return doc[:s] + Instructions + doc[e:]
	}
	if doc != "" && !strings.HasSuffix(doc, "\n") {
		doc += "\n"
	}
	if doc != "" {
		doc += "\n"
	}
	return doc + Instructions + "\n"
}

// Unsplice returns doc without the block and the blank line before it.
func Unsplice(doc string) string {
	s, e, ok := span(doc)
	if !ok {
		return doc
	}
	head := strings.TrimRight(doc[:s], "\n")
	tail := strings.TrimLeft(doc[e:], "\n")
	switch {
	case head == "":
		return tail
	case tail == "":
		return head + "\n"
	default:
		return head + "\n\n" + tail
	}
}
