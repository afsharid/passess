package policy

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// fileStamp identifies a file's content without reading it. ctime is the part
// that matters: any write or chmod moves it, and unlike mtime the file's owner
// cannot set it back. A replaced file has a new inode.
type fileStamp struct {
	dev, ino     uint64
	size         int64
	mtime, ctime int64
}

func stampOf(path string) (fileStamp, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return fileStamp{}, err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fileStamp{}, errors.New("no file identity on this system")
	}
	return fileStamp{dev: uint64(st.Dev), ino: st.Ino, size: fi.Size(), mtime: fi.ModTime().UnixNano(), ctime: ctimeOf(st)}, nil //nolint:unconvert,gosec // Dev is int32 on darwin; it is only compared with itself
}

// ErrChanged means the program's file changed after it was judged.
var ErrChanged = errors.New("the program changed after it was checked")

// Unchanged reports whether the file at p.Path is still the one Inspect
// judged. Call it immediately before running the program: what was checked is
// then what receives the secrets, even when a person took a minute to approve.
func (p Program) Unchanged() error {
	if p.stamp == (fileStamp{}) {
		return nil // not made by Inspect: there is nothing to compare
	}
	now, err := stampOf(p.Path)
	if err != nil || now != p.stamp {
		return fmt.Errorf("%w: %s; run the command again", ErrChanged, p.Path)
	}
	for _, i := range p.interps {
		if i.written != "" {
			now, err := filepath.EvalSymlinks(i.written)
			if i.path == "" && err != nil {
				continue // still not there
			}
			if abs, aerr := filepath.Abs(now); err != nil || aerr != nil || abs != i.path {
				return fmt.Errorf("%w: %s; run the command again", ErrChanged, i.written)
			}
		}
		if i.path == "" {
			continue
		}
		if now, err := stampOf(i.path); err != nil || now != i.stamp {
			return fmt.Errorf("%w: %s; run the command again", ErrChanged, i.path)
		}
	}
	return nil
}
