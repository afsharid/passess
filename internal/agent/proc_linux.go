package agent

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

func procInfo(pid int) (Proc, error) {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return Proc{}, err
	}
	// pid (comm) state ppid … starttime: comm may hold spaces and parentheses,
	// so the fields after it start at the last ')'.
	s := string(b)
	open, closing := strings.IndexByte(s, '('), strings.LastIndexByte(s, ')')
	if open < 0 || closing < open {
		return Proc{}, fmt.Errorf("/proc/%d/stat: unexpected format", pid)
	}
	f := strings.Fields(s[closing+1:])
	if len(f) < 20 {
		return Proc{}, fmt.Errorf("/proc/%d/stat: unexpected format", pid)
	}
	ppid, err1 := strconv.Atoi(f[1])
	start, err2 := strconv.ParseInt(f[19], 10, 64) // field 22, in clock ticks since boot
	if err1 != nil || err2 != nil {
		return Proc{}, fmt.Errorf("/proc/%d/stat: unexpected format", pid)
	}
	return Proc{PID: pid, PPID: ppid, Name: s[open+1 : closing], Start: start}, nil
}
