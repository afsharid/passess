package agent

import (
	"golang.org/x/sys/unix"
)

func procInfo(pid int) (Proc, error) {
	k, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
	if err != nil {
		return Proc{}, err
	}
	if k.Proc.P_pid == 0 && pid != 0 {
		return Proc{}, errNoProc // the kernel answers an unused pid with zeroes
	}
	name := k.Proc.P_comm[:]
	for i, b := range name {
		if b == 0 {
			name = name[:i]
			break
		}
	}
	start := k.Proc.P_starttime.Sec*1_000_000 + int64(k.Proc.P_starttime.Usec)
	return Proc{PID: int(k.Proc.P_pid), PPID: int(k.Eproc.Ppid), Name: string(name), Start: start}, nil
}
