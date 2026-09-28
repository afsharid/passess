package policy

import "syscall"

func ctimeOf(st *syscall.Stat_t) int64 { return st.Ctimespec.Nano() }
