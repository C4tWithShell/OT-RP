package main

import "syscall"

func checkPresents() bool {
	// on linux only make a system call to ptrace to get debugger presence
	_, _, res := syscall.RawSyscall(syscall.SYS_PTRACE, uintptr(syscall.PTRACE_TRACEME), 0, 0)

	if res == 1 {
		return true
	}
	return false
}
