package main

import (
	"syscall"
)

var (
	kernel32                 = syscall.NewLazyDLL("kernel32.dll")
	CreateToolhelp32Snapshot = kernel32.NewProc("CreateToolhelp32Snapshot")
	Process32First           = kernel32.NewProc("Process32FirstW")
	Process32Next            = kernel32.NewProc("Process32NextW")
	CloseHandle              = kernel32.NewProc("CloseHandle")
	// on windows only, make a system call to kernel32.dll for isDebuggerPresent to get debugger presence
	isDebuggerPresent = kernel32.NewProc("IsDebuggerPresent")
)

type PROCESSENTRY32 struct {
	dwSize              uint32
	cntUsage            uint32
	th32ProcessID       uint32
	th32DefaultHeapID   uintptr
	th32ModuleID        uint32
	cntThreads          uint32
	th32ParentProcessID uint32
	pcPriClassBase      int32
	dwFlags             uint32
	szExeFile           [260]uint16
}

func checkPresents() bool {
	flag, _, _ := isDebuggerPresent.Call()
	if flag != 0 {
		return true
	}
	return false
	// } else {
	// 	EvidenceOfSandbox := make([]string, 0)
	// 	sandboxProcesses := [...]string{`vmsrvc`, `tcpview`, `wireshark`, `visual basic`, `fiddler`, `vmware`, `vbox`, `process explorer`, `autoit`, `vboxtray`, `vmtools`, `vmrawdsk`, `vmusbmouse`, `vmvss`, `vmscsi`, `vmxnet`, `vmx_svga`, `vmmemctl`, `df5serv`, `vboxservice`, `vmhgfs`}

	// 	// TH32CS_SNAPPROCESS == 0x00000002, meaning snapshot all processes
	// 	hProcessSnap, _, _ := CreateToolhelp32Snapshot.Call(2, 0)
	// 	if hProcessSnap > 0 {
	// 		defer CloseHandle.Call(hProcessSnap)

	// 		exeNames := make([]string, 0, 100)
	// 		var pe32 PROCESSENTRY32
	// 		pe32.dwSize = uint32(unsafe.Sizeof(pe32))

	// 		Process32First.Call(hProcessSnap, uintptr(unsafe.Pointer(&pe32)))

	// 		for {

	// 			exeNames = append(exeNames, syscall.UTF16ToString(pe32.szExeFile[:260]))

	// 			retVal, _, _ := Process32Next.Call(hProcessSnap, uintptr(unsafe.Pointer(&pe32)))
	// 			if retVal == 0 {
	// 				break
	// 			}

	// 		}

	// 		for _, exe := range exeNames {
	// 			for _, sandboxProc := range sandboxProcesses {
	// 				if strings.Contains(strings.ToLower(exe), strings.ToLower(sandboxProc)) {
	// 					EvidenceOfSandbox = append(EvidenceOfSandbox, exe)
	// 				}
	// 			}
	// 		}

	// 		if len(EvidenceOfSandbox) == 0 {
	// 			return false
	// 		} else {
	// 			return true
	// 		}
	// 	} else {
	// 		return false
	// 	}
	// }
}
