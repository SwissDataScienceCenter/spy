package main

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
)

func readStringFromReg(pid int, addr uintptr) (string, error) {
	buffSize := 64
	maxBuffSize := 1000 * buffSize
	if addr == 0 {
		return "", nil
	}
	for {
		if buffSize > maxBuffSize {
			return "", fmt.Errorf("reached max reading buffer size trying to find 0x00")
		}
		buff := make([]byte, buffSize)
		_, err := syscall.PtracePeekData(pid, addr, buff)
		if err != nil {
			return "", err
		}
		ind := bytes.IndexByte(buff, 0x00)
		if ind == -1 {
			buffSize *= 2
			continue
		}
		output := make([]byte, ind+1)
		copy(output, buff[:ind+1])
		return string(output), nil
	}
}

func getFileOpenFlag(flag uint64) string {
	lastByteVal := flag % 8
	switch lastByteVal {
	case 0:
		return "readonly"
	case 1:
		return "writeonly"
	case 2:
		return "readwrite"
	default:
		return "unknown"
	}
}

func isPathGood(fp string) string {
	cwd, err := os.Getwd()
	if err != nil {
		log.Fatal(err)
	}
	cwd = filepath.Clean(cwd) + "/"
	var absPath string
	if filepath.IsAbs(fp) {
		absPath = fp
	} else {
		absPath, err = filepath.Abs(fp)
		if err != nil {
			log.Fatal(err)
		}
	}
	if strings.HasPrefix(absPath, cwd) {
		return absPath
	}
	return ""
}

func main() {
	log.Printf("Run %v\n", os.Args[1:])
	cmd := exec.Command(os.Args[1], os.Args[2:]...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	cmd.SysProcAttr = &syscall.SysProcAttr{Ptrace: true}
	err := cmd.Start()
	if err != nil {
		log.Fatal(err)
	}
	err = cmd.Wait()
	log.Printf("State: %v\n", err)

	entry := true

	for {
		var regs syscall.PtraceRegs
		err = syscall.PtraceGetRegs(cmd.Process.Pid, &regs)
		if err != nil {
			log.Panic(err)
		}

		if entry {
			switch regs.Orig_rax {
			case 80:
				path, err := readStringFromReg(cmd.Process.Pid, uintptr(regs.Rdi))
				if err != nil {
					log.Printf("error with peek data: %s\n", err.Error())
				}
				absPath := isPathGood(path)
				if absPath == "" {
					break
				}
				log.Printf("chdir %s\n", absPath)
			case 2:
				path, err := readStringFromReg(cmd.Process.Pid, uintptr(regs.Rdi))
				if err != nil {
					log.Printf("error with peek data: %s\n", err.Error())
				}
				absPath := isPathGood(path)
				if absPath == "" {
					break
				}
				log.Printf("open %s, flags %s, hexFlag %#v\n", absPath, getFileOpenFlag(regs.Rsi), regs.Rsi)
			case 257:
				path, err := readStringFromReg(cmd.Process.Pid, uintptr(regs.Rsi))
				if err != nil {
					log.Printf("error with peek data: %s\n", err.Error())
				}
				absPath := isPathGood(path)
				if absPath == "" {
					break
				}
				log.Printf("openat %s, flags %s, hexFlag %#v\n", absPath, getFileOpenFlag(regs.Rdx), regs.Rdx)
			}
		}

		err = syscall.PtraceSyscall(cmd.Process.Pid, 0)
		if err != nil {
			log.Panic(err)
		}

		var ws syscall.WaitStatus
		_, err = syscall.Wait4(cmd.Process.Pid, &ws, syscall.WALL, nil)
		if err != nil {
			log.Panic(err)
		}
		if ws.Exited() {
			break
		}
		entry = !entry
	}
}
