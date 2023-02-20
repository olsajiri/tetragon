package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
)

func main() {
	path := os.Args[1]
	ss := os.Args[2]

	fmt.Printf("path: %v ss: %v\n", path, ss)

	exec, err := link.OpenExecutable(path)
	if err != nil {
		fmt.Printf("link.OpenExecutable failed: %v\n", err)
		return
	}

	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Type: ebpf.Kprobe,
		Instructions: asm.Instructions{
			asm.LoadImm(asm.R0, 0, asm.DWord),
			asm.Return(),
		},
		License: "GPL",
	})

	if err != nil {
		fmt.Printf("failed to create prog: %v\n", err)
		return
	}

	for symbol, addr := range exec.Addresses {
		if !strings.Contains(symbol, ss) {
			continue
		}

		fmt.Printf("attaching symmbol %v (%v)\n", symbol, addr)
		_, err := exec.Uprobe(symbol, prog, nil)
		if err != nil {
			fmt.Printf("failed: %v\n", err)
			break
		}
	}
}
