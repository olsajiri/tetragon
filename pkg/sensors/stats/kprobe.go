package stats

import (
	"fmt"

	"github.com/cilium/ebpf/link"
)

type Kprobe struct {
	Function string
}

func (s Kprobe) Process(link link.Link) error {
	info, err := link.Info()
	if err != nil {
		return fmt.Errorf("failed to get link info: %w", err)
	}

	fd := info.PerfFd()
	fmt.Printf("KRAVA fd %d\n", fd)
	return nil
}
