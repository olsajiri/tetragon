package base

import (
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/tetragon/pkg/logger"
	"golang.org/x/sys/unix"
)

type KprobeStatsValue struct {
	Id      uint64
	Nmissed uint64
}

func GetKprobeMissed(lnk link.Link) uint64 {
	pe, ok := lnk.(link.PerfEvent)
	if !ok {
		return 0
	}

	file, err := pe.PerfEvent()
	if err != nil {
		return 0
	}
	defer file.Close()

	fd := int(file.Fd())

	id, err := unix.IoctlGetInt(fd, unix.PERF_EVENT_IOC_ID)
	if err != nil {
		logger.GetLogger().WithError(err).Warn("Failed to get kprobe event ID")
		return 0
	}

	v := &KprobeStatsValue{
		Id:      uint64(id),
		Nmissed: 0,
	}
	KprobeStatsMap.MapHandle.Put(uint32(0), v)

	var buf []byte
	syscall.Read(fd, buf)

	KprobeStatsMap.MapHandle.Lookup(int32(0), v)
	return v.Nmissed
}
