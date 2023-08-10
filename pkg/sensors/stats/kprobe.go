package stats

import (
	"fmt"
	"path/filepath"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/cilium/tetragon/pkg/sensors/program"
	"golang.org/x/sys/unix"
)

type Kprobe struct {
	Function string
}

type KprobeStatsValue struct {
	Id      uint64
	Nmissed uint64
	Hit     uint64
}

var (
	kprobeStats = program.Builder(
		"bpf_kprobe_stats.o",
		"perf_read",
		"kprobe/perf_read",
		"kprobe_stats",
		"kprobe",
	)

	sensor = &sensors.Sensor{
		Name:  "__kprobe_stats__",
		Progs: []*program.Program{kprobeStats},
		Maps:  []*program.Map{kprobeStatsMap},
	}

	kprobeStatsMap = program.MapBuilder("kprobe_stats_map", kprobeStats)
)

func getSensor() *sensors.Sensor {
	return &sensors.Sensor{
		Name:  "__kprobe_stats__",
		Progs: []*program.Program{kprobeStats},
		Maps:  []*program.Map{kprobeStatsMap},
	}
}

func loadSensor(bpfDir, mapDir, ciliumDir string) error {
	if kprobeStats.LoadState.IsLoaded() {
		return nil
	}
	err := sensor.Load(bpfDir, mapDir, ciliumDir)
	return err
}

func (s Kprobe) Cleanup() {
	if kprobeStats.LoadState.IsLoaded() {
		sensor.Unload()
	}
}

func (s Kprobe) Process(link link.Link) error {
	info, err := link.Info()
	if err != nil {
		return fmt.Errorf("failed to get link info: %w", err)
	}

	fd := info.PerfFd()

	id, err := unix.IoctlGetInt(fd, unix.PERF_EVENT_IOC_ID)
	if err != nil {
		logger.GetLogger().WithError(err).Warn("Failed to get kprobe event ID")
	}

	err = loadSensor(option.Config.BpfDir, option.Config.MapDir, option.Config.CiliumDir)
	if err != nil {
		logger.GetLogger().WithError(err).Warn("Failed to load kprobe stats program")
		return err
	}

	m, err := ebpf.LoadPinnedMap(filepath.Join(option.Config.MapDir, kprobeStatsMap.Name), nil)
	if err != nil {
		logger.GetLogger().WithError(err).Warn("Failed to open kprobe_stats_map.")
		return err
	}

	v := &KprobeStatsValue{
		Id:      uint64(id),
		Nmissed: 0,
		Hit:     0,
	}
	m.Put(uint32(0), v)

	var buf []byte
	syscall.Read(fd, buf)

	err = m.Lookup(int32(0), v)

	if err == nil {
		fmt.Printf("KRAVA id %d hit %d missed %d\n", id, v.Hit, v.Nmissed)
	} else {
		fmt.Printf("ERROR %v\n", err)
	}

	return nil
}
