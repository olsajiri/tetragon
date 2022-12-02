// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package tracing

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"reflect"
	"syscall"
	"unsafe"

	"github.com/cilium/tetragon/pkg/api/ops"
	"github.com/cilium/tetragon/pkg/api/tracingapi"
	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/grpc/tracing"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/kernels"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/observer"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/cilium/tetragon/pkg/sensors/program"
	"golang.org/x/sys/unix"
)

var (
	loader = program.Builder(
		"bpf_loader.o",
		"perf_event_mmap_output",
		"kprobe/perf_event_mmap_output",
		"loader_kprobe",
		"loader",
	)

	idsMap = program.MapBuilder("ids_map", loader)

	loaderEnabled bool

	loaderFds []int
)

type loaderSensor struct {
	name string
}

func init() {
	loader := &loaderSensor{
		name: "loader sensor",
	}
	sensors.RegisterProbeType("loader", loader)
	sensors.RegisterTracingSensorsAtInit(loader.name, loader)

	observer.RegisterEventHandlerAtInit(ops.MSG_OP_LOADER, handleLoader)
}

func GetLoaderSensor() *sensors.Sensor {
	return &sensors.Sensor{
		Name:  "__loader__",
		Progs: []*program.Program{loader},
		Maps:  []*program.Map{idsMap},
	}
}

func hasLoaderEvents() bool {
	return bpf.HasBuildId() && kernels.MinKernelVersion("5.19.0")
}

func (k *loaderSensor) SpecHandler(raw interface{}) (*sensors.Sensor, error) {
	spec, ok := raw.(*v1alpha1.TracingPolicySpec)
	if !ok {
		s, ok := reflect.Indirect(reflect.ValueOf(raw)).FieldByName("TracingPolicySpec").Interface().(v1alpha1.TracingPolicySpec)
		if !ok {
			return nil, nil
		}
		spec = &s
	}
	if spec.Loader {
		if !hasLoaderEvents() {
			return nil, fmt.Errorf("Loader event are not supported on running kernel")
		}
		loaderEnabled = true
		return GetLoaderSensor(), nil
	}
	return nil, nil
}

func createLoaderEvents() error {
	attr := &unix.PerfEventAttr{
		Type:        unix.PERF_TYPE_SOFTWARE,
		Config:      unix.PERF_COUNT_SW_BPF_OUTPUT,
		Sample_type: unix.PERF_SAMPLE_RAW,
		Bits:        unix.PerfBitMmap | unix.PerfBitMmap2 | bpf.PerfBitBuildId,
	}

	nCpus := bpf.GetNumPossibleCPUs()

	var ids []uint64

	for cpu := 0; cpu < nCpus; cpu++ {
		fd, err := unix.PerfEventOpen(attr, -1, cpu, -1, unix.PERF_FLAG_FD_CLOEXEC)
		if err != nil {
			return fmt.Errorf("can't create perf event: %w", err)
		}
		loaderFds = append(loaderFds, fd)

		var id int

		_, _, errno := syscall.Syscall(unix.SYS_IOCTL, uintptr(fd), unix.PERF_EVENT_IOC_ID, uintptr(unsafe.Pointer(&id)))
		if errno != 0 {
			return fmt.Errorf("failed to get perf event id for fd %d: %w\n", fd, err)
		}
		ids = append(ids, uint64(id))
	}

	key := uint32(0)
	err := idsMap.MapHandle.Put(key, ids[0:])
	if err != nil {
		return fmt.Errorf("failed to update ids_map: %w", err)
	}
	return nil
}

func (k *loaderSensor) LoadProbe(args sensors.LoadProbeArgs) error {
	if loaderEnabled {
		if err := createLoaderEvents(); err != nil {
			return err
		}
		return program.LoadKprobeProgram(args.BPFDir, args.MapDir, args.Load, args.Verbose)
	}
	return nil
}

func handleLoader(r *bytes.Reader) ([]observer.Event, error) {
	m := tracingapi.MsgLoader{}
	err := binary.Read(r, binary.LittleEndian, &m)
	if err != nil {
		logger.GetLogger().WithError(err).Warnf("Failed to read process call msg")
		return nil, fmt.Errorf("Failed to read process call msg")
	}

	path := m.Path[:m.PathSize-1]

	msg := &tracing.MsgProcessLoaderUnix{
		ProcessKey: m.ProcessKey,
		Ktime:      m.Common.Ktime,
		Path:       string(path),
		Buildid:    m.BuildId[:],
	}
	return []observer.Event{msg}, nil
}
