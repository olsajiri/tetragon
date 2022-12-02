// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package tracing

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/cilium/tetragon/pkg/api/ops"
	"github.com/cilium/tetragon/pkg/api/tracingapi"
	"github.com/cilium/tetragon/pkg/grpc/tracing"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/observer"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/cilium/tetragon/pkg/sensors/program"
)

var (
	loader = program.Builder(
		"bpf_loader.o",
		"perf_event_mmap_output",
		"kprobe/perf_event_mmap_output",
		"loader_kprobe",
		"kprobe",
	)
)

func init() {
	observer.RegisterEventHandlerAtInit(ops.MSG_OP_LOADER, handleLoader)
}

func GetLoaderSensor() *sensors.Sensor {
	return &sensors.Sensor{
		Name:  "__loader__",
		Progs: []*program.Program{loader},
		Maps:  nil,
	}
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
