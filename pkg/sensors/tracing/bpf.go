package tracing

import (
	"bytes"
	"encoding/binary"

	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/grpc/tracing"
	"github.com/cilium/tetragon/pkg/observer"
	"golang.org/x/sys/unix"
)

type perfEventBpf struct {
	Type  uint16
	Flags uint16
	Id    uint32
	Tag   [8]byte
}

func readProcessBpf(header *bpf.PerfEventHeader, rd *bytes.Reader) (*tracing.MsgProcessBpfUnix, error) {
	var bpf perfEventBpf

	if err := binary.Read(rd, binary.LittleEndian, &bpf); err != nil {
		return nil, err
	}

	return &tracing.MsgProcessBpfUnix{
		Type: bpf.Type,
		Id:   bpf.Id,
		Tag:  bpf.Tag,
	}, nil
}

func handleBpf(header *bpf.PerfEventHeader, rd *bytes.Reader, cpu int) ([]observer.Event, error) {
	msg, err := readProcessBpf(header, rd)
	if err != nil {
		return nil, err
	}
	return []observer.Event{msg}, nil
}

func init() {
	observer.RegisterPerfEventHandler(unix.PERF_RECORD_BPF_EVENT, handleBpf)
}
