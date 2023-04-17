package link

import (
	"errors"
	"fmt"
	"os"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/internal/sys"
	"github.com/cilium/ebpf/internal/unix"
)

type UprobeMultiOptions struct {
	Paths         []string
	Offsets       []uintptr
	RefCtrOffsets []uintptr
	Cookies       []uint64
}

func (ex *Executable) UprobeMulti(prog *ebpf.Program, opts UprobeMultiOptions) (Link, error) {
	return uprobeMulti(prog, opts, 0)
}

// KretprobeMulti attaches the given eBPF program to the return point of a given
// set of kernel symbols.
//
// The difference with Kretprobe() is that multi-kprobe accomplishes this in a
// single system call, making it significantly faster than attaching many
// probes one at a time.
//
// Requires at least Linux 5.18.
func (ex *Executable) UretprobeMulti(prog *ebpf.Program, opts UprobeMultiOptions) (Link, error) {
	return uprobeMulti(prog, opts, unix.BPF_F_UPROBE_MULTI_RETURN)
}

func uprobeMulti(prog *ebpf.Program, opts UprobeMultiOptions, flags uint32) (Link, error) {
	if prog == nil {
		return nil, errors.New("cannot attach a nil program")
	}

	paths := uint32(len(opts.Paths))
	offsets := uint32(len(opts.Offsets))
	refctrs := uint32(len(opts.RefCtrOffsets))
	cookies := uint32(len(opts.Cookies))

	if err := haveBPFLinkUprobeMulti(); err != nil {
		return nil, err
	}

	attr := &sys.LinkCreateUprobeMultiAttr{
		ProgFd:           uint32(prog.FD()),
		AttachType:       sys.BPF_TRACE_KPROBE_MULTI,
		UprobeMultiFlags: flags,
	}

	attr.Count = paths
	attr.Paths = sys.NewStringSlicePointer(opts.Paths)
	attr.Offsets = sys.NewStringSlicePointer(opts.Offsets)
	attr.RefCtrOffsets = sys.NewStringSlicePointer(opts.RefCtrOffsets)
	attr.Cookies = sys.NewStringSlicePointer(opts.Cookies)

	fd, err := sys.LinkCreateUprobeMulti(attr)
	if errors.Is(err, unix.ESRCH) {
		return nil, fmt.Errorf("couldn't find one or more symbols: %w", os.ErrNotExist)
	}
	if errors.Is(err, unix.EINVAL) {
		return nil, fmt.Errorf("%w (missing kernel symbol or prog's AttachType not AttachTraceUprobeMulti?)", err)
	}
	if err != nil {
		return nil, err
	}

	return &uprobeMultiLink{RawLink{fd, ""}}, nil
}

type uprobeMultiLink struct {
	RawLink
}

var _ Link = (*uprobeMultiLink)(nil)

func (kml *uprobeMultiLink) Update(prog *ebpf.Program) error {
	return fmt.Errorf("update kprobe_multi: %w", ErrNotSupported)
}

func (kml *uprobeMultiLink) Pin(string) error {
	return fmt.Errorf("pin kprobe_multi: %w", ErrNotSupported)
}

func (kml *uprobeMultiLink) Unpin() error {
	return fmt.Errorf("unpin kprobe_multi: %w", ErrNotSupported)
}
