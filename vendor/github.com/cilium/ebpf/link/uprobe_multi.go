package link

import (
	"errors"
	"fmt"
	"os"
	"unsafe"

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

func (ex *Executable) UprobeMulti(symbols []string, cookies []uint64, prog *ebpf.Program) (Link, error) {
	opts := UprobeMultiOptions{}

	for idx, symbol := range symbols {
		offset, err := ex.address(symbol, &UprobeOptions{})
		if err != nil {
			return nil, err
		}

		opts.Paths = append(opts.Paths, ex.path)
		opts.Offsets = append(opts.Offsets, uintptr(offset))
		opts.Cookies = append(opts.Cookies, cookies[idx])
	}

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
	return uprobeMulti(prog, opts, unix.BPF_F_KPROBE_MULTI_RETURN)
}

func uprobeMulti(prog *ebpf.Program, opts UprobeMultiOptions, flags uint32) (Link, error) {
	if prog == nil {
		return nil, errors.New("cannot attach a nil program")
	}

	paths := uint32(len(opts.Paths))
	offsets := uint32(len(opts.Offsets))
	refctrs := uint32(len(opts.RefCtrOffsets))
	cookies := uint32(len(opts.Cookies))

	if paths == 0 {
		return nil, fmt.Errorf("Paths is required: %w", errInvalidInput)
	}
	if offsets == 0 && refctrs == 0 {
		return nil, fmt.Errorf("one of Symbols or Addresses is required: %w", errInvalidInput)
	}
	if cookies > 0 && cookies != offsets && cookies != paths {
		return nil, fmt.Errorf("Cookies must be exactly Offsets or RefCtrOffsets in length: %w", errInvalidInput)
	}

	attr := &sys.LinkCreateUprobeMultiAttr{
		ProgFd:           uint32(prog.FD()),
		AttachType:       sys.BPF_TRACE_KPROBE_MULTI,
		UprobeMultiFlags: flags,
	}

	attr.Count = paths
	attr.Paths = sys.NewStringSlicePointer(opts.Paths)
	attr.Offsets = sys.NewPointer(unsafe.Pointer(&opts.Offsets[0]))
	if refctrs > 0 {
		attr.RefCtrOffsets = sys.NewPointer(unsafe.Pointer(&opts.RefCtrOffsets[0]))
	}
	if cookies > 0 {
		attr.Cookies = sys.NewPointer(unsafe.Pointer(&opts.Cookies[0]))
	}

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
