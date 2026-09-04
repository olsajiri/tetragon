// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build linux

package javaipc

import (
	"encoding/binary"
	"fmt"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	ringMagic              = uint32(0x4a52534a) // "JRSJ" in little endian
	ringVersion            = uint32(1)
	ringHeaderSize         = 256
	ringProducerOff        = 64
	ringConsumerOff        = 128
	ringNotifyOff          = 192
	registrationMagic      = uint32(0x4a524547) // "JREG"
	registrationVersion    = uint32(1)
	registrationHeaderSize = 12
	registrationAckMagic   = uint32(0x4a524143) // "JRAC"
	registrationOK         = uint32(0)
	maxRingPath            = 4096
)

const (
	// These are the public ABI values used by the Java FFM producer.
	RecordSize      = 432
	DefaultRingSize = 4 << 20
)

type sharedRing struct {
	data     []byte
	producer *uint64
	consumer *uint64
	notify   *uint32
	slots    uint64
	mask     uint64
}

func openRing(path string) (*sharedRing, error) {
	clean := filepath.Clean(path)
	if clean != path || !filepath.IsAbs(path) || strings.Contains(path, "\x00") {
		return nil, fmt.Errorf("invalid Java ring path %q", path)
	}
	fd, err := unix.Open(path, unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("open Java ring %q: %w", path, err)
	}
	defer unix.Close(fd)
	var st unix.Stat_t
	err = unix.Fstat(fd, &st)
	if err != nil {
		return nil, fmt.Errorf("stat Java ring %q: %w", path, err)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Size < ringHeaderSize {
		return nil, fmt.Errorf("invalid Java ring file %q", path)
	}
	mapped, err := unix.Mmap(fd, 0, int(st.Size), unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if err != nil {
		return nil, fmt.Errorf("map Java ring %q: %w", path, err)
	}
	bad := func(err error) (*sharedRing, error) {
		_ = unix.Munmap(mapped)
		return nil, err
	}
	if binary.LittleEndian.Uint32(mapped[0:4]) != ringMagic ||
		binary.LittleEndian.Uint32(mapped[4:8]) != ringVersion ||
		binary.LittleEndian.Uint32(mapped[8:12]) != RecordSize {
		return bad(fmt.Errorf("invalid Java ring header in %q", path))
	}
	slots := binary.LittleEndian.Uint64(mapped[16:24])
	if slots < 2 || slots&(slots-1) != 0 ||
		slots > (uint64(st.Size)-uint64(ringHeaderSize))/RecordSize {
		return bad(fmt.Errorf("invalid Java ring slot count %d", slots))
	}
	return &sharedRing{
		data:     mapped,
		producer: (*uint64)(unsafe.Pointer(&mapped[ringProducerOff])),
		consumer: (*uint64)(unsafe.Pointer(&mapped[ringConsumerOff])),
		notify:   (*uint32)(unsafe.Pointer(&mapped[ringNotifyOff])),
		slots:    slots,
		mask:     slots - 1,
	}, nil
}

func (r *sharedRing) close() error {
	if r == nil || r.data == nil {
		return nil
	}
	err := unix.Munmap(r.data)
	r.data = nil
	return err
}

func (r *sharedRing) drain(callback func([]byte)) int {
	count := 0
	for {
		consumer := atomic.LoadUint64(r.consumer)
		producer := atomic.LoadUint64(r.producer)
		if consumer == producer {
			return count
		}
		offset := uint64(ringHeaderSize) + (consumer&r.mask)*RecordSize
		// The callback must consume the record synchronously. The observer
		// copies it into its queue before this release allows the producer to
		// reuse the slot, avoiding an extra allocation and copy here.
		callback(r.data[offset : offset+RecordSize])
		atomic.StoreUint64(r.consumer, consumer+1)
		count++
	}
}

func waitForRing(r *sharedRing, ctxDone <-chan struct{}) bool {
	for {
		producer := atomic.LoadUint64(r.producer)
		consumer := atomic.LoadUint64(r.consumer)
		if producer != consumer {
			return true
		}
		seq := atomic.LoadUint32(r.notify)
		if atomic.LoadUint64(r.producer) != consumer {
			return true
		}
		// A bounded wait makes cancellation and control-connection loss
		// observable even if the producer exits without waking the futex.
		timeout := unix.NsecToTimespec(int64(100 * time.Millisecond))
		_, _, errno := unix.Syscall6(unix.SYS_FUTEX, uintptr(unsafe.Pointer(r.notify)), 0, uintptr(seq), uintptr(unsafe.Pointer(&timeout)), 0, 0)
		if errno != 0 && errno != unix.EAGAIN && errno != unix.EINTR && errno != unix.ETIMEDOUT {
			return false
		}
		select {
		case <-ctxDone:
			return false
		default:
		}
	}
}

func parseRegistration(data []byte) (string, error) {
	if len(data) < registrationHeaderSize || binary.LittleEndian.Uint32(data[0:4]) != registrationMagic ||
		binary.LittleEndian.Uint32(data[4:8]) != registrationVersion {
		return "", fmt.Errorf("invalid Java ring registration")
	}
	pathLen := int(binary.LittleEndian.Uint32(data[8:12]))
	if pathLen <= 0 || pathLen > maxRingPath || registrationHeaderSize+pathLen != len(data) {
		return "", fmt.Errorf("invalid Java ring registration path length")
	}
	return string(data[registrationHeaderSize:]), nil
}

func registrationAck() []byte {
	ack := make([]byte, 8)
	binary.LittleEndian.PutUint32(ack[0:4], registrationAckMagic)
	binary.LittleEndian.PutUint32(ack[4:8], registrationOK)
	return ack
}
