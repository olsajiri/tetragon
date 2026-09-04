// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build linux

package javaipc

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cilium/tetragon/pkg/api/javaapi"
	"github.com/cilium/tetragon/pkg/api/ops"
	"github.com/cilium/tetragon/pkg/api/processapi"
)

func TestRingDrainAndValidation(t *testing.T) {
	path := t.TempDir() + "/ring"
	slots := uint64(2)
	data := make([]byte, ringHeaderSize+int(slots)*RecordSize)
	binary.LittleEndian.PutUint32(data[0:4], ringMagic)
	binary.LittleEndian.PutUint32(data[4:8], ringVersion)
	binary.LittleEndian.PutUint32(data[8:12], RecordSize)
	binary.LittleEndian.PutUint64(data[16:24], slots)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	ring, err := openRing(path)
	if err != nil {
		t.Fatal(err)
	}
	defer ring.close()
	copy(ring.data[ringHeaderSize:ringHeaderSize+RecordSize], []byte{29})
	atomic.StoreUint64(ring.producer, 1)
	var got []byte
	if n := ring.drain(func(record []byte) { got = record }); n != 1 {
		t.Fatalf("drained %d records, want 1", n)
	}
	if len(got) != RecordSize || got[0] != 29 {
		t.Fatalf("unexpected record: len=%d opcode=%d", len(got), got[0])
	}
	if consumer := atomic.LoadUint64(ring.consumer); consumer != 1 {
		t.Fatalf("consumer index %d, want 1", consumer)
	}
}

func TestServeListenerConsumesRegisteredRing(t *testing.T) {
	socketPath := t.TempDir() + "/java.sock"
	ringPath := t.TempDir() + "/java.ring"
	slots := uint64(2)
	ringData := make([]byte, ringHeaderSize+int(slots)*RecordSize)
	binary.LittleEndian.PutUint32(ringData[0:4], ringMagic)
	binary.LittleEndian.PutUint32(ringData[4:8], ringVersion)
	binary.LittleEndian.PutUint32(ringData[8:12], RecordSize)
	binary.LittleEndian.PutUint64(ringData[16:24], slots)
	if err := os.WriteFile(ringPath, ringData, 0600); err != nil {
		t.Fatal(err)
	}

	listener, err := Listen(socketPath)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	received := make(chan []byte, 1)
	done := make(chan error, 1)
	go func() { done <- ServeListener(ctx, socketPath, listener, func(data []byte) { received <- data }) }()

	var conn net.Conn
	for i := 0; i < 50; i++ {
		conn, err = net.DialTimeout("unixpacket", socketPath, time.Second)
		if err == nil {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	registration := make([]byte, registrationHeaderSize+len(ringPath))
	binary.LittleEndian.PutUint32(registration[0:4], registrationMagic)
	binary.LittleEndian.PutUint32(registration[4:8], registrationVersion)
	binary.LittleEndian.PutUint32(registration[8:12], uint32(len(ringPath)))
	copy(registration[12:], ringPath)
	if _, err := conn.Write(registration); err != nil {
		t.Fatal(err)
	}
	ack := make([]byte, 8)
	if _, err := io.ReadFull(conn, ack); err != nil {
		t.Fatal(err)
	}
	if binary.LittleEndian.Uint32(ack[0:4]) != registrationAckMagic {
		t.Fatalf("bad registration ack: %#x", ack)
	}

	ring, err := openRing(ringPath)
	if err != nil {
		t.Fatal(err)
	}
	defer ring.close()
	msg := javaapi.MsgJava{Common: processapi.MsgCommon{Op: ops.MSG_OP_JAVA, Size: javaapi.MsgJavaSize, Ktime: 1}, ProcessKey: processapi.MsgExecveKey{Pid: 1}}
	copy(ring.data[ringHeaderSize:ringHeaderSize+RecordSize], encodeJavaRecord(t, &msg))
	atomic.StoreUint64(ring.producer, 1)
	select {
	case record := <-received:
		if got := binary.LittleEndian.Uint32(record[16:20]); got != uint32(os.Getpid()) {
			t.Fatalf("record PID %d, want peer PID %d", got, os.Getpid())
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for ring record")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("listener did not stop")
	}
}

func encodeJavaRecord(t *testing.T, msg *javaapi.MsgJava) []byte {
	t.Helper()
	data := make([]byte, RecordSize)
	data[0] = byte(msg.Common.Op)
	binary.LittleEndian.PutUint32(data[4:8], msg.Common.Size)
	binary.LittleEndian.PutUint64(data[8:16], msg.Common.Ktime)
	binary.LittleEndian.PutUint32(data[16:20], msg.ProcessKey.Pid)
	binary.LittleEndian.PutUint64(data[24:32], msg.ProcessKey.Ktime)
	binary.LittleEndian.PutUint64(data[32:40], msg.MethodID)
	binary.LittleEndian.PutUint32(data[40:44], msg.TID)
	return data
}

func TestParseRegistration(t *testing.T) {
	data := make([]byte, registrationHeaderSize+4)
	binary.LittleEndian.PutUint32(data[0:4], registrationMagic)
	binary.LittleEndian.PutUint32(data[4:8], registrationVersion)
	binary.LittleEndian.PutUint32(data[8:12], 4)
	copy(data[12:], "/tmp")
	path, err := parseRegistration(data)
	if err != nil || path != "/tmp" {
		t.Fatalf("parseRegistration() = %q, %v", path, err)
	}
	data[8]++
	if _, err := parseRegistration(data); err == nil {
		t.Fatal("accepted registration with an invalid path length")
	}
}
