// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build linux

// Package javaipc implements the Java control socket and shared-memory ring
// consumer. The socket authenticates a JVM and keeps its ring alive; event
// records themselves never cross the socket.
package javaipc

import (
	"context"
	"fmt"
	"net"
	"os"
	"sync"

	"github.com/cilium/tetragon/pkg/api/javaapi"
	"github.com/cilium/tetragon/pkg/unixlisten"
	"golang.org/x/sys/unix"
)

func Listen(path string) (net.Listener, error) {
	if path == "" {
		return nil, nil
	}
	listener, err := unixlisten.ListenWithRenameNetwork("unixpacket", path, 0660)
	if err != nil {
		return nil, fmt.Errorf("listen for Java IPC on %s: %w", path, err)
	}
	return listener, nil
}

// Serve is a convenience wrapper that publishes and serves the Java control
// socket until ctx is cancelled.
func Serve(ctx context.Context, path string, callback func([]byte)) error {
	listener, err := Listen(path)
	if err != nil {
		return err
	}
	return ServeListener(ctx, path, listener, callback)
}

func prepareRingRecord(data []byte, peerPID uint32) error {
	return javaapi.PreparePacket(data, peerPID)
}

// ServeListener accepts multiple JVMs concurrently. Each authenticated
// connection registers exactly one ring and remains open as a liveness
// channel for that ring.
func ServeListener(ctx context.Context, path string, listener net.Listener, callback func([]byte)) error {
	if listener == nil {
		return nil
	}
	defer func() {
		_ = listener.Close()
		if path != "" {
			_ = os.Remove(path)
		}
	}()

	var connections sync.Map
	var wg sync.WaitGroup
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		select {
		case <-ctx.Done():
			_ = listener.Close()
			connections.Range(func(key, _ any) bool {
				_ = key.(net.Conn).Close()
				return true
			})
		case <-stop:
		}
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				wg.Wait()
				return nil
			}
			return fmt.Errorf("accept Java IPC connection: %w", err)
		}
		connections.Store(conn, struct{}{})
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer connections.Delete(conn)
			_ = serveConnection(ctx, conn, callback)
			_ = conn.Close()
		}()
	}
}

func serveConnection(ctx context.Context, conn net.Conn, callback func([]byte)) error {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return fmt.Errorf("Java IPC connection is not a Unix connection")
	}
	peerPID, err := unixPeerPID(uc)
	if err != nil {
		return err
	}

	registration := make([]byte, maxRingPath+registrationHeaderSize)
	n, _, flags, _, err := uc.ReadMsgUnix(registration, nil)
	if err != nil {
		return err
	}
	if flags&unix.MSG_TRUNC != 0 {
		return fmt.Errorf("truncated Java ring registration")
	}
	ringPath, err := parseRegistration(registration[:n])
	if err != nil {
		return err
	}
	ring, err := openRing(ringPath)
	if err != nil {
		return err
	}
	defer ring.close()
	if _, _, err := uc.WriteMsgUnix(registrationAck(), nil, nil); err != nil {
		return fmt.Errorf("acknowledge Java ring: %w", err)
	}

	controlClosed := make(chan struct{})
	go func() {
		_, _ = conn.Read(make([]byte, 1))
		close(controlClosed)
	}()
	waitDone := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.Close()
		case <-controlClosed:
		case <-waitDone:
		}
	}()
	defer close(waitDone)

	for {
		if ring.drain(func(data []byte) {
			if err := prepareRingRecord(data, peerPID); err == nil {
				callback(data)
			}
		}) != 0 {
			continue
		}
		select {
		case <-ctx.Done():
			return nil
		case <-controlClosed:
			return nil
		default:
		}
		if !waitForRing(ring, controlClosed) {
			return nil
		}
	}
}

func unixPeerPID(conn *net.UnixConn) (uint32, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0, err
	}
	var cred *unix.Ucred
	var controlErr error
	if err := raw.Control(func(fd uintptr) {
		cred, controlErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return 0, err
	}
	if controlErr != nil {
		return 0, controlErr
	}
	if cred == nil || cred.Pid <= 0 {
		return 0, fmt.Errorf("Java IPC peer has invalid PID")
	}
	return uint32(cred.Pid), nil
}
