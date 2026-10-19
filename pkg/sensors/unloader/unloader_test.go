// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package unloader

import (
	"errors"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

var errUnpin = errors.New("unpin failed")

type testLink struct {
	link.Link
	unpinErr error
	closeErr error
	closed   bool
}

func (l *testLink) Update(*ebpf.Program) error { return nil }
func (l *testLink) Pin(string) error           { return nil }
func (l *testLink) Unpin() error               { return l.unpinErr }
func (l *testLink) Close() error {
	l.closed = true
	return l.closeErr
}
func (l *testLink) Detach() error             { return nil }
func (l *testLink) Info() (*link.Info, error) { return nil, nil }
func (l *testLink) isLink()                   {}

func TestLinkUnloaderReportsUnpinErrorAndCloses(t *testing.T) {
	lnk := &testLink{unpinErr: errUnpin}
	err := (LinkUnloader{Link: lnk}).Unload(true)

	if !errors.Is(err, errUnpin) {
		t.Fatalf("expected unpin error, got %v", err)
	}
	if !lnk.closed {
		t.Fatal("link was not closed after unpin failed")
	}
}

func TestRelinkUnloaderReportsUnpinErrorAndCloses(t *testing.T) {
	lnk := &testLink{unpinErr: errUnpin}
	unloader := &RelinkUnloader{
		UnloadProg: func(bool) error { return nil },
		IsLinked:   true,
		Link:       lnk,
	}
	err := unloader.Unload(true)

	if !errors.Is(err, errUnpin) {
		t.Fatalf("expected unpin error, got %v", err)
	}
	if !lnk.closed {
		t.Fatal("link was not closed after unpin failed")
	}
	if unloader.IsLinked {
		t.Fatal("unloader still reports link as attached after close")
	}
}

func TestMultiRelinkUnloaderReportsUnpinErrorsAndClosesAll(t *testing.T) {
	first := &testLink{unpinErr: errUnpin}
	second := &testLink{}
	unloader := &MultiRelinkUnloader{
		UnloadProg: func(bool) error { return nil },
		IsLinked:   true,
		Links:      []link.Link{first, second},
	}
	err := unloader.Unload(true)

	if !errors.Is(err, errUnpin) {
		t.Fatalf("expected unpin error, got %v", err)
	}
	if !first.closed || !second.closed {
		t.Fatalf("expected all links to close, got first=%v second=%v", first.closed, second.closed)
	}
}
