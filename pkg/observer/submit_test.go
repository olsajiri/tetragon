// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package observer

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/process"
	"github.com/cilium/tetragon/pkg/reader/notify"
)

type submitTestEvent struct{}

func (submitTestEvent) HandleMessage() *tetragon.GetEventsResponse { return nil }
func (submitTestEvent) RetryInternal(notify.Event, uint64) (*process.ProcessInternal, error) {
	return nil, nil
}
func (submitTestEvent) Retry(*process.ProcessInternal, notify.Event) error { return nil }
func (submitTestEvent) Notify() bool                                       { return true }
func (e submitTestEvent) Cast(any) notify.Message                          { return e }

func TestSubmitEvent(t *testing.T) {
	// observer is not running
	require.False(t, SubmitEvent(submitTestEvent{}))

	q := make(chan Event, 2)
	submitQueue.Store(&q)
	t.Cleanup(func() { submitQueue.Store(nil) })

	require.True(t, SubmitEvent(submitTestEvent{}))
	require.True(t, SubmitEvent(submitTestEvent{}))
	// queue is full, the event is dropped
	require.False(t, SubmitEvent(submitTestEvent{}))

	require.Len(t, q, 2)
	<-q
	require.True(t, SubmitEvent(submitTestEvent{}))
}
