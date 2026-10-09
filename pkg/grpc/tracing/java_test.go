// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package tracing

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/tetragon/pkg/defaults"
	"github.com/cilium/tetragon/pkg/process"
)

func javaEvent() *MsgJavaEvent {
	return &MsgJavaEvent{
		Pid:        100,
		Tid:        101,
		Ktime:      123456789,
		MethodID:   0x1234,
		ClassName:  "com.example.Foo",
		MethodName: "work",
		Descriptor: "(I)V",
		PolicyName: "java-policy",
		Message:    "foo work called",
		Tags:       []string{"tag1", "tag2"},
	}
}

func TestProcessJavaUnknownProcess(t *testing.T) {
	require.NoError(t, process.InitCache(t.Context(), nil, 16, defaults.DefaultProcessCacheGCInterval))
	t.Cleanup(process.FreeCache)

	res := javaEvent().HandleMessage()
	require.NotNil(t, res)
	ev := res.GetProcessJava()
	require.NotNil(t, ev)

	require.Equal(t, uint64(0x1234), ev.MethodId)
	require.Equal(t, "com.example.Foo", ev.ClassName)
	require.Equal(t, "work", ev.MethodName)
	require.Equal(t, "(I)V", ev.Descriptor_)
	require.Equal(t, "java-policy", ev.PolicyName)
	require.Equal(t, "foo work called", ev.Message)
	require.Equal(t, []string{"tag1", "tag2"}, ev.Tags)

	// process is not in the cache, the event carries the pid and unknown flag
	require.Equal(t, uint32(100), ev.Process.GetPid().GetValue())
	require.Equal(t, "unknown", ev.Process.Flags)
	require.Nil(t, ev.Parent)
}

func TestProcessJavaPolicyInfo(t *testing.T) {
	info := javaEvent().PolicyInfo()
	require.Equal(t, "java-policy", info.Name)
	require.Equal(t, "java:com.example.Foo.work", info.Hook)
}

func TestProcessJavaCast(t *testing.T) {
	ev := javaEvent()
	cp := ev.Cast(*ev).(*MsgJavaEvent)
	require.Equal(t, ev, cp)
	require.NotSame(t, ev, cp)
}
