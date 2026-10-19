// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build linux

package java

import (
	"testing"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	api "github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/policyfilter"
	"github.com/cilium/tetragon/pkg/sensors"
)

func TestPolicyHandlerRejectsPatches(t *testing.T) {
	policy := &api.TracingPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "patch-policy"},
		Spec: api.TracingPolicySpec{
			Java: &api.JavaSpec{
				Patches: []api.JavaPatch{{
					Class:     "com.example.Foo",
					ClassFile: []byte{0xca, 0xfe, 0xba, 0xbe},
				}},
			},
		},
	}
	_, err := (policyHandler{}).PolicyHandler(policy, policyfilter.NoFilterID)
	require.ErrorContains(t, err, "patches are not supported")
}

func TestContainsArgs(t *testing.T) {
	cmdline := []byte("java\x00-orders-service.jar\x00--port=8080\x00")
	require.True(t, containsArgs(cmdline, []string{"orders", "port=8080"}))
	require.False(t, containsArgs(cmdline, []string{"orders", "missing"}))
	require.True(t, containsArgs(cmdline, nil))
}

func TestJavaSensorUnloadUnloadsEmbeddedSensor(t *testing.T) {
	base := &sensors.Sensor{
		Name:            "java-test",
		BpfDir:          t.TempDir(),
		Loaded:          true,
		NoHooksAttached: true,
	}
	sensor := &javaSensor{
		Sensor: base,
		stop:   make(chan struct{}),
		done:   make(chan struct{}),
	}
	close(sensor.done)

	err := sensor.unload(func(uint32) error {
		require.True(t, base.Loaded, "embedded sensor must stay loaded until its Unload runs")
		return nil
	})
	require.NoError(t, err)
	require.False(t, base.Loaded, "embedded sensor Unload should clear Loaded")
}
