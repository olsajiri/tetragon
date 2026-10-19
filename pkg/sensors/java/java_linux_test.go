// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build linux

package java

import (
	"os"
	"path/filepath"
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

func TestExecutableOnlySensorSkipsAgentLifecycle(t *testing.T) {
	base := &sensors.Sensor{
		Name:            "java-env-only-test",
		BpfDir:          t.TempDir(),
		NoHooksAttached: true,
	}
	sensor := &javaSensor{
		Sensor:       base,
		agentEnabled: false,
	}

	serverBefore := agentServer
	require.NoError(t, sensor.Load(base.BpfDir))
	require.True(t, sensor.Loaded)
	require.Same(t, serverBefore, agentServer, "environment-only policy must not initialize the JVMTI server")

	removed := false
	err := sensor.unload(func(uint32) error {
		removed = true
		return nil
	})
	require.NoError(t, err)
	require.False(t, removed, "environment-only policy must not register or remove an agent policy")
	require.False(t, sensor.Loaded)
}

func TestResolveNativeAgentPath(t *testing.T) {
	writeAgent := func(path string) {
		t.Helper()
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
		require.NoError(t, os.WriteFile(path, []byte("agent"), 0o644))
	}

	t.Run("configured path takes precedence", func(t *testing.T) {
		workingDir := t.TempDir()
		configuredPath := filepath.Join(workingDir, "custom-agent.so")
		writeAgent(configuredPath)
		writeAgent(filepath.Join(workingDir, sourceNativeAgentPath))

		path, err := resolveNativeAgentPathFrom(configuredPath, workingDir, filepath.Join(workingDir, "installed.so"))
		require.NoError(t, err)
		require.Equal(t, configuredPath, path)
	})

	t.Run("missing configured path fails", func(t *testing.T) {
		workingDir := t.TempDir()
		writeAgent(filepath.Join(workingDir, sourceNativeAgentPath))

		_, err := resolveNativeAgentPathFrom(filepath.Join(workingDir, "missing.so"), workingDir, filepath.Join(workingDir, "installed.so"))
		require.ErrorContains(t, err, "configured JVMTI agent")
	})

	t.Run("source tree fallback", func(t *testing.T) {
		workingDir := t.TempDir()
		sourcePath := filepath.Join(workingDir, sourceNativeAgentPath)
		writeAgent(sourcePath)

		path, err := resolveNativeAgentPathFrom("", workingDir, filepath.Join(workingDir, "installed.so"))
		require.NoError(t, err)
		require.Equal(t, sourcePath, path)
	})

	t.Run("installed path fallback", func(t *testing.T) {
		workingDir := t.TempDir()
		installedPath := filepath.Join(workingDir, "installed.so")
		writeAgent(installedPath)

		path, err := resolveNativeAgentPathFrom("", workingDir, installedPath)
		require.NoError(t, err)
		require.Equal(t, installedPath, path)
	})

	t.Run("missing fallback paths fail", func(t *testing.T) {
		workingDir := t.TempDir()
		installedPath := filepath.Join(workingDir, "installed.so")

		_, err := resolveNativeAgentPathFrom("", workingDir, installedPath)
		require.ErrorContains(t, err, "JVMTI agent unavailable")
	})
}
