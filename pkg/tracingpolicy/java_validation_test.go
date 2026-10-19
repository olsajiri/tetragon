// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package tracingpolicy

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
)

// base64 of the first 8 bytes of a class file (magic + version 65)
const javaClassFile = "yv66vgAAAEE="

func javaPolicy(java string) string {
	return `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "java"
spec:
  java:
` + java
}

func TestJavaValidationFull(t *testing.T) {
	tp, err := FromYAML(javaPolicy(`
    targets:
      executables:
      - /opt/java/openjdk/bin/java
      processArgsContains:
      - orders-service.jar
    hooks:
    - class: com.example.orders.RequestHandler
      methods:
      - name: handle
      - name: validate
        descriptor: "(Ljava/lang/String;)Z"
      message: "orders request handled"
      tags: ["orders", "ingress"]
    - classPrefix: com.example.billing.
      methods:
      - name: charge
    patches:
    - class: com.example.orders.RequestHandler
      classFile: ` + javaClassFile + `
`))
	require.NoError(t, err)

	java := tp.TpSpec().Java
	require.NotNil(t, java)

	require.NotNil(t, java.Targets)
	require.Equal(t, []string{"/opt/java/openjdk/bin/java"}, java.Targets.Executables)
	require.Equal(t, []string{"orders-service.jar"}, java.Targets.ProcessArgsContains)

	require.Len(t, java.Hooks, 2)
	require.Equal(t, "com.example.orders.RequestHandler", java.Hooks[0].Class)
	require.Empty(t, java.Hooks[0].ClassPrefix)
	require.Equal(t, []v1alpha1.JavaMethod{
		{Name: "handle"},
		{Name: "validate", Descriptor: "(Ljava/lang/String;)Z"},
	}, java.Hooks[0].Methods)
	require.Equal(t, "orders request handled", java.Hooks[0].Message)
	require.Equal(t, []string{"orders", "ingress"}, java.Hooks[0].Tags)
	require.Equal(t, "com.example.billing.", java.Hooks[1].ClassPrefix)
	require.Empty(t, java.Hooks[1].Class)

	require.Len(t, java.Patches, 1)
	require.Equal(t, "com.example.orders.RequestHandler", java.Patches[0].Class)
	require.Equal(t, []byte{0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 0x41}, java.Patches[0].ClassFile)
}

func TestJavaValidationMinimal(t *testing.T) {
	// hooks only, no targets
	tp, err := FromYAML(javaPolicy(`
    hooks:
    - classPrefix: com.example.
`))
	require.NoError(t, err)
	require.Nil(t, tp.TpSpec().Java.Targets)
	require.Len(t, tp.TpSpec().Java.Hooks, 1)

	// executable target only: prepare JVM options without method hooks
	tp, err = FromYAML(javaPolicy(`
    targets:
      executables:
      - /opt/java/openjdk/bin/java
`))
	require.NoError(t, err)
	require.Empty(t, tp.TpSpec().Java.Hooks)
	require.Equal(t, []string{"/opt/java/openjdk/bin/java"}, tp.TpSpec().Java.Targets.Executables)

	// patches only
	tp, err = FromYAML(javaPolicy(`
    patches:
    - class: com.example.Handler
      classFile: ` + javaClassFile + `
`))
	require.NoError(t, err)
	require.Len(t, tp.TpSpec().Java.Patches, 1)
}

func TestJavaValidationHookClass(t *testing.T) {
	// both class and classPrefix
	_, err := FromYAML(javaPolicy(`
    hooks:
    - class: com.example.Handler
      classPrefix: com.example.
`))
	require.Error(t, err)
	require.Contains(t, err.Error(), "hook needs exactly one of class or classPrefix")

	// neither class nor classPrefix
	_, err = FromYAML(javaPolicy(`
    hooks:
    - methods:
      - name: handle
`))
	require.Error(t, err)
	require.Contains(t, err.Error(), "hook needs exactly one of class or classPrefix")
}

func TestJavaValidationEmpty(t *testing.T) {
	_, err := FromYAML(javaPolicy(`    {}
`))
	require.Error(t, err)
	require.Contains(t, err.Error(), "java needs at least one hook, patch, or executable target")

	_, err = FromYAML(javaPolicy(`
    hooks: []
`))
	require.Error(t, err)
	require.Contains(t, err.Error(), "java needs at least one hook, patch, or executable target")

	_, err = FromYAML(javaPolicy(`
    targets:
      processArgsContains:
      - orders-service.jar
`))
	require.Error(t, err)
	require.Contains(t, err.Error(), "java needs at least one hook, patch, or executable target")
}

// requireErrorOneOf checks err contains one of the messages, structural schema
// errors are reported differently by the k8s and nok8s (jsonschema) validators.
func requireErrorOneOf(t *testing.T, err error, msgs ...string) {
	t.Helper()
	require.Error(t, err)
	for _, msg := range msgs {
		if strings.Contains(err.Error(), msg) {
			return
		}
	}
	require.Failf(t, "unexpected error", "error %q does not contain any of %q", err.Error(), msgs)
}

func TestJavaValidationLimits(t *testing.T) {
	// method without name
	_, err := FromYAML(javaPolicy(`
    hooks:
    - class: com.example.Handler
      methods:
      - descriptor: "()V"
`))
	requireErrorOneOf(t, err,
		"spec.java.hooks[0].methods[0].name in body is required",
		"at '/spec/java/hooks/0/methods/0': missing property 'name'")

	// message longer than 256 characters
	_, err = FromYAML(javaPolicy(`
    hooks:
    - class: com.example.Handler
      message: "` + strings.Repeat("a", 257) + `"
`))
	requireErrorOneOf(t, err,
		"spec.java.hooks[0].message in body should be at most 256 chars long",
		"at '/spec/java/hooks/0/message': maxLength: got 257, want 256")

	// patch without classFile
	_, err = FromYAML(javaPolicy(`
    patches:
    - class: com.example.Handler
`))
	requireErrorOneOf(t, err,
		"spec.java.patches[0].classFile in body is required",
		"at '/spec/java/patches/0': missing property 'classFile'")
}

func TestJavaValidationNoJava(t *testing.T) {
	tp, err := FromYAML(`
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "no-java"
spec:
  kprobes:
  - call: "sys_openat"
    syscall: true
`)
	require.NoError(t, err)
	require.Nil(t, tp.TpSpec().Java)
}
