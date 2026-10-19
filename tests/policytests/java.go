// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package tests

import (
	ec "github.com/cilium/tetragon/api/v1/tetragon/codegen/eventchecker"
	"github.com/cilium/tetragon/pkg/testutils/policytest"
)

const javaToolOptions = "-XX:+StartAttachListener -XX:+EnableDynamicAgentLoading -XX:-DisableAttachMechanism"

var _ = policytest.NewBuilder("java-tool-options").WithLabels("java").WithPolicyTemplate(`
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "java-tool-options"
spec:
  java:
    targets:
      executables:
      - {{ testBinary "java-tool-options" }}
    hooks:
    - class: example.Main
      methods:
      - name: main
`).AddScenario(func(c *policytest.Conf) *policytest.Scenario {
	bin := c.TestBinary("java-tool-options")
	trigger := policytest.NewCmdTrigger(bin).ExpectExitCode(0)
	trigger.ExpectedStdout = []string{javaToolOptions}
	return &policytest.Scenario{
		Name:         "JAVA_TOOL_OPTIONS is updated for a targeted executable",
		Trigger:      trigger,
		EventChecker: ec.NewUnorderedEventChecker(),
	}
}).RegisterAtInit()
