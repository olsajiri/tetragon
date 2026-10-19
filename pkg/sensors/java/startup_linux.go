// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build linux

package java

import (
	"bufio"
	"fmt"
	"hash/fnv"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/config"
	"github.com/cilium/tetragon/pkg/elf"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/cilium/tetragon/pkg/sensors/program"
	"github.com/cilium/tetragon/pkg/tracingpolicy"
)

func javaStartupPrograms(policy tracingpolicy.TracingPolicy, executables map[string]struct{}) ([]*program.Program, []*program.Map, error) {
	if len(executables) == 0 {
		return nil, nil, nil
	}
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" {
		return nil, nil, fmt.Errorf("Java startup probes are unsupported on architecture %q", runtime.GOARCH)
	}
	if !config.EnableV61Progs() {
		return nil, nil, fmt.Errorf("Java startup probes require the v6.1 BPF program set")
	}
	if !bpf.HasProbeWriteUserHelper() {
		return nil, nil, fmt.Errorf("Java startup probes require the bpf_probe_write_user helper")
	}
	if !bpf.HasUprobeRegsChange() {
		return nil, nil, fmt.Errorf("Java startup probes require uprobe register modification support")
	}

	var progs []*program.Program
	var maps []*program.Map
	for executable := range executables {
		mmapOffset, setenvOffset, err := libcStartupOffsets(executable)
		if err != nil {
			return nil, nil, fmt.Errorf("resolve libc startup functions for %q: %w", executable, err)
		}
		pathHash := fnv.New32a()
		_, _ = pathHash.Write([]byte(executable))
		prog := program.Builder(
			filepath.Join(option.Config.HubbleLib, "bpf_java_start_v61.o"),
			fmt.Sprintf("%s _start", executable),
			"uprobe.s/java_start",
			fmt.Sprintf("java-start-%08x", pathHash.Sum32()),
			"java_start",
		).SetAttachData(&program.UprobeAttachData{
			Path:   executable,
			Symbol: "_start",
		}).SetPolicy(policy.TpName())
		prog.RewriteConstants = map[string]any{
			"java_mmap_offset":   mmapOffset,
			"java_setenv_offset": setenvOffset,
		}
		progs = append(progs, prog)
		maps = append(maps, program.MapBuilderProgram("tg_dyn_sm", prog))
	}
	return progs, maps, nil
}

func libcStartupOffsets(binary string) (mmapOffset, setenvOffset uint64, err error) {
	output, err := exec.Command("ldd", binary).Output()
	if err != nil {
		return 0, 0, fmt.Errorf("run ldd: %w", err)
	}
	var libcPath string
	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		parts := strings.SplitN(line, "=>", 2)
		if len(parts) != 2 || strings.TrimSpace(parts[0]) != "libc.so.6" {
			continue
		}
		fields := strings.Fields(strings.TrimSpace(parts[1]))
		if len(fields) > 0 && fields[0] != "not" {
			libcPath = fields[0]
			break
		}
	}
	if err := scanner.Err(); err != nil {
		return 0, 0, err
	}
	if libcPath == "" {
		return 0, 0, fmt.Errorf("libc.so.6 dependency not found")
	}
	file, err := elf.OpenSafeELFFile(libcPath)
	if err != nil {
		return 0, 0, fmt.Errorf("open %q: %w", libcPath, err)
	}
	defer file.Close()
	if mmapOffset, err = file.DynamicAddress("mmap"); err != nil {
		return 0, 0, fmt.Errorf("resolve mmap: %w", err)
	}
	if setenvOffset, err = file.DynamicAddress("setenv"); err != nil {
		return 0, 0, fmt.Errorf("resolve setenv: %w", err)
	}
	return mmapOffset, setenvOffset, nil
}

func startupSensor(policy tracingpolicy.TracingPolicy, executables map[string]struct{}) (*sensors.Sensor, error) {
	progs, maps, err := javaStartupPrograms(policy, executables)
	if err != nil {
		return nil, err
	}
	return &sensors.Sensor{
		Name:      sensorName + ":" + policy.TpName(),
		Policy:    policy.TpName(),
		Namespace: policy.TpNamespace(),
		Progs:     progs,
		Maps:      maps,
	}, nil
}

type javaStartupProbe struct{}

func init() {
	sensors.RegisterProbeType("java_start", javaStartupProbe{})
}

func (javaStartupProbe) LoadProbe(args sensors.LoadProbeArgs) error {
	return program.LoadUprobeProgram(args.BPFDir, args.Load, args.Maps, args.Verbose)
}
