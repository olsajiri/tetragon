// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build linux

package java

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	grpctracing "github.com/cilium/tetragon/pkg/grpc/tracing"
	"github.com/cilium/tetragon/pkg/javaagent"
	"github.com/cilium/tetragon/pkg/javaattach"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/observer"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/policyfilter"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/cilium/tetragon/pkg/tracingpolicy"
)

const (
	sensorName      = "java"
	nativeAgentPath = "/usr/lib/tetragon/tetragon-jvmti.so"
	scanInterval    = time.Second
	retryInterval   = 5 * time.Second
)

type policyHandler struct{}
type processIdentity struct {
	pid        int
	startTicks uint64
}

type javaSensor struct {
	*sensors.Sensor
	mu           sync.Mutex
	policy       javaagent.Policy
	agentEnabled bool
	executables  map[string]struct{}
	argsContain  []string
	active       map[int]processIdentity
	lastAttempt  map[int]time.Time
	stop         chan struct{}
	done         chan struct{}
}

var (
	serverOnce  sync.Once
	agentServer *javaagent.Server
	attachedMu  sync.Mutex
	attachedVMs = make(map[processIdentity]int)
)

func init() {
	sensors.RegisterPolicyHandlerAtInit(sensorName, policyHandler{})
}

func ensureServer() *javaagent.Server {
	serverOnce.Do(func() {
		path := optionSocketPath()
		agentServer = javaagent.NewServer(path, func(
			pid, tid uint32,
			ktime, methodID uint64,
			className, methodName, descriptor, policyName, message string,
			tags []string,
		) {
			observer.SubmitEvent(&grpctracing.MsgJavaEvent{
				Pid:        pid,
				Tid:        tid,
				Ktime:      ktime,
				MethodID:   methodID,
				ClassName:  className,
				MethodName: methodName,
				Descriptor: descriptor,
				PolicyName: policyName,
				Message:    message,
				Tags:       tags,
			})
		})
		go func() {
			if err := agentServer.Listen(context.Background()); err != nil {
				logger.GetLogger().Error("Java agent control socket stopped", "error", err)
			}
		}()
	})
	return agentServer
}

func optionSocketPath() string {
	// Read the configured value when the server is first needed, after option
	// parsing has completed.
	if option.Config.JavaAgentSocketPath != "" {
		return option.Config.JavaAgentSocketPath
	}
	return "/var/run/tetragon/java.sock"
}

func (policyHandler) PolicyHandler(
	policy tracingpolicy.TracingPolicy,
	filterID policyfilter.PolicyID,
) (sensors.SensorIface, error) {
	if filterID != policyfilter.NoFilterID {
		return nil, errors.New("Java policies do not support policy filtering")
	}
	spec := policy.TpSpec().Java
	if spec == nil {
		return nil, nil
	}
	if len(spec.Patches) != 0 {
		return nil, errors.New(
			"Java class patches are not supported by the JVMTI method monitoring agent",
		)
	}
	executables := make(map[string]struct{})
	if spec.Targets != nil {
		for _, path := range spec.Targets.Executables {
			if !filepath.IsAbs(path) || filepath.Clean(path) != path || strings.ContainsRune(path, '\x00') {
				return nil, fmt.Errorf("Java executable path %q must be absolute and clean", path)
			}
			executables[path] = struct{}{}
		}
		for _, token := range spec.Targets.ProcessArgsContains {
			if token == "" || strings.ContainsRune(token, '\x00') {
				return nil, errors.New("Java processArgsContains entries must be non-empty and contain no NUL")
			}
		}
	}
	if len(spec.Hooks) == 0 && len(executables) == 0 {
		return nil, errors.New("Java policy without method hooks needs at least one executable target")
	}
	agentEnabled := len(spec.Hooks) != 0
	if agentEnabled {
		if _, err := os.Stat(nativeAgentPath); err != nil {
			return nil, fmt.Errorf("JVMTI agent %q unavailable: %w", nativeAgentPath, err)
		}
	}
	agentPolicy := javaagent.Policy{
		ID:   uint32(filterID),
		Name: tracingpolicy.TpLongname(policy),
		Meta: make(map[uint32]javaagent.HookMetadata),
	}
	// Policy IDs used by the JVMTI agent must be unique even when policy
	// filtering is disabled (NoFilterID is zero). Sensor manager allocates a
	// stable per-policy ID separately from the filter ID; use a local hash for
	// the agent namespace until that ID is exposed to policy handlers.
	agentPolicy.ID = policyID(policy)
	for i, hook := range spec.Hooks {
		if (hook.Class == "") == (hook.ClassPrefix == "") {
			return nil, fmt.Errorf("java.hooks[%d] requires exactly one of class or classPrefix", i)
		}
		class := hook.Class
		kind := uint8(javaagent.HookClass)
		if class == "" {
			class = hook.ClassPrefix
			kind = javaagent.HookPrefix
		}
		class = strings.ReplaceAll(class, ".", "/")
		methods := make([]javaagent.HookMethod, 0, len(hook.Methods))
		for _, m := range hook.Methods {
			methods = append(methods, javaagent.HookMethod{Name: m.Name, Descriptor: m.Descriptor})
		}
		agentPolicy.Hooks = append(agentPolicy.Hooks, javaagent.Hook{
			PolicyID: agentPolicy.ID,
			HookID:   uint32(i),
			Kind:     kind,
			Class:    class,
			Methods:  methods,
		})
		agentPolicy.Meta[uint32(i)] = javaagent.HookMetadata{
			Message: hook.Message,
			Tags:    append([]string(nil), hook.Tags...),
		}
	}
	args := []string(nil)
	if spec.Targets != nil {
		args = append(args, spec.Targets.ProcessArgsContains...)
	}
	bpfSensor, err := startupSensor(policy, executables)
	if err != nil {
		return nil, fmt.Errorf("create Java startup sensor: %w", err)
	}
	return &javaSensor{
		Sensor:       bpfSensor,
		policy:       agentPolicy,
		agentEnabled: agentEnabled,
		executables:  executables,
		argsContain:  args,
		active:       make(map[int]processIdentity),
		lastAttempt:  make(map[int]time.Time),
	}, nil
}

func policyID(policy tracingpolicy.TracingPolicy) uint32 {
	// FNV-1a keeps the protocol's u32 policy key stable across daemon restarts.
	h := uint32(2166136261)
	for _, b := range []byte(tracingpolicy.TpLongname(policy)) {
		h ^= uint32(b)
		h *= 16777619
	}
	if h == 0 {
		return 1
	}
	return h
}

func (s *javaSensor) Load(bpfDir string) error {
	s.mu.Lock()
	if s.Loaded {
		s.mu.Unlock()
		return fmt.Errorf("Java sensor %q is already loaded", s.Name)
	}
	if s.Destroyed {
		s.mu.Unlock()
		return fmt.Errorf("Java sensor %q was destroyed", s.Name)
	}
	if s.agentEnabled {
		s.stop = make(chan struct{})
		s.done = make(chan struct{})
		s.lastAttempt = make(map[int]time.Time)
	}
	s.mu.Unlock()
	if len(s.Progs) != 0 {
		if err := s.Sensor.Load(bpfDir); err != nil {
			if s.agentEnabled {
				s.mu.Lock()
				s.stop = nil
				s.done = nil
				s.mu.Unlock()
			}
			return fmt.Errorf("load Java startup probes: %w", err)
		}
	}
	s.mu.Lock()
	s.Loaded = true
	s.mu.Unlock()
	if !s.agentEnabled {
		return nil
	}
	server := ensureServer()
	if err := server.SetPolicy(s.policy); err != nil {
		if s.Sensor.Loaded {
			_ = s.Sensor.Unload(true)
		}
		return err
	}
	if err := s.scan(); err != nil {
		logger.GetLogger().Warn("Java JVM scan failed", "policy", s.Policy, "error", err)
	}
	go s.watch()
	return nil
}

func (s *javaSensor) watch() {
	defer close(s.done)
	ticker := time.NewTicker(scanInterval)
	defer ticker.Stop()
	for {
		select {
		case <-s.stop:
			return
		case <-ticker.C:
			if err := s.scan(); err != nil {
				logger.GetLogger().Warn("Java JVM scan failed", "policy", s.Policy, "error", err)
			}
		}
	}
}

func (s *javaSensor) scan() error {
	candidates, err := matchingProcesses(s.executables, s.argsContain)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.Loaded {
		return nil
	}
	server := ensureServer()
	present := make(map[int]uint64, len(candidates))
	var first error
	for _, target := range candidates {
		present[target.pid] = target.startTicks
		if current, ok := s.active[target.pid]; ok && current.startTicks == target.startTicks {
			continue
		} else if ok {
			delete(s.active, target.pid)
			server.RevokeProcess(s.policy.ID, uint32(target.pid), current.startTicks)
			attachedMu.Lock()
			if refs := attachedVMs[current]; refs <= 1 {
				delete(attachedVMs, current)
			} else {
				attachedVMs[current] = refs - 1
			}
			attachedMu.Unlock()
		}
		if last, ok := s.lastAttempt[target.pid]; ok && time.Since(last) < retryInterval {
			continue
		}
		s.lastAttempt[target.pid] = time.Now()
		if err := server.AllowProcess(s.policy.ID, uint32(target.pid), target.startTicks); err != nil && first == nil {
			first = fmt.Errorf("apply Java policy to pid %d: %w", target.pid, err)
			continue
		}
		attachedMu.Lock()
		refs := attachedVMs[target]
		if refs > 0 {
			attachedVMs[target] = refs + 1
			attachedMu.Unlock()
			s.active[target.pid] = target
			delete(s.lastAttempt, target.pid)
			continue
		}
		if err := s.attach(target); err != nil {
			attachedMu.Unlock()
			server.RevokeProcess(s.policy.ID, uint32(target.pid), target.startTicks)
			if first == nil {
				first = fmt.Errorf("attach JVMTI agent to pid %d: %w", target.pid, err)
			}
			continue
		}
		attachedVMs[target] = 1
		attachedMu.Unlock()
		s.active[target.pid] = target
		delete(s.lastAttempt, target.pid)
	}
	for pid, target := range s.active {
		if start, ok := present[pid]; ok && start == target.startTicks {
			continue
		}
		current, err := readProcessIdentity(pid)
		if err != nil || current.startTicks != target.startTicks {
			delete(s.active, pid)
			server.RevokeProcess(s.policy.ID, uint32(pid), target.startTicks)
			attachedMu.Lock()
			if refs := attachedVMs[target]; refs <= 1 {
				delete(attachedVMs, target)
			} else {
				attachedVMs[target] = refs - 1
			}
			attachedMu.Unlock()
		}
	}
	return first
}

func (s *javaSensor) attach(target processIdentity) error {
	current, err := readProcessIdentity(target.pid)
	if err != nil {
		return err
	}
	if current.startTicks != target.startTicks {
		return errors.New("process exited or PID was reused")
	}
	data, err := os.ReadFile(nativeAgentPath)
	if err != nil {
		return err
	}
	procRoot := filepath.Join("/proc", strconv.Itoa(target.pid), "root", "tmp")
	path := filepath.Join(
		procRoot,
		fmt.Sprintf(".tetragon-jvmti-%d-%d.so", target.pid, target.startTicks),
	)
	if err := writeAgentFile(path, data); err != nil {
		return err
	}
	defer os.Remove(path)
	return javaattach.LoadNativeAgent(
		target.pid,
		filepath.Join("/tmp", filepath.Base(path)),
		optionSocketPath(),
	)
}

func writeAgentFile(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0555)
	if errors.Is(err, os.ErrExist) {
		return os.Chmod(path, 0555)
	}
	if err != nil {
		return err
	}
	_, werr := f.Write(data)
	cerr := f.Close()
	if werr != nil {
		os.Remove(path)
		return werr
	}
	if cerr != nil {
		os.Remove(path)
		return cerr
	}
	return nil
}

func (s *javaSensor) Unload(_ bool) error {
	return s.unload(func(id uint32) error {
		return ensureServer().RemovePolicy(id)
	})
}

func (s *javaSensor) unload(removePolicy func(uint32) error) error {
	var err error
	if s.agentEnabled {
		s.mu.Lock()
		if !s.Loaded {
			s.mu.Unlock()
			return fmt.Errorf("Java sensor %q is not loaded", s.Name)
		}
		close(s.stop)
		done := s.done
		s.mu.Unlock()

		<-done
		err = removePolicy(s.policy.ID)
	} else if !s.Loaded {
		return fmt.Errorf("Java sensor %q is not loaded", s.Name)
	}
	return errors.Join(err, s.Sensor.Unload(true))
}

func (s *javaSensor) Destroy(unpin bool) error {
	if s.Loaded {
		if err := s.Unload(unpin); err != nil {
			return err
		}
	}
	s.mu.Lock()
	s.Destroyed = true
	s.mu.Unlock()
	return nil
}

func matchingProcesses(
	executables map[string]struct{},
	argsContain []string,
) ([]processIdentity, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}
	matches := make([]processIdentity, 0)
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid <= 1 {
			continue
		}
		proc := filepath.Join("/proc", entry.Name())
		exe, err := os.Readlink(filepath.Join(proc, "exe"))
		if err != nil {
			continue
		}
		if len(executables) > 0 {
			if _, ok := executables[exe]; !ok {
				continue
			}
		} else {
			maps, e := os.ReadFile(filepath.Join(proc, "maps"))
			if e != nil || !bytes.Contains(maps, []byte("libjvm.so")) {
				continue
			}
		}
		cmd, err := os.ReadFile(filepath.Join(proc, "cmdline"))
		if err != nil || !containsArgs(cmd, argsContain) {
			continue
		}
		ident, err := readProcessIdentity(pid)
		if err == nil {
			matches = append(matches, ident)
		}
	}
	return matches, nil
}

func containsArgs(cmd []byte, required []string) bool {
	for _, token := range required {
		found := false
		for _, arg := range bytes.Split(cmd, []byte{0}) {
			if bytes.Contains(arg, []byte(token)) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func readProcessIdentity(pid int) (processIdentity, error) {
	data, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "stat"))
	if err != nil {
		return processIdentity{}, err
	}
	end := bytes.LastIndexByte(data, ')')
	if end < 0 {
		return processIdentity{}, errors.New("malformed proc stat")
	}
	fields := strings.Fields(string(data[end+1:]))
	if len(fields) <= 19 {
		return processIdentity{}, errors.New("proc stat lacks start time")
	}
	ticks, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil {
		return processIdentity{}, err
	}
	return processIdentity{pid: pid, startTicks: ticks}, nil
}
