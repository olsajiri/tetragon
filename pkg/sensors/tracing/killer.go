package tracing

import (
	"fmt"
	"strings"
	"sync/atomic"

	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/policyfilter"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/cilium/tetragon/pkg/syscallinfo"
	"github.com/cilium/tetragon/pkg/tracingpolicy"
)

type killerSensor struct{}

func init() {
	killer := &killerSensor{}
	sensors.RegisterProbeType("killer", killer)
	sensors.RegisterPolicyHandlerAtInit("killer", killerSensor{})
}

var (
	initialized bool
	syscalls    []uint64
)

func KillerMapValues() ([]uint64, error) {
	if !initialized {
		return nil, fmt.Errorf("killer: no syscall data")
	}
	return syscalls, nil
}

func (h killerSensor) PolicyHandler(
	policy tracingpolicy.TracingPolicy,
	policyID policyfilter.PolicyID,
) (*sensors.Sensor, error) {

	policyName := policy.TpName()
	spec := policy.TpSpec()

	if len(spec.Killers) > 0 {
		name := fmt.Sprintf("gtp-sensor-%d", atomic.AddUint64(&sensorCounter, 1))
		return createKillerSensor(name, spec.Killers, policyID, policyName)
	}
	return nil, nil
}

func (k *killerSensor) LoadProbe(args sensors.LoadProbeArgs) error {
	return nil
}

func createKillerSensor(
	name string,
	killers []v1alpha1.KillerSpec,
	policyID policyfilter.PolicyID,
	policyName string,
) (*sensors.Sensor, error) {

	if len(killers) > 1 {
		return nil, fmt.Errorf("failed: we support only single killer sensor")

	}

	killer := killers[0]

	for idx := range killer.Syscalls {
		name := killer.Syscalls[idx]
		if strings.HasPrefix(name, "sys_") {
			name = name[4:]
		}
		// translate into syscall number
		sc := syscallinfo.GetSyscallID(name)
		syscalls = append(syscalls, uint64(sc))
	}

	initialized = true
	return nil, nil
}
