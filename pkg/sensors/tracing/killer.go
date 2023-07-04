package tracing

import (
	"fmt"
	"path"
	"strings"
	"sync/atomic"

	"github.com/cilium/tetragon/pkg/arch"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/policyfilter"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/cilium/tetragon/pkg/sensors/program"
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

	syscallsIDs  []uint64
	syscallsSyms []string
)

func KillerMapValues() ([]uint64, error) {
	if !initialized {
		return nil, fmt.Errorf("killer: no syscall data")
	}
	return syscallsIDs, nil
}

func (h killerSensor) PolicyHandler(
	policy tracingpolicy.TracingPolicy,
	policyID policyfilter.PolicyID,
) (*sensors.Sensor, error) {

	spec := policy.TpSpec()

	if len(spec.Killers) > 0 {
		name := fmt.Sprintf("gkp-sensor-%d", atomic.AddUint64(&sensorCounter, 1))
		return createKillerSensor(spec.Killers, name)
	}

	return nil, nil
}

func loadKillerSensor(bpfDir, mapDir string, load *program.Program, verbose int) error {
	data := &program.MultiKprobeAttachData{}

	for idx := range syscallsSyms {
		sym := syscallsSyms[idx]
		pfxSym, err := arch.AddSyscallPrefix(sym)
		if err != nil {
			return err
		}
		data.Symbols = append(data.Symbols, pfxSym)
	}

	load.SetAttachData(data)

	if err := program.LoadMultiKprobeProgram(bpfDir, mapDir, load, verbose); err == nil {
		logger.GetLogger().Infof("Loaded killer sensor: %s", load.Attach)
	} else {
		return err
	}

	return nil
}

func (k *killerSensor) LoadProbe(args sensors.LoadProbeArgs) error {
	return loadKillerSensor(args.BPFDir, args.MapDir, args.Load, args.Verbose)

}
func createKillerSensor(
	killers []v1alpha1.KillerSpec,
	name string,
) (*sensors.Sensor, error) {

	if len(killers) > 1 {
		return nil, fmt.Errorf("failed: we support only single killer sensor")

	}

	killer := killers[0]

	for idx := range killer.Syscalls {
		sym := killer.Syscalls[idx]
		syscallsSyms = append(syscallsSyms, sym)
		if strings.HasPrefix(sym, "sys_") {
			sym = sym[4:]
		}
		// translate into syscall number
		id := syscallinfo.GetSyscallID(sym)
		syscallsIDs = append(syscallsIDs, uint64(id))
	}

	load := program.Builder(
		path.Join(option.Config.HubbleLib, "bpf_killer.o"),
		"attach",
		"kprobe.multi/killer",
		sensors.PathJoin(name, "killer_kprobe"),
		"killer")

	killerDataMap := program.MapBuilderPin("killer_data", "killer_data", load)

	initialized = true

	return &sensors.Sensor{
		Name:  "__killer__",
		Progs: []*program.Program{load},
		Maps:  []*program.Map{killerDataMap},
	}, nil
}
