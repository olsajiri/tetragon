// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package bench

import (
	"context"
	"log"
	"os"
	"strings"
	"time"

	"github.com/tezc/goperf"
)

type TraceBench interface {
	Crd(ctx context.Context, args *Arguments) string
	Run(ctx context.Context, args *Arguments, summary *Summary) error
}

var (
	traceBenches = []string{"rw", "open", "perf-msg"}
)

func TraceBenchSupported() []string {
	keys := make([]string, 0, len(traceBenches))
	for k := range traceBenches {
		keys = append(keys, string(k))
	}
	return keys
}

func TraceBenchNameOrPanic(s string) string {
	for _, k := range traceBenches {
		if k == s {
			return s
		}
	}
	log.Fatalf("Unknown bench '%s', use one of: %s", s, strings.Join(TraceBenchSupported(), ", "))
	return string("")
}

func RunTraceBench(args *Arguments) (summary *Summary) {
	ctx, cancel := context.WithCancel(context.Background())
	go sigHandler(ctx, cancel)

	summary = newSummary(args)
	summary.StartTime = time.Now()

	EnableBpfStats()
	oldBpfStats := GetBpfStats()

	var bench TraceBench

	switch args.Trace {
	case "rw":
		bench = newTraceBenchRw()
	case "open":
		bench = newTraceBenchOpen()
	case "perf-msg":
		bench = newTraceBenchPerfMsg()
	default:
		panic("unknown benchmark")
	}

	configFile := bench.Crd(ctx, args)
	defer os.Remove(configFile)

	// Start FGS if requested.
	tetragonFinished := make(chan bool, 1)
	if !args.Baseline {
		ready := make(chan bool)
		log.Printf("Starting tetragon...\n")
		go func() {
			runTetragon(ctx, configFile, args, summary, ready)
			tetragonFinished <- true
		}()
		// Wait for FGS to initialize.
		<-ready
	} else {
		tetragonFinished <- true
	}
	summary.SetupDurationNanos = time.Since(summary.StartTime)

	log.Printf("Benchmark start [%s]", args.Trace)

	cpuUsageBefore := GetCPUUsage(CPU_USAGE_ALL_THREADS)

	summary.RunTime = time.Now()

	if args.GoPerf {
		goperf.Start()
	}

	err := bench.Run(ctx, args, summary)
	if err != nil {
		cancel()
		return
	}

	if args.GoPerf {
		goperf.Pause()
	}

	summary.EndTime = time.Now()

	cpuUsageAfter := GetCPUUsage(CPU_USAGE_ALL_THREADS)

	summary.BpfStats = GetBpfStatsSince(oldBpfStats)
	summary.TestDurationNanos = summary.EndTime.Sub(summary.StartTime)

	log.Printf("Benchmark finished, cleaning..")

	// Now that the source finished, cancel the context to stop everything and collect stats.
	cancel()
	// Wait for FGS to finish cleaning up.
	<-tetragonFinished

	summary.FgsCPUUsage = cpuUsageAfter.Sub(cpuUsageBefore)
	return
}
