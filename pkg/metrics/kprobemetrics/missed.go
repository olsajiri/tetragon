// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package kprobemetrics

import (
	"sync"

	"github.com/cilium/tetragon/pkg/metrics"
	"github.com/cilium/tetragon/pkg/metrics/consts"
	"github.com/prometheus/client_golang/prometheus"
)

type MissedKey struct {
	id     uint32
	attach string
}

type MissedStat struct {
	policy string
	missed float64
}

var (
	MissedProbes = metrics.NewBPFCounter(prometheus.NewDesc(
		prometheus.BuildFQName(consts.MetricsNamespace, "", "missed_probes_total"),
		"The total number of Tetragon probe missed per policy,probe.",
		[]string{"policy", "attach"}, nil,
	))

	lock        sync.Mutex
	missedStats = make(map[MissedKey]*MissedStat)
)

func MissedStore(id uint32, policy, attach string, missed float64) {
	lock.Lock()
	defer lock.Unlock()

	key := MissedKey{id, attach}
	if stat, found := missedStats[key]; found {
		stat.missed = missed
	} else {
		missedStats[key] = &MissedStat{
			policy: policy,
			missed: missed,
		}
	}
}

func MissedRemove(id uint32, attach string) {
	lock.Lock()
	defer lock.Unlock()
	delete(missedStats, MissedKey{id, attach})
}
