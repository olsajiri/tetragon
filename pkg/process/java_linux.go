// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build linux

package process

import (
	"github.com/cilium/tetragon/pkg/option"
)

// GetParentProcessInternalByPID selects the newest cached exec for pid whose
// start time is not later than the Java submission timestamp.
func GetParentProcessInternalByPID(pid uint32, eventKtime uint64) (*ProcessInternal, *ProcessInternal) {
	if option.Config.DisableProcessCache || procCache == nil {
		return nil, nil
	}
	return procCache.getByPID(pid, eventKtime)
}
