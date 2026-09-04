// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !linux

package process

func GetParentProcessInternalByPID(uint32, uint64) (*ProcessInternal, *ProcessInternal) {
	return nil, nil
}
