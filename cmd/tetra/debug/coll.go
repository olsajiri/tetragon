// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package debug

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/spf13/cobra"
)

func NewCollCmd() *cobra.Command {
	var path string

	cmd := cobra.Command{
		Use:   "coll",
		Short: "collection info",
		Long: `Displays details for collection.
Example:
  # tetra debug coll --path ./bpf/objs/bpf_generic_kprobe.o
`,

		RunE: func(_ *cobra.Command, _ []string) error {
			spec, err := ebpf.LoadCollectionSpec(path)
			if err != nil {
				return fmt.Errorf("loading collection spec failed: %w", err)
			}

			for _, prog := range spec.Programs {
				fmt.Printf("%s %d insns\n", prog.Name, len(prog.Instructions))
			}
			return nil
		},
	}

	flags := cmd.Flags()
	flags.StringVar(&path, "path", "", "Path of the bpf object file.")
	return &cmd
}
