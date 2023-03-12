// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package yaml

import (
	"fmt"

	"github.com/cilium/tetragon/pkg/btf"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func New() *cobra.Command {
	yamlCmd := &cobra.Command{
		Use:   "yaml",
		Short: "Generate yaml policies",
	}

	yamlAllSyscallsCmd := &cobra.Command{
		Use:   "all-syscalls",
		Short: "Generate all syscalls",
		Run: func(cmd *cobra.Command, args []string) {
			allSyscalls(args)
		},
	}

	flags := yamlAllSyscallsCmd.Flags()
	flags.Bool("not", false, "Filter out all syscalls")
	viper.BindPFlags(flags)

	yamlCmd.AddCommand(yamlAllSyscallsCmd)
	return yamlCmd
}

func allSyscalls(args []string) {
	not := viper.GetBool("not")
	crd, err := btf.GetSyscallsYaml(not)
	if err != nil {
		fmt.Print(err)
		return
	}
	fmt.Printf("%s\n", crd)
}
