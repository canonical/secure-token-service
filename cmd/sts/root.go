// Copyright 2025 Canonical Ltd
// SPDX-License-Identifier: AGPL-3.0

package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var (
	// rootCmd represents the base command when called without any subcommands
	rootCmd = &cobra.Command{
		Use:   "sts",
		Short: "Secure Token Service - Manages user sessions and JWT tokens",
		Long: `Secure Token Service that manages user sessions, 
generates and validates JWT tokens, and provides both HTTP and gRPC interfaces.`,
	}
)

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main().It only needs to happen once to the rootCmd.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func main() {
	Execute()
}
