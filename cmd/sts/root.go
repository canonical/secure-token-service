package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var (
	rootCmd = &cobra.Command{
		Use:   "sts",
		Short: "Secure Token Service - Manages user sessions and JWT tokens",
		Long: `Secure Token Service that manages user sessions, 
generates and validates JWT tokens, and provides both HTTP and gRPC interfaces.`,
	}
)

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func main() {
	Execute()
}
