package main

import (
	"fmt"
	"github.com/komari-monitor/komari-agent/internal/hostcmd"
	"os"
)

func main() {
	if err := hostcmd.Run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "komari-host:", err)
		os.Exit(1)
	}
}
