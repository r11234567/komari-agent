package main

import (
	"os"

	"github.com/komari-monitor/komari-agent/cmd"
	"github.com/komari-monitor/komari-agent/files"
)

func main() {
	if len(os.Args) == 2 && os.Args[1] == files.WorkerArgument {
		if err := files.ServeWorker(os.Stdin, os.Stdout); err != nil {
			os.Exit(1)
		}
		return
	}
	cmd.Execute()
	os.Exit(0)
}
