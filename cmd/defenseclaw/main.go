package main

import "github.com/defenseclaw/defenseclaw/internal/cli"

var (
	version = "dev"
	commit  = "unknown"
	date    = "unknown"
)

func main() {
	cli.SetVersion(version)
	cli.SetBuildInfo(commit, date)
	cli.Execute()
}
