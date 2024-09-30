package main

import (
	"fmt"
	"github.com/open-policy-agent/opa/cmd"
	"os"
	"umbrella-associates/opa-spicedb/builtins"
	"umbrella-associates/opa-spicedb/plugins"
)

func main() {
	builtins.Register()
	plugins.Register()

	if err := cmd.RootCommand.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
