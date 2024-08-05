package main

import (
	"log/slog"

	"github.com/turbot/tailpipe-plugin-github/github"
	"github.com/turbot/tailpipe-plugin-sdk/plugin"
)

func main() {
	err := plugin.Serve(&plugin.ServeOpts{
		PluginFunc: github.NewPlugin,
	})

	if err != nil {
		slog.Error("Error starting plugin", "error", err)
	}
}
