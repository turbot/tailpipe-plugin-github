package github

import (
	"github.com/turbot/go-kit/helpers"
	"github.com/turbot/tailpipe-plugin-github/config"
	"github.com/turbot/tailpipe-plugin-sdk/plugin"
	"github.com/turbot/tailpipe-plugin-sdk/table"

	// reference the table package to ensure that the tables are registered by the init functions
	_ "github.com/turbot/tailpipe-plugin-github/tables"
)

type Plugin struct {
	plugin.PluginImpl
}

func NewPlugin() (_ plugin.TailpipePlugin, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = helpers.ToError(r)
		}
	}()

	p := &Plugin{
		PluginImpl: plugin.NewPluginImpl("github", config.NewGitHubConnection),
	}

	// initialise table factory
	if err := table.Factory.Init(); err != nil {
		return nil, err
	}

	return p, nil
}
