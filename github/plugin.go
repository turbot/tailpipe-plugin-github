package github

import (
	"github.com/turbot/go-kit/helpers"
	"github.com/turbot/tailpipe-plugin-github/config"
	"github.com/turbot/tailpipe-plugin-github/tables"
	"github.com/turbot/tailpipe-plugin-sdk/plugin"
	"github.com/turbot/tailpipe-plugin-sdk/table"
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

	resources := &plugin.ResourceFunctions{
		Tables: []func() table.Table{tables.NewAuditLogTable},
	}

	if err := p.RegisterResources(resources); err != nil {
		return nil, err
	}
	return p, nil
}
