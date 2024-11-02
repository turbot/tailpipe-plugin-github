package github

import (
	"github.com/turbot/tailpipe-plugin-github/config"
	"github.com/turbot/tailpipe-plugin-github/tables"
	"github.com/turbot/tailpipe-plugin-sdk/plugin"
	"github.com/turbot/tailpipe-plugin-sdk/table"
)

type Plugin struct {
	plugin.PluginBase
}

func NewPlugin() (plugin.TailpipePlugin, error) {
	p := &Plugin{
		PluginBase: plugin.NewPluginBase("github", config.NewGithubConnection),
	}

	err := p.RegisterResources(
		&plugin.ResourceFunctions{
			Tables: []func() table.Table{tables.NewAuditLogTable}, // TODO: #finish implement error log table
		})
	if err != nil {
		return nil, err
	}

	return p, nil
}
