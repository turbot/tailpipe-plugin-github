package github

import (
	"github.com/turbot/tailpipe-plugin-github/tables"
	"github.com/turbot/tailpipe-plugin-sdk/plugin"
	"github.com/turbot/tailpipe-plugin-sdk/table"
)

type Plugin struct {
	plugin.Plugin
}

func NewPlugin() (plugin.TailpipePlugin, error) {
	p := &Plugin{}

	err := p.RegisterResources(
		&plugin.ResourceFunctions{
			Tables: []func() table.Table{tables.NewAuditLogTable}, // TODO: #finish implement error log table
		})
	if err != nil {
		return nil, err
	}

	return p, nil
}

func (t *Plugin) Identifier() string {
	return "github"
}
