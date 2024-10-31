package github

import (
	"github.com/turbot/tailpipe-plugin-github/tables"
	"github.com/turbot/tailpipe-plugin-sdk/plugin"
	"github.com/turbot/tailpipe-plugin-sdk/table"
)

func NewPlugin() (plugin.TailpipePlugin, error) {
	p := plugin.NewPlugin("github")

	err := p.RegisterResources(
		&plugin.ResourceFunctions{
			Tables: []func() table.Table{tables.NewAuditLogTable}, // TODO: #finish implement error log table
		})
	if err != nil {
		return nil, err
	}

	return p, nil
}
