package github

import (
	"github.com/turbot/tailpipe-plugin-github/github_collection"
	"github.com/turbot/tailpipe-plugin-sdk/collection"
	"github.com/turbot/tailpipe-plugin-sdk/plugin"
)

type Plugin struct {
	plugin.PluginBase
}

func NewPlugin() (plugin.TailpipePlugin, error) {
	p := &Plugin{}

	err := p.RegisterResources(
		&plugin.ResourceFunctions{
			Collections: []func() collection.Collection{github_collection.NewAuditLogCollection}, // TODO: #finish implement error log collection
		})
	if err != nil {
		return nil, err
	}

	return p, nil
}

func (t *Plugin) Identifier() string {
	return "github"
}
