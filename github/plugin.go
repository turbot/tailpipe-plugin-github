package github

import (
	"github.com/turbot/go-kit/helpers"
	"github.com/turbot/tailpipe-plugin-github/config"
	"github.com/turbot/tailpipe-plugin-sdk/plugin"
	"github.com/turbot/tailpipe-plugin-sdk/table"

	"github.com/turbot/tailpipe-plugin-github/tables/audit_log"
)

type Plugin struct {
	plugin.PluginImpl
}

func init() {
	// Register tables, with type parameters:
	// 1. row struct
	// 2. table implementation
	table.RegisterTable[*audit_log.AuditLog, *audit_log.AuditLogTable]()

	// TODO: register sources in future if needed
}

func NewPlugin() (_ plugin.TailpipePlugin, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = helpers.ToError(r)
		}
	}()

	p := &Plugin{
		PluginImpl: plugin.NewPluginImpl(config.PluginName),
	}

	return p, nil
}
