package tables

import (
	"context"
	"time"

	"github.com/rs/xid"

	"github.com/turbot/tailpipe-plugin-github/config"
	"github.com/turbot/tailpipe-plugin-github/mappers"
	"github.com/turbot/tailpipe-plugin-github/rows"
	"github.com/turbot/tailpipe-plugin-sdk/artifact_source"
	"github.com/turbot/tailpipe-plugin-sdk/enrichment"
	"github.com/turbot/tailpipe-plugin-sdk/parse"
	"github.com/turbot/tailpipe-plugin-sdk/row_source"
	"github.com/turbot/tailpipe-plugin-sdk/table"
	"github.com/turbot/tailpipe-plugin-sdk/types"
)

// AuditLogTable - table for github audit logs
type AuditLogTable struct {
	table.TableImpl[*rows.AuditLog, *AuditLogTableConfig, *config.GitHubConnection]
}

func NewAuditLogTable() table.Table {
	return &AuditLogTable{}
}

func (c *AuditLogTable) Init(ctx context.Context, connectionSchemaProvider table.ConnectionSchemaProvider, req *types.CollectRequest) error {
	// call base init
	if err := c.TableImpl.Init(ctx, connectionSchemaProvider, req); err != nil {
		return err
	}

	c.initMapper()
	return nil
}

func (c *AuditLogTable) initMapper() {
	// TODO switch on source
	c.Mapper = mappers.NewAuditLogMapper()
}

func (c *AuditLogTable) Identifier() string {
	return "github_audit_log"
}

func (c *AuditLogTable) GetSourceOptions(string) []row_source.RowSourceOption {
	return []row_source.RowSourceOption{
		artifact_source.WithRowPerLine(),
	}
}

func (c *AuditLogTable) GetRowSchema() any {
	return rows.AuditLog{}
}

func (c *AuditLogTable) GetConfigSchema() parse.Config {
	return &AuditLogTableConfig{}
}

func (c *AuditLogTable) EnrichRow(row *rows.AuditLog, sourceEnrichmentFields *enrichment.CommonFields) (*rows.AuditLog, error) {
	if sourceEnrichmentFields != nil {
		row.CommonFields = *sourceEnrichmentFields
	}

	// Record standardization
	row.TpID = xid.New().String()
	row.TpTimestamp = *row.Timestamp
	row.TpIngestTimestamp = time.Now()
	row.TpSourceIP = row.ActorIP
	switch {
	case row.Org != nil:
		row.TpIndex = *row.Org
	case row.User != nil:
		row.TpIndex = *row.User
	default:
		row.TpIndex = *row.OrgID
	}
	row.TpDate = row.Timestamp.Format("2006-01-02")

	return row, nil
}
