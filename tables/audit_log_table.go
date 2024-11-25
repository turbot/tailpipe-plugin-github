package tables

import (
	"time"

	"github.com/rs/xid"

	"github.com/turbot/tailpipe-plugin-github/mappers"
	"github.com/turbot/tailpipe-plugin-github/rows"
	"github.com/turbot/tailpipe-plugin-sdk/artifact_source"
	"github.com/turbot/tailpipe-plugin-sdk/constants"
	"github.com/turbot/tailpipe-plugin-sdk/enrichment"
	"github.com/turbot/tailpipe-plugin-sdk/row_source"
	"github.com/turbot/tailpipe-plugin-sdk/table"
)

const AuditLogTableIdentifier = "github_audit_log"

// register the table from the package init function
func init() {
	// Register the table, with type parameters:
	// 1. row struct
	// 2. table config struct
	// 3. table implementation
	table.RegisterTable[*rows.AuditLog, *AuditLogTableConfig, *AuditLogTable]()
}

// AuditLogTable - table for github audit logs
type AuditLogTable struct {
}

func (c *AuditLogTable) Identifier() string {
	return AuditLogTableIdentifier
}

func (c *AuditLogTable) SupportedSources(_ *AuditLogTableConfig) []*table.SourceMetadata[*rows.AuditLog] {
	return []*table.SourceMetadata[*rows.AuditLog]{
		{
			SourceName: constants.ArtifactSourceIdentifier,
			MapperFunc: mappers.NewAuditLogMapper,
			Options: []row_source.RowSourceOption{
				artifact_source.WithRowPerLine(),
			},
		},
	}
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
	row.TpDate = row.Timestamp.Truncate(24 * time.Hour)
	return row, nil
}
