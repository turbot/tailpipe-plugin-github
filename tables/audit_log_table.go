package tables

import (
	"time"

	"github.com/rs/xid"

	"github.com/turbot/tailpipe-plugin-github/config"
	"github.com/turbot/tailpipe-plugin-github/mappers"
	"github.com/turbot/tailpipe-plugin-github/rows"
	"github.com/turbot/tailpipe-plugin-sdk/constants"
	"github.com/turbot/tailpipe-plugin-sdk/enrichment"
	"github.com/turbot/tailpipe-plugin-sdk/table"
)

const AuditLogTableIdentifier = "github_audit_log"

// register the table from the package init function
func init() {
	table.RegisterTable[*rows.AuditLog, *AuditLogTable]()
}

// AuditLogTable - table for github audit logs
type AuditLogTable struct {
	table.TableImpl[*rows.AuditLog, *AuditLogTableConfig, *config.GitHubConnection]
}

func (c *AuditLogTable) Identifier() string {
	return AuditLogTableIdentifier
}

func (c *AuditLogTable) SupportedSources() []*table.SourceMetadata[*rows.AuditLog] {
	return []*table.SourceMetadata[*rows.AuditLog]{
		{
			// TODO: We don't have any source for this plugin
			SourceName: constants.ArtifactSourceIdentifier,
			MapperFunc: mappers.NewAuditLogMapper,
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
