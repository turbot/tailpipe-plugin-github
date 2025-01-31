package audit_log

import (
	"fmt"
	"time"

	"github.com/rs/xid"
	"github.com/turbot/tailpipe-plugin-sdk/artifact_source"
	"github.com/turbot/tailpipe-plugin-sdk/constants"
	"github.com/turbot/tailpipe-plugin-sdk/row_source"
	"github.com/turbot/tailpipe-plugin-sdk/schema"
	"github.com/turbot/tailpipe-plugin-sdk/table"
)

const AuditLogTableIdentifier = "github_audit_log"

// AuditLogTable - table for GitHub audit logs
type AuditLogTable struct{}

// Identifier implements table.Table
func (t *AuditLogTable) Identifier() string {
	return AuditLogTableIdentifier
}

func (c *AuditLogTable) GetSourceMetadata() []*table.SourceMetadata[*AuditLog] {
	return []*table.SourceMetadata[*AuditLog]{
		{
			SourceName: constants.ArtifactSourceIdentifier,
			Mapper: &AuditLogMapper{},
			Options: []row_source.RowSourceOption{
				artifact_source.WithRowPerLine(),
			},
		},
	}
}

// EnrichRow implements table.Table
func (c *AuditLogTable) EnrichRow(row *AuditLog, sourceEnrichmentFields schema.SourceEnrichment) (*AuditLog, error) {
	row.CommonFields = sourceEnrichmentFields.CommonFields

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
	case row.OrgID != nil:
		row.TpIndex = *row.OrgID
	case row.UserID != nil:
		row.TpIndex = fmt.Sprintf("%d", *row.UserID)
	default:
		row.TpIndex = "default"
	}
	row.TpDate = row.Timestamp.Truncate(24 * time.Hour)
	return row, nil
}

func (c *AuditLogTable) GetDescription() string {
	return "GitHub Audit logs capture API activity and user actions within your GiHub account."
}
