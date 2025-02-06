package audit_log

import (
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
			Mapper:     &AuditLogMapper{},
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
	if row.ActorIP != nil {
		row.TpIps = append(row.TpIps, *row.TpSourceIP)
	}
	if row.User != nil {
		row.TpUsernames = append(row.TpUsernames, *row.User)
	}

	if row.Org != nil {
		row.TpIndex = *row.Org
	} else {
		// Set the default tp_index value to "default" for events that do not contain the "org" property, such as packages.package_version_deleted and packages.package_version_published.
		row.TpIndex = "default"
	}
	
	row.TpDate = row.Timestamp.Truncate(24 * time.Hour)
	return row, nil
}

func (c *AuditLogTable) GetDescription() string {
	return "GitHub audit logs list events triggered by activities that affect your organization."
}
