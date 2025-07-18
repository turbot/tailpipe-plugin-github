package security_log

import (
	"time"

	"github.com/rs/xid"
	"github.com/turbot/tailpipe-plugin-sdk/artifact_source"
	"github.com/turbot/tailpipe-plugin-sdk/constants"
	"github.com/turbot/tailpipe-plugin-sdk/row_source"
	"github.com/turbot/tailpipe-plugin-sdk/schema"
	"github.com/turbot/tailpipe-plugin-sdk/table"
)

const SecurityLogTableIdentifier = "github_security_log"

// SecurityLogTable - table for GitHub security logs
type SecurityLogTable struct{}

// Identifier implements table.Table
func (t *SecurityLogTable) Identifier() string {
	return SecurityLogTableIdentifier
}

func (t *SecurityLogTable) GetSourceMetadata() ([]*table.SourceMetadata[*SecurityLog], error) {
	return []*table.SourceMetadata[*SecurityLog]{
		{
			SourceName: constants.ArtifactSourceIdentifier,
			Mapper:     &SecurityLogMapper{},
			Options: []row_source.RowSourceOption{
				artifact_source.WithRowPerLine(),
			},
		},
	}, nil
}

// EnrichRow implements table.Table
func (t *SecurityLogTable) EnrichRow(row *SecurityLog, sourceEnrichmentFields schema.SourceEnrichment) (*SecurityLog, error) {
	row.CommonFields = sourceEnrichmentFields.CommonFields

	// Record standardization
	row.TpID = xid.New().String()

	// Parse timestamp from the @timestamp field
	if row.Timestamp != nil {
		if timestamp, err := time.Parse(time.RFC3339, row.Timestamp.Format(time.RFC3339)); err == nil {
			row.TpTimestamp = timestamp
		} else {
			// Fallback to current time if parsing fails
			row.TpTimestamp = time.Now()
		}
	} else {
		row.TpTimestamp = time.Now()
	}

	row.TpIngestTimestamp = time.Now()

	// Extract usernames
	if row.Actor != nil {
		row.TpUsernames = append(row.TpUsernames, *row.Actor)
	}
	if row.User != nil {
		row.TpUsernames = append(row.TpUsernames, *row.User)
	}

	// Note: Security logs don't typically have direct IP fields like audit logs
	// We would need to extract from additional fields if available

	row.TpDate = row.TpTimestamp.Truncate(24 * time.Hour)
	return row, nil
}

func (t *SecurityLogTable) GetDescription() string {
	return "GitHub security logs list events triggered by activities that affect your personal account security."
}
