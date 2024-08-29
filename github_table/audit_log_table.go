package github_table

import (
	"fmt"
	"strconv"
	"time"

	"github.com/rs/xid"
	"github.com/turbot/tailpipe-plugin-github/github_source"
	"github.com/turbot/tailpipe-plugin-github/github_types"
	"github.com/turbot/tailpipe-plugin-sdk/artifact_source"
	"github.com/turbot/tailpipe-plugin-sdk/enrichment"
	"github.com/turbot/tailpipe-plugin-sdk/helpers"
	"github.com/turbot/tailpipe-plugin-sdk/parse"
	"github.com/turbot/tailpipe-plugin-sdk/row_source"
	"github.com/turbot/tailpipe-plugin-sdk/table"
)

// AuditLogTable - table for github audit logs
type AuditLogTable struct {
	table.TableBase[*AuditLogTableConfig]
}

func (c *AuditLogTable) SupportedSources() []string {
	return []string{
		artifact_source.FileSystemSourceIdentifier,
	}
}

func NewAuditLogTable() table.Table {
	return &AuditLogTable{}
}

func (c *AuditLogTable) Identifier() string {
	return "github_audit_log"
}

func (c *AuditLogTable) GetSourceOptions(string) []row_source.RowSourceOption {
	/*
		if c.Config.LogFormat == nil {
			defaultLogFormat := `$remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent"`
			c.Config.LogFormat = &defaultLogFormat
		}

		return []row_source.RowSourceOption{
			artifact_source.WithRowPerLine(),
			artifact_source.WithMapper(github_source.NewAuditLogMapper(*c.Config.LogFormat)),
		}
	*/
	return []row_source.RowSourceOption{
		artifact_source.WithRowPerLine(),
		artifact_source.WithArtifactMapper(github_source.NewAuditLogMapper()),
	}
}

func (c *AuditLogTable) GetRowSchema() any {
	return github_types.AuditLog{}
}

func (c *AuditLogTable) GetConfigSchema() parse.Config {
	return &AuditLogTableConfig{}
}

// EnrichRow NOTE: Receives RawAuditLog & returns AuditLog
func (c *AuditLogTable) EnrichRow(row any, sourceEnrichmentFields *enrichment.CommonFields) (any, error) {
	// short-circuit for unexpected row type
	rawRecord, ok := row.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid row type: %T, expected map[string]interface{}", row)
	}

	// TODO: #validate ensure we have either `time_local` or `time_iso8601` field as without one of these we can't populate timestamp...

	// Build record and add any source enrichment fields
	var record github_types.AuditLog
	if sourceEnrichmentFields != nil {
		record.CommonFields = *sourceEnrichmentFields
	}

	for key, value := range rawRecord {
		switch key {
		case "action":
			if strVal, ok := value.(string); ok {
				record.Action = &strVal
			}
		case "actor":
			if strVal, ok := value.(string); ok {
				record.Actor = &strVal
			}
		case "actor_id":
			if floatVal, ok := value.(float64); ok {
				strVal := strconv.FormatInt(int64(floatVal), 10)
				record.ActorID = &strVal
			}
		case "actor_ip":
			if strVal, ok := value.(string); ok {
				record.ActorIP = &strVal
			}
		case "actor_is_bot":
			if boolVal, ok := value.(bool); ok {
				record.ActorIsBot = &boolVal
			}
		case "actor_location_country_code":
			if strVal, ok := value.(string); ok {
				record.ActorLocationCountryCode = &strVal
			}
		case "business":
			if strVal, ok := value.(string); ok {
				record.Business = &strVal
			}
		case "comment_id":
			if floatVal, ok := value.(float64); ok {
				strVal := strconv.FormatInt(int64(floatVal), 10)
				record.CommentID = &strVal
			}
		case "created_at":
			if floatVal, ok := value.(float64); ok {
				t := time.Unix(0, int64(floatVal)*int64(time.Millisecond))
				record.CreatedAt = &t
			}
		case "_document_id":
			if strVal, ok := value.(string); ok {
				record.DocumentID = &strVal
			}
		case "environment_name":
			if strVal, ok := value.(string); ok {
				record.EnvironmentName = &strVal
			}
		case "hashed_token":
			if strVal, ok := value.(string); ok {
				record.HashedToken = &strVal
			}
		case "operation_type":
			if strVal, ok := value.(string); ok {
				record.OperationType = &strVal
			}
		case "org":
			if strVal, ok := value.(string); ok {
				record.Org = &strVal
			}
		case "org_id":
			if floatVal, ok := value.(float64); ok {
				strVal := strconv.FormatInt(int64(floatVal), 10)
				record.OrgID = &strVal
			}
		case "programmatic_access_type":
			if strVal, ok := value.(string); ok {
				record.ProgrammaticAccessType = &strVal
			}
		case "project_name":
			if strVal, ok := value.(string); ok {
				record.ProjectName = &strVal
			}
		case "public_repo":
			if boolVal, ok := value.(bool); ok {
				record.PublicRepo = &boolVal
			}
		case "pull_request_id":
			if floatVal, ok := value.(float64); ok {
				strVal := strconv.FormatInt(int64(floatVal), 10)
				record.PullRequestID = &strVal
			}
		case "pull_request_title":
			if strVal, ok := value.(string); ok {
				record.PullRequestTitle = &strVal
			}
		case "pull_request_url":
			if strVal, ok := value.(string); ok {
				record.PullRequestURL = &strVal
			}
		case "repo":
			if strVal, ok := value.(string); ok {
				record.Repo = &strVal
			}
		case "repo_id":
			if floatVal, ok := value.(float64); ok {
				strVal := strconv.FormatInt(int64(floatVal), 10)
				record.RepoID = &strVal
			}
		case "repository_security_configuration_failure_reason":
			if strVal, ok := value.(string); ok {
				record.RepositorySecurityConfigurationFailureReason = &strVal
			}
		case "repository_security_configuration_state":
			if strVal, ok := value.(string); ok {
				record.RepositorySecurityConfigurationState = &strVal
			}
		case "review_id":
			if floatVal, ok := value.(float64); ok {
				strVal := strconv.FormatInt(int64(floatVal), 10)
				record.ReviewID = &strVal
			}
		case "reviewer_type":
			if strVal, ok := value.(string); ok {
				record.ReviewerType = &strVal
			}
		case "security_configuration_id":
			if floatVal, ok := value.(float64); ok {
				strVal := strconv.FormatInt(int64(floatVal), 10)
				record.SecurityConfigurationID = &strVal
			}
		case "security_configuration_name":
			if strVal, ok := value.(string); ok {
				record.SecurityConfigurationName = &strVal
			}
		case "@timestamp":
			if floatVal, ok := value.(float64); ok {
				t := time.Unix(0, int64(floatVal)*int64(time.Millisecond))
				record.Timestamp = &t
				timeISO8601 := t.Format(time.RFC3339)
				record.TimeISO8601 = &timeISO8601
			}
		case "token_id":
			if floatVal, ok := value.(float64); ok {
				strVal := strconv.FormatInt(int64(floatVal), 10)
				record.TokenID = &strVal
			}
		case "topic":
			if strVal, ok := value.(string); ok {
				record.Topic = &strVal
			}
		case "user":
			if strVal, ok := value.(string); ok {
				record.User = &strVal
			}
		case "user_agent":
			if strVal, ok := value.(string); ok {
				record.UserAgent = &strVal
			}
		case "user_id":
			if floatVal, ok := value.(float64); ok {
				strVal := strconv.FormatInt(int64(floatVal), 10)
				record.UserID = &strVal
			}
		}
	}

	// Record standardization
	record.TpID = xid.New().String()
	record.TpIngestTimestamp = helpers.UnixMillis(time.Now().UnixNano() / int64(time.Millisecond))
	record.TpSourceType = "github_audit_log" // TODO: #refactor move to source?

	// Hive Fields
	record.TpTable = c.Identifier()
	record.TpIndex = c.Identifier() // TODO: #refactor figure out how to get connection
	record.TpYear = int32(record.Timestamp.Year())
	record.TpMonth = int32(record.Timestamp.Month())
	record.TpDay = int32(record.Timestamp.Day())

	return record, nil
}
