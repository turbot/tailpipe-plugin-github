package github_collection

import (
	"fmt"
	"github.com/turbot/tailpipe-plugin-sdk/hcl"
	"time"

	"github.com/rs/xid"
	"github.com/turbot/tailpipe-plugin-github/github_source"
	"github.com/turbot/tailpipe-plugin-github/github_types"
	"github.com/turbot/tailpipe-plugin-sdk/artifact_source"
	"github.com/turbot/tailpipe-plugin-sdk/collection"
	"github.com/turbot/tailpipe-plugin-sdk/enrichment"
	"github.com/turbot/tailpipe-plugin-sdk/helpers"
	"github.com/turbot/tailpipe-plugin-sdk/row_source"
)

// AuditLogCollection - collection for github audit logs
type AuditLogCollection struct {
	collection.CollectionBase[*AuditLogCollectionConfig]
}

func (c *AuditLogCollection) SupportedSources() []string {
	return []string{
		artifact_source.FileSystemSourceIdentifier,
	}
}

func NewAuditLogCollection() collection.Collection {
	return &AuditLogCollection{}
}

func (c *AuditLogCollection) Identifier() string {
	return "github_audit_log"
}

func (c *AuditLogCollection) GetSourceOptions() []row_source.RowSourceOption {
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
		artifact_source.WithMapper(github_source.NewAuditLogMapper()),
	}
}

func (c *AuditLogCollection) GetRowSchema() any {
	return github_types.AuditLog{}
}

func (c *AuditLogCollection) GetConfigSchema() hcl.Config {
	return &AuditLogCollectionConfig{}
}

// EnrichRow NOTE: Receives RawAuditLog & returns AuditLog
func (c *AuditLogCollection) EnrichRow(row any, sourceEnrichmentFields *enrichment.CommonFields) (any, error) {
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
					record.Action, _ = value.(*string)
			case "actor":
					record.Actor, _ = value.(*string)
			case "actor_id":
					if intVal, ok := value.(int); ok {
							record.ActorID = &intVal
					}
			case "actor_ip":
					record.ActorIP, _ = value.(*string)
			case "actor_is_bot":
					if boolVal, ok := value.(bool); ok {
							record.ActorIsBot = &boolVal
					}
			case "actor_location_country_code":
					record.ActorLocationCountryCode, _ = value.(*string)
			case "business":
					record.Business, _ = value.(*string)
			case "comment_id":
					if intVal, ok := value.(int); ok {
							record.CommentID = &intVal
					}
			case "created_at":
				if intVal, ok := value.(int64); ok {
						t := time.Unix(0, intVal*int64(time.Millisecond))
						record.CreatedAt = &t
				}
			case "_document_id":
					record.DocumentID, _ = value.(*string)
			case "hashed_token":
					record.HashedToken, _ = value.(*string)
			case "operation_type":
					record.OperationType, _ = value.(*string)
			case "org":
					record.Org, _ = value.(*string)
			case "org_id":
					if intVal, ok := value.(int); ok {
							record.OrgID = &intVal
					}
			case "programmatic_access_type":
					record.ProgrammaticAccessType, _ = value.(*string)
			case "public_repo":
					if boolVal, ok := value.(bool); ok {
							record.PublicRepo = &boolVal
					}
			case "pull_request_id":
					if intVal, ok := value.(int); ok {
							record.PullRequestID = &intVal
					}
			case "pull_request_title":
					record.PullRequestTitle, _ = value.(*string)
			case "pull_request_url":
					record.PullRequestURL, _ = value.(*string)
			case "repo":
					record.Repo, _ = value.(*string)
			case "repo_id":
					if intVal, ok := value.(int); ok {
							record.RepoID = &intVal
					}
			case "repository_security_configuration_failure_reason":
					record.RepositorySecurityConfigurationFailureReason, _ = value.(*string)
			case "repository_security_configuration_state":
					record.RepositorySecurityConfigurationState, _ = value.(*string)
			case "review_id":
					if intVal, ok := value.(int); ok {
							record.ReviewID = &intVal
					}
			case "reviewer_type":
					record.ReviewerType, _ = value.(*string)
			case "security_configuration_id":
					if intVal, ok := value.(int); ok {
							record.SecurityConfigurationID = &intVal
					}
			case "security_configuration_name":
					record.SecurityConfigurationName, _ = value.(*string)
			case "@timestamp":
				if intVal, ok := value.(int64); ok {
					t := time.Unix(0, intVal*int64(time.Millisecond))
					record.Timestamp = &t
					timeISO8601 := t.Format(time.RFC3339)
					record.TimeISO8601 = &timeISO8601
				}
			case "token_id":
				if intVal, ok := value.(int); ok {
						record.TokenID = &intVal
				}
			case "topic":
				record.Topic, _ = value.(*string)
			case "user":
				record.User, _ = value.(*string)
			case "user_agent":
				record.UserAgent, _ = value.(*string)
			case "user_id":
				if intVal, ok := value.(int); ok {
						record.UserID = &intVal
				}
		}
	}

	// Record standardization
	record.TpID = xid.New().String()
	record.TpIngestTimestamp = helpers.UnixMillis(time.Now().UnixNano() / int64(time.Millisecond))
	record.TpSourceType = "github_audit_log" // TODO: #refactor move to source?

	// Hive Fields
	record.TpCollection = c.Identifier()
	record.TpConnection = c.Identifier() // TODO: #refactor figure out how to get connection
	// TODO: Re-add these once Timestamp works
	record.TpYear = int32(1)
	record.TpMonth = int32(1)
	record.TpDay = int32(1)
	//record.TpYear = int32(record.Timestamp.Year())
	//record.TpMonth = int32(record.Timestamp.Month())
	//record.TpDay = int32(record.Timestamp.Day())

	return record, nil
}
