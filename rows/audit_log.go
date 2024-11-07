package rows

import (
	"github.com/turbot/tailpipe-plugin-sdk/enrichment"
	"strconv"
	"time"
)

/*
* TODOs:
* - Should IDs be strings or ints?
* - Should IP addresses be strings?
* - Are the CreatedAt and Timestamp properties the correct type? Should they be *time.Time or helpers.UnixMillis?
* - Should we preserve millisecond time fields as is and create new fields?
* - Should nested properties be broken out/flattened?
* - How best to add all possible fields? There are about 130 top level properties and 33 nested properties.
* - Do we use `Data` and `AdditionalFields`?
 */
type AuditLog struct {
	enrichment.CommonFields

	Action                                       *string    `json:"action,omitempty"`
	Actor                                        *string    `json:"actor,omitempty"`
	ActorID                                      *string    `json:"actor_id,omitempty"`
	ActorIP                                      *string    `json:"actor_ip,omitempty"`
	ActorIsBot                                   *bool      `json:"actor_is_bot,omitempty"`
	ActorLocationCountryCode                     *string    `json:"actor_location_country_code,omitempty"`
	Business                                     *string    `json:"business,omitempty"`
	CommentID                                    *string    `json:"comment_id,omitempty"`
	CreatedAt                                    *time.Time `json:"created_at,omitempty"`
	DocumentID                                   *string    `json:"document_id,omitempty"`
	EnvironmentName                              *string    `json:"environment_name,omitempty"`
	HashedToken                                  *string    `json:"hashed_token,omitempty"`
	OperationType                                *string    `json:"operation_type,omitempty"`
	Org                                          *string    `json:"org,omitempty"`
	OrgID                                        *string    `json:"org_id,omitempty"`
	ProgrammaticAccessType                       *string    `json:"programmatic_access_type,omitempty"`
	ProjectName                                  *string    `json:"project_name,omitempty"`
	PublicRepo                                   *bool      `json:"public_repo,omitempty"`
	PullRequestID                                *string    `json:"pull_request_id,omitempty"`
	PullRequestTitle                             *string    `json:"pull_request_title,omitempty"`
	PullRequestURL                               *string    `json:"pull_request_url,omitempty"`
	Repo                                         *string    `json:"repo,omitempty"`
	RepoID                                       *string    `json:"repo_id,omitempty"`
	RepositorySecurityConfigurationFailureReason *string    `json:"repository_security_configuration_failure_reason,omitempty"`
	RepositorySecurityConfigurationState         *string    `json:"repository_security_configuration_state,omitempty"`
	ReviewID                                     *string    `json:"review_id,omitempty"`
	ReviewerType                                 *string    `json:"reviewer_type,omitempty"`
	SecurityConfigurationID                      *string    `json:"security_configuration_id,omitempty"`
	SecurityConfigurationName                    *string    `json:"security_configuration_name,omitempty"`
	TimeISO8601                                  *string    `json:"time_iso_8601,omitempty"`
	Timestamp                                    *time.Time `json:"timestamp,omitempty"`
	TokenID                                      *string    `json:"token_id,omitempty"`
	Topic                                        *string    `json:"topic,omitempty"`
	User                                         *string    `json:"user,omitempty"`
	UserAgent                                    *string    `json:"user_agent,omitempty"`
	UserID                                       *string    `json:"user_id,omitempty"`
}

func NewAuditLog() *AuditLog {
	return &AuditLog{}
}

func (a *AuditLog) FromMap(in map[string]interface{}) {
	for key, value := range in {
		switch key {
		case "action":
			if strVal, ok := value.(string); ok {
				a.Action = &strVal
			}
		case "actor":
			if strVal, ok := value.(string); ok {
				a.Actor = &strVal
			}
		case "actor_id":
			if floatVal, ok := value.(float64); ok {
				strVal := strconv.FormatInt(int64(floatVal), 10)
				a.ActorID = &strVal
			}
		case "actor_ip":
			if strVal, ok := value.(string); ok {
				a.ActorIP = &strVal
			}
		case "actor_is_bot":
			if boolVal, ok := value.(bool); ok {
				a.ActorIsBot = &boolVal
			}
		case "actor_location_country_code":
			if strVal, ok := value.(string); ok {
				a.ActorLocationCountryCode = &strVal
			}
		case "business":
			if strVal, ok := value.(string); ok {
				a.Business = &strVal
			}
		case "comment_id":
			if floatVal, ok := value.(float64); ok {
				strVal := strconv.FormatInt(int64(floatVal), 10)
				a.CommentID = &strVal
			}
		case "created_at":
			if floatVal, ok := value.(float64); ok {
				t := time.Unix(0, int64(floatVal)*int64(time.Millisecond))
				a.CreatedAt = &t
			}
		case "_document_id":
			if strVal, ok := value.(string); ok {
				a.DocumentID = &strVal
			}
		case "environment_name":
			if strVal, ok := value.(string); ok {
				a.EnvironmentName = &strVal
			}
		case "hashed_token":
			if strVal, ok := value.(string); ok {
				a.HashedToken = &strVal
			}
		case "operation_type":
			if strVal, ok := value.(string); ok {
				a.OperationType = &strVal
			}
		case "org":
			if strVal, ok := value.(string); ok {
				a.Org = &strVal
			}
		case "org_id":
			if floatVal, ok := value.(float64); ok {
				strVal := strconv.FormatInt(int64(floatVal), 10)
				a.OrgID = &strVal
			}
		case "programmatic_access_type":
			if strVal, ok := value.(string); ok {
				a.ProgrammaticAccessType = &strVal
			}
		case "project_name":
			if strVal, ok := value.(string); ok {
				a.ProjectName = &strVal
			}
		case "public_repo":
			if boolVal, ok := value.(bool); ok {
				a.PublicRepo = &boolVal
			}
		case "pull_request_id":
			if floatVal, ok := value.(float64); ok {
				strVal := strconv.FormatInt(int64(floatVal), 10)
				a.PullRequestID = &strVal
			}
		case "pull_request_title":
			if strVal, ok := value.(string); ok {
				a.PullRequestTitle = &strVal
			}
		case "pull_request_url":
			if strVal, ok := value.(string); ok {
				a.PullRequestURL = &strVal
			}
		case "repo":
			if strVal, ok := value.(string); ok {
				a.Repo = &strVal
			}
		case "repo_id":
			if floatVal, ok := value.(float64); ok {
				strVal := strconv.FormatInt(int64(floatVal), 10)
				a.RepoID = &strVal
			}
		case "repository_security_configuration_failure_reason":
			if strVal, ok := value.(string); ok {
				a.RepositorySecurityConfigurationFailureReason = &strVal
			}
		case "repository_security_configuration_state":
			if strVal, ok := value.(string); ok {
				a.RepositorySecurityConfigurationState = &strVal
			}
		case "review_id":
			if floatVal, ok := value.(float64); ok {
				strVal := strconv.FormatInt(int64(floatVal), 10)
				a.ReviewID = &strVal
			}
		case "reviewer_type":
			if strVal, ok := value.(string); ok {
				a.ReviewerType = &strVal
			}
		case "security_configuration_id":
			if floatVal, ok := value.(float64); ok {
				strVal := strconv.FormatInt(int64(floatVal), 10)
				a.SecurityConfigurationID = &strVal
			}
		case "security_configuration_name":
			if strVal, ok := value.(string); ok {
				a.SecurityConfigurationName = &strVal
			}
		case "@timestamp":
			if floatVal, ok := value.(float64); ok {
				t := time.Unix(0, int64(floatVal)*int64(time.Millisecond))
				a.Timestamp = &t
				timeISO8601 := t.Format(time.RFC3339)
				a.TimeISO8601 = &timeISO8601
			}
		case "token_id":
			if floatVal, ok := value.(float64); ok {
				strVal := strconv.FormatInt(int64(floatVal), 10)
				a.TokenID = &strVal
			}
		case "topic":
			if strVal, ok := value.(string); ok {
				a.Topic = &strVal
			}
		case "user":
			if strVal, ok := value.(string); ok {
				a.User = &strVal
			}
		case "user_agent":
			if strVal, ok := value.(string); ok {
				a.UserAgent = &strVal
			}
		case "user_id":
			if floatVal, ok := value.(float64); ok {
				strVal := strconv.FormatInt(int64(floatVal), 10)
				a.UserID = &strVal
			}
		}
	}
}
