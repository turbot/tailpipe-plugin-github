package github_types

import (
	"github.com/turbot/tailpipe-plugin-sdk/enrichment"
	"time"
)

/*
* TODOs:
* - Should IDs be strings or ints?
* - Should IP addresses be strings?
* - Are the CreatedAt and Timestamp properties the correct type? Should they be *time.Time or helpers.UnixMillis?
* - Should nested properties be broken out?
* - How best to add all possible fields? There are about 130 top level properties and 33 nested properties.
 */
type AuditLog struct {
	enrichment.CommonFields

	Action                                       *string    `json:"action,omitempty"`
	Actor                                        *string    `json:"actor,omitempty"`
	ActorID                                      *int       `json:"actor_id,omitempty"`
	ActorIP                                      *string    `json:"actor_ip,omitempty"`
	ActorIsBot                                   *bool      `json:"actor_is_bot,omitempty"`
	ActorLocationCountryCode                     *string    `json:"actor_location_country_code,omitempty"`
	Business                                     *string    `json:"business,omitempty"`
	CommentID                                    *int       `json:"comment_id,omitempty"`
	CreatedAt                                    *time.Time `json:"created_at,omitempty"`
	DocumentID                                   *string    `json:"document_id,omitempty"`
	HashedToken                                  *string    `json:"hashed_token,omitempty"`
	OperationType                                *string    `json:"operation_type,omitempty"`
	Org                                          *string    `json:"org,omitempty"`
	OrgID                                        *int       `json:"org_id,omitempty"`
	ProgrammaticAccessType                       *string    `json:"programmatic_access_type,omitempty"`
	PublicRepo                                   *bool      `json:"public_repo,omitempty"`
	PullRequestID                                *int       `json:"pull_request_id,omitempty"`
	PullRequestTitle                             *string    `json:"pull_request_title,omitempty"`
	PullRequestURL                               *string    `json:"pull_request_url,omitempty"`
	Repo                                         *string    `json:"repo,omitempty"`
	RepoID                                       *int       `json:"repo_id,omitempty"`
	RepositorySecurityConfigurationFailureReason *string    `json:"repository_security_configuration_failure_reason,omitempty"`
	RepositorySecurityConfigurationState         *string    `json:"repository_security_configuration_state,omitempty"`
	ReviewID                                     *int       `json:"review_id,omitempty"`
	ReviewerType                                 *string    `json:"reviewer_type,omitempty"`
	SecurityConfigurationID                      *int       `json:"security_configuration_id,omitempty"`
	SecurityConfigurationName                    *string    `json:"security_configuration_name,omitempty"`
	TimeISO8601                                  *string    `json:"time_iso_8601,omitempty"`
	Timestamp                                    *time.Time `json:"timestamp,omitempty"`
	TokenID                                      *int       `json:"token_id,omitempty"`
	Topic                                        *string    `json:"topic,omitempty"`
	User                                         *string    `json:"user,omitempty"`
	UserAgent                                    *string    `json:"user_agent,omitempty"`
	UserID                                       *int       `json:"user_id,omitempty"`
}
