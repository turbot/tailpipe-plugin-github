package audit_log

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/turbot/tailpipe-plugin-sdk/schema"
)

/*
* TODOs:
* - Should IDs be strings or ints?
* - Should IP addresses be strings?
* - Are the CreatedAt and Timestamp properties the correct type? Should they be *time.Time or helpers.UnixMillis?
* - Should we preserve millisecond time fields as is and create new fields?
* - Should nested properties be broken out/flattened?
* - How best to add all possible fields? There are about 130 top level properties and 33 nested properties.
 */

type AuditLogBatch struct {
	Records []AuditLog `json:"Records"`
}

type AuditLog struct {
	schema.CommonFields

	Action                                         *string                 `json:"action,omitempty"`
	Actor                                          *string                 `json:"actor,omitempty"`
	ActorID                                        *int64                  `json:"actor_id,omitempty"`
	ActorIP                                        *string                 `json:"actor_ip,omitempty"`
	ActorLocation                                  *map[string]interface{} `json:"actor_location,omitempty" parquet:"type=JSON"`
	Business                                       *string                 `json:"business,omitempty"`
	BusinessID                                     *int64                  `json:"business_id,omitempty"`
	CreatedAt                                      *time.Time              `json:"created_at,omitempty"`
	CompletedAt                                    *time.Time              `json:"completed_at,omitempty"`
	ConfigWas                                      *Config                 `json:"config_was,omitempty"`
	Config                                         *Config                 `json:"config,omitempty"`
	DocumentID                                     *string                 `json:"document_id,omitempty"`
	HookID                                         *string                 `json:"hook_id,omitempty"`
	Active                                         *bool                   `json:"active,omitempty"`
	Team                                           *string                 `json:"team,omitempty"`
	Events                                         []string                `json:"events,omitempty"`
	Event                                          *string                 `json:"event,omitempty"`
	EventNameCategory                              *string                 `json:"name,omitempty"`
	TransportProtocolName                          *string                 `json:"transport_protocol_name,omitempty"`
	TransportProtocol                              *int64                  `json:"transport_protocol,omitempty"`
	Repository                                     *string                 `json:"repository,omitempty"`
	RepositoryPublic                               *bool                   `json:"repository_public,omitempty"`
	WasActive                                      *bool                   `json:"active_was,omitempty"`
	ContentType                                    *string                 `json:"content_type,omitempty"`
	DeployKeyFingerprint                           *string                 `json:"deploy_key_fingerprint,omitempty"`
	Emoji                                          *string                 `json:"emoji,omitempty"`
	Explanation                                    *string                 `json:"explanation,omitempty"`
	Fingerprint                                    *string                 `json:"fingerprint,omitempty"`
	LimitedAvailability                            *bool                   `json:"limited_availability,omitempty"`
	ActionMessage                                  *string                 `json:"message,omitempty"`
	OpensshPublicKey                               *string                 `json:"openssh_public_key,omitempty"`
	PreviousVisibility                             *string                 `json:"previous_visibility,omitempty"`
	ReadOnly                                       *bool                   `json:"read_only,omitempty"`
	TargetLogin                                    *string                 `json:"target_login,omitempty"`
	Branch                                         *string                 `json:"branch,omitempty"`
	CategoryType                                   *string                 `json:"category_type,omitempty"`
	ClientID                                       *string                 `json:"client_id,omitempty"`
	OperationType                                  *string                 `json:"operation_type,omitempty"`
	Conclusion                                     *string                 `json:"conclusion,omitempty"`
	ControllerAction                               *string                 `json:"controller_action,omitempty"`
	DeviceCookie                                   *string                 `json:"device_cookie,omitempty"`
	EnvironmentName                                *string                 `json:"environment_name,omitempty"`
	ForkSource                                     *string                 `json:"fork_source,omitempty"`
	ForkSourceID                                   *string                 `json:"fork_source_id,omitempty"`
	HeadBranch                                     *string                 `json:"head_branch,omitempty"`
	HeadSha                                        *string                 `json:"head_sha,omitempty"`
	IsHostedRunner                                 *bool                   `json:"is_hosted_runner,omitempty"`
	JobName                                        *string                 `json:"job_name,omitempty"`
	JobWorkflowRef                                 *string                 `json:"job_workflow_ref,omitempty"`
	ActionKey                                      *string                 `json:"key,omitempty"`
	HTTPMethod                                     *string                 `json:"method,omitempty"`
	ProgrammaticAccessType                         *string                 `json:"programmatic_access_type,omitempty"`
	PublicRepo                                     *bool                   `json:"public_repo,omitempty"`
	Referrer                                       *string                 `json:"referrer,omitempty"`
	RunAttempt                                     *int64                  `json:"run_attempt,omitempty"`
	RunNumber                                      *int64                  `json:"run_number,omitempty"`
	RunnerID                                       *string                 `json:"runner_id,omitempty"`
	RunnerGroupID                                  *string                 `json:"runner_group_id,omitempty"`
	RunnerGroupName                                *string                 `json:"runner_group_name,omitempty"`
	RunnerName                                     *string                 `json:"runner_name,omitempty"`
	ServerID                                       *string                 `json:"server_id,omitempty"`
	WorkflowStartedAt                              *time.Time              `json:"started_at,omitempty"`
	TriggerID                                      *string                 `json:"trigger_id,omitempty"`
	UserAgent                                      *string                 `json:"user_agent,omitempty"`
	UserProgrammaticAccessName                     *string                 `json:"user_programmatic_access_name,omitempty"`
	PullRequestUrl                                 *string                 `json:"pull_request_url,omitempty"`
	PullRequestTitle                               *string                 `json:"pull_request_title,omitempty"`
	PullRequestID                                  *string                 `json:"pull_request_id,omitempty"`
	OverriddenCodes                                []string                `json:"overridden_codes,omitempty"`
	ActionsCacheID                                 *string                 `json:"actions_cache_id,omitempty"`
	ActionsCacheKey                                *string                 `json:"actions_cache_key,omitempty"`
	ActionsCacheScope                              *string                 `json:"actions_cache_scope,omitempty"`
	ActionsCacheVersion                            *string                 `json:"actions_cache_version,omitempty"`
	AlertNumber                                    *int64                  `json:"alert_number,omitempty"`
	AllowDeletionsEnforcementLevel                 *string                 `json:"allow_deletions_enforcement_level,omitempty"`
	EnforcementLevel                               *string                 `json:"enforcement_level,omitempty"`
	LockAllowsFetchAndMerge                        *bool                   `json:"lock_allows_fetch_and_merge,omitempty"`
	AllowForcePushesEnforcementLevel               *string                 `json:"allow_force_pushes_enforcement_level,omitempty"`
	LockBranchEnforcementLevel                     *string                 `json:"lock_branch_enforcement_level,omitempty"`
	RequiredDeploymentsEnforcementLevel            *string                 `json:"required_deployments_enforcement_level,omitempty"`
	RequiredReviewThreadResolutionEnforcementLevel *string                 `json:"required_review_thread_resolution_enforcement_level,omitempty"`
	MergeMethod                                    *string                 `json:"merge_method,omitempty"`
	MergeQueueEnforcementLevel                     *string                 `json:"merge_queue_enforcement_level,omitempty"`
	NewRepoBaseRole                                *string                 `json:"new_repo_base_role,omitempty"`
	NewRepoPermission                              *string                 `json:"new_repo_permission,omitempty"`
	Permission                                     *string                 `json:"permission,omitempty"`
	OauthApplication                               *string                 `json:"oauth_application,omitempty"`
	OauthApplicationID                             *string                 `json:"oauth_application_id,omitempty"`
	OldRepoBaseRole                                *string                 `json:"old_repo_base_role,omitempty"`
	RulesetEnforcement                             *string                 `json:"ruleset_enforcement,omitempty"`
	RulesetID                                      *string                 `json:"ruleset_id,omitempty"`
	RulesetName                                    *string                 `json:"ruleset_name,omitempty"`
	RulesetSourceType                              *string                 `json:"ruleset_source_type,omitempty"`
	SourceVersion                                  *string                 `json:"source_version,omitempty"`
	Ecosystem                                      *string                 `json:"ecosystem,omitempty"`
	IsRepublished                                  *bool                   `json:"is_republished,omitempty"`
	PackageName                                    *string                 `json:"package,omitempty"`
	PackageVersion                                 *string                 `json:"version,omitempty"`
	Integration                                    *bool                   `json:"integration,omitempty"`
	ActorIsBot                                     *bool                   `json:"actor_is_bot,omitempty"`
	TargetVersion                                  *string                 `json:"target_version,omitempty"`
	AdminEnforced                                  *bool                   `json:"admin_enforced,omitempty"`
	RequiredApprovingReviewCount                   *int64                  `json:"required_approving_review_count,omitempty"`
	RequireCodeOwnerReview                         *bool                   `json:"require_code_owner_review,omitempty"`
	SignatureRequirementEnforcementLevel           *int64                  `json:"signature_requirement_enforcement_level,omitempty"`
	PackagePublished                               *map[string]interface{} `json:"package_published,omitempty"  parquet:"type=JSON"`
	PackageVersionPublished                        *map[string]interface{} `json:"package_version_published,omitempty"  parquet:"type=JSON"`
	ExternalIdentityNameID                         *string                 `json:"external_identity_name_id,omitempty"`
	ExternalIdentityUsername                       *string                 `json:"external_identity_username,omitempty"`
	HashedToken                                    *string                 `json:"hashed_token,omitempty"`
	Org                                            *string                 `json:"org,omitempty"`
	OrgID                                          *string                 `json:"org_id,omitempty"`
	Repo                                           *string                 `json:"repo,omitempty"`
	RepoID                                         *string                 `json:"repo_id,omitempty"`
	Timestamp                                      *time.Time              `json:"timestamp,omitempty"`
	TokenID                                        *int64                  `json:"token_id,omitempty"`
	ReviewID                                       *int64                  `json:"review_id,omitempty"`
	CommentID                                      *int64                  `json:"comment_id,omitempty"`
	WorkflowID                                     *int64                  `json:"workflow_id,omitempty"`
	WorkflowRunID                                  *int64                  `json:"workflow_run_id,omitempty"`
	AlertID                                        *int64                  `json:"alert_id,omitempty"`
	TokenScopes                                    *string                 `json:"token_scopes,omitempty"`
	User                                           *string                 `json:"user,omitempty"`
	Visibility                                     *string                 `json:"visibility,omitempty"`
	GhsaID                                         *string                 `json:"ghsa_id,omitempty"`
	Owner                                          *string                 `json:"owner,omitempty"`
	WorkflowRunTopic                               *string                 `json:"topic,omitempty"`
	ReviewerType                                   *string                 `json:"reviewer_type,omitempty"`
	CommitAfter                                    *string                 `json:"after,omitempty"`
	CommitBefore                                   *string                 `json:"before,omitempty"`
	ActionReasons                                  []ActionReasons         `json:"reasons,omitempty"`
	UserID                                         *int64                  `json:"user_id,omitempty"`
	AdditionalFields                               *map[string]interface{} `json:"additional_fields,omitempty" parquet:"type=JSON"`
}

type Config struct {
	ContentType *string `json:"content_type,omitempty"`
	InsecureSSL *bool   `json:"insecure_ssl,omitempty"`
	Url         *string `json:"url,omitempty"`
}

type ActorLocation struct {
	CountryCode *string `json:"country_code,omitempty"`
}

type ActionReasons struct {
	Code    *string `json:"code,omitempty"`
	Message *string `json:"message,omitempty"`
}

func (a *AuditLog) mapAuditLogFields(in map[string]interface{}) {
	// Create a map to hold dynamic fields
	dynamicFields := make(map[string]interface{})

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
		case "actor_ip":
			if strVal, ok := value.(string); ok {
				a.ActorIP = &strVal
			}
		case "actor_id":
			if floatVal, ok := value.(float64); ok {
				intVal := int64(floatVal)
				a.ActorID = &intVal
			}
		case "actor_location":
			if location, ok := value.(map[string]interface{}); ok {
				a.ActorLocation = &location
			}
		case "business":
			if strVal, ok := value.(string); ok {
				a.Business = &strVal
			}
		case "business_id":
			if floatVal, ok := value.(float64); ok {
				intVal := int64(floatVal)
				a.BusinessID = &intVal
			}
		case "created_at":
			if floatVal, ok := value.(float64); ok {
				t := time.Unix(0, int64(floatVal)*int64(time.Millisecond))
				a.CreatedAt = &t
			}
		case "completed_at":
			if floatVal, ok := value.(float64); ok {
				t := time.Unix(0, int64(floatVal)*int64(time.Millisecond))
				a.CreatedAt = &t
			}
		case "_document_id":
			if strVal, ok := value.(string); ok {
				a.DocumentID = &strVal
			}
		case "hook_id":
			if strVal, ok := value.(string); ok {
				a.HookID = &strVal
			}
		case "active":
			if boolVal, ok := value.(bool); ok {
				a.Active = &boolVal
			}
		case "team":
			if strVal, ok := value.(string); ok {
				a.Team = &strVal
			}
		case "event":
			if strVal, ok := value.(string); ok {
				a.Event = &strVal
			}
		case "reviewer_type":
			if strVal, ok := value.(string); ok {
				a.ReviewerType = &strVal
			}
		case "name":
			if strVal, ok := value.(string); ok {
				a.EventNameCategory = &strVal
			}
		case "permission":
			if strVal, ok := value.(string); ok {
				a.Permission = &strVal
			}
		case "transport_protocol_name":
			if strVal, ok := value.(string); ok {
				a.TransportProtocolName = &strVal
			}
		case "after":
			if strVal, ok := value.(string); ok {
				a.CommitAfter = &strVal
			}
		case "before":
			if strVal, ok := value.(string); ok {
				a.CommitBefore = &strVal
			}
		case "reasons":
			var reasons []ActionReasons
			jsonData, err := json.Marshal(value) // Convert back to JSON
			if err != nil {
				fmt.Errorf("failed to marshal []interface{} to JSON: %v", err)
			}
			err = json.Unmarshal(jsonData, &reasons)
			if err != nil {
				fmt.Errorf("failed to unmarshal JSON to []ActionReasons: %v", err)
			}

			a.ActionReasons = reasons
		case "transport_protocol":
			if floatVal, ok := value.(float64); ok {
				intVal := int64(floatVal)
				a.TransportProtocol = &intVal
			}
		case "repository":
			if strVal, ok := value.(string); ok {
				a.Repository = &strVal
			}
		case "ghsa_id":
			if strVal, ok := value.(string); ok {
				a.GhsaID = &strVal
			}
		case "owner":
			if strVal, ok := value.(string); ok {
				a.Owner = &strVal
			}
		case "topic":
			if strVal, ok := value.(string); ok {
				a.WorkflowRunTopic = &strVal
			}
		case "visibility":
			if strVal, ok := value.(string); ok {
				a.Visibility = &strVal
			}
		case "repository_public":
			if boolVal, ok := value.(bool); ok {
				a.RepositoryPublic = &boolVal
			}
		case "active_was":
			if boolVal, ok := value.(bool); ok {
				a.WasActive = &boolVal
			}
		case "content_type":
			if strVal, ok := value.(string); ok {
				a.ContentType = &strVal
			}
		case "deploy_key_fingerprint":
			if strVal, ok := value.(string); ok {
				a.DeployKeyFingerprint = &strVal
			}
		case "emoji":
			if strVal, ok := value.(string); ok {
				a.Emoji = &strVal
			}
		case "explanation":
			if strVal, ok := value.(string); ok {
				a.Explanation = &strVal
			}
		case "fingerprint":
			if strVal, ok := value.(string); ok {
				a.Fingerprint = &strVal
			}
		case "limited_availability":
			if boolVal, ok := value.(bool); ok {
				a.LimitedAvailability = &boolVal
			}
		case "message":
			if strVal, ok := value.(string); ok {
				a.ActionMessage = &strVal
			}
		case "openssh_public_key":
			if strVal, ok := value.(string); ok {
				a.OpensshPublicKey = &strVal
			}
		case "previous_visibility":
			if strVal, ok := value.(string); ok {
				a.PreviousVisibility = &strVal
			}
		case "read_only":
			if boolVal, ok := value.(bool); ok {
				a.ReadOnly = &boolVal
			}
		case "target_login":
			if strVal, ok := value.(string); ok {
				a.TargetLogin = &strVal
			}
		case "branch":
			if strVal, ok := value.(string); ok {
				a.Branch = &strVal
			}
		case "category_type":
			if strVal, ok := value.(string); ok {
				a.CategoryType = &strVal
			}
		case "client_id":
			if strVal, ok := value.(string); ok {
				a.ClientID = &strVal
			}
		case "operation_type":
			if strVal, ok := value.(string); ok {
				a.OperationType = &strVal
			}
		case "conclusion":
			if strVal, ok := value.(string); ok {
				a.Conclusion = &strVal
			}
		case "controller_action":
			if strVal, ok := value.(string); ok {
				a.ControllerAction = &strVal
			}
		case "device_cookie":
			if strVal, ok := value.(string); ok {
				a.DeviceCookie = &strVal
			}
		case "environment_name":
			if strVal, ok := value.(string); ok {
				a.EnvironmentName = &strVal
			}
		case "fork_source":
			if strVal, ok := value.(string); ok {
				a.ForkSource = &strVal
			}
		case "fork_source_id":
			if strVal, ok := value.(string); ok {
				a.ForkSourceID = &strVal
			}
		case "head_branch":
			if strVal, ok := value.(string); ok {
				a.HeadBranch = &strVal
			}
		case "head_sha":
			if strVal, ok := value.(string); ok {
				a.HeadSha = &strVal
			}
		case "is_hosted_runner":
			if boolVal, ok := value.(bool); ok {
				a.IsHostedRunner = &boolVal
			}
		case "job_name":
			if strVal, ok := value.(string); ok {
				a.JobName = &strVal
			}
		case "job_workflow_ref":
			if strVal, ok := value.(string); ok {
				a.JobWorkflowRef = &strVal
			}
		case "key":
			if strVal, ok := value.(string); ok {
				a.ActionKey = &strVal
			}
		case "method":
			if strVal, ok := value.(string); ok {
				a.HTTPMethod = &strVal
			}
		case "programmatic_access_type":
			if strVal, ok := value.(string); ok {
				a.ProgrammaticAccessType = &strVal
			}
		case "public_repo":
			if boolVal, ok := value.(bool); ok {
				a.PublicRepo = &boolVal
			}
		case "referrer":
			if strVal, ok := value.(string); ok {
				a.Referrer = &strVal
			}
		case "run_attempt":
			if floatVal, ok := value.(float64); ok {
				intVal := int64(floatVal)
				a.RunAttempt = &intVal
			}
		case "run_number":
			if floatVal, ok := value.(float64); ok {
				intVal := int64(floatVal)
				a.RunNumber = &intVal
			}
		case "runner_id":
			if strVal, ok := value.(string); ok {
				a.RunnerID = &strVal
			}
		case "runner_group_id":
			if strVal, ok := value.(string); ok {
				a.RunnerGroupID = &strVal
			}
		case "runner_group_name":
			if strVal, ok := value.(string); ok {
				a.RunnerGroupName = &strVal
			}
		case "runner_name":
			if strVal, ok := value.(string); ok {
				a.RunnerName = &strVal
			}
		case "server_id":
			if strVal, ok := value.(string); ok {
				a.ServerID = &strVal
			}
		case "started_at":
			if floatVal, ok := value.(float64); ok {
				t := time.Unix(0, int64(floatVal)*int64(time.Millisecond))
				a.WorkflowStartedAt = &t
			}
		case "trigger_id":
			if strVal, ok := value.(string); ok {
				a.TriggerID = &strVal
			}
		case "alert_id":
			if floatVal, ok := value.(float64); ok {
				intVal := int64(floatVal)
				a.AlertID = &intVal
			}
		case "workflow_id":
			if floatVal, ok := value.(float64); ok {
				intVal := int64(floatVal)
				a.WorkflowID = &intVal
			}
		case "workflow_run_id":
			if floatVal, ok := value.(float64); ok {
				intVal := int64(floatVal)
				a.WorkflowRunID = &intVal
			}
		case "user_agent":
			if strVal, ok := value.(string); ok {
				a.UserAgent = &strVal
			}
		case "user_programmatic_access_name":
			if strVal, ok := value.(string); ok {
				a.UserProgrammaticAccessName = &strVal
			}
		case "pull_request_url":
			if strVal, ok := value.(string); ok {
				a.PullRequestUrl = &strVal
			}
		case "pull_request_title":
			if strVal, ok := value.(string); ok {
				a.PullRequestTitle = &strVal
			}
		case "pull_request_id":
			if strVal, ok := value.(string); ok {
				a.PullRequestID = &strVal
			}
		case "overridden_codes":
			if strVal, ok := value.([]string); ok {
				a.OverriddenCodes = strVal
			}
		case "actions_cache_id":
			if strVal, ok := value.(string); ok {
				a.ActionsCacheID = &strVal
			}
		case "actions_cache_key":
			if strVal, ok := value.(string); ok {
				a.ActionsCacheKey = &strVal
			}
		case "actions_cache_scope":
			if strVal, ok := value.(string); ok {
				a.ActionsCacheScope = &strVal
			}
		case "actions_cache_version":
			if strVal, ok := value.(string); ok {
				a.ActionsCacheVersion = &strVal
			}
		case "alert_number":
			if floatVal, ok := value.(float64); ok {
				intVal := int64(floatVal)
				a.AlertNumber = &intVal
			}
		case "allow_deletions_enforcement_level":
			if strVal, ok := value.(string); ok {
				a.AllowDeletionsEnforcementLevel = &strVal
			}
		case "enforcement_level":
			if strVal, ok := value.(string); ok {
				a.EnforcementLevel = &strVal
			}
		case "lock_allows_fetch_and_merge":
			if boolVal, ok := value.(bool); ok {
				a.LockAllowsFetchAndMerge = &boolVal
			}
		case "allow_force_pushes_enforcement_level":
			if strVal, ok := value.(string); ok {
				a.AllowForcePushesEnforcementLevel = &strVal
			}
		case "lock_branch_enforcement_level":
			if strVal, ok := value.(string); ok {
				a.LockBranchEnforcementLevel = &strVal
			}
		case "required_deployments_enforcement_level":
			if strVal, ok := value.(string); ok {
				a.RequiredDeploymentsEnforcementLevel = &strVal
			}
		case "required_review_thread_resolution_enforcement_level":
			if strVal, ok := value.(string); ok {
				a.RequiredReviewThreadResolutionEnforcementLevel = &strVal
			}
		case "merge_method":
			if strVal, ok := value.(string); ok {
				a.MergeMethod = &strVal
			}
		case "merge_queue_enforcement_level":
			if strVal, ok := value.(string); ok {
				a.MergeQueueEnforcementLevel = &strVal
			}
		case "new_repo_base_role":
			if strVal, ok := value.(string); ok {
				a.NewRepoBaseRole = &strVal
			}
		case "new_repo_permission":
			if strVal, ok := value.(string); ok {
				a.NewRepoPermission = &strVal
			}
		case "oauth_application":
			if strVal, ok := value.(string); ok {
				a.OauthApplication = &strVal
			}
		case "oauth_application_id":
			if strVal, ok := value.(string); ok {
				a.OauthApplicationID = &strVal
			}
		case "old_repo_base_role":
			if strVal, ok := value.(string); ok {
				a.OldRepoBaseRole = &strVal
			}
		case "ruleset_enforcement":
			if strVal, ok := value.(string); ok {
				a.RulesetEnforcement = &strVal
			}
		case "ruleset_id":
			if strVal, ok := value.(string); ok {
				a.RulesetID = &strVal
			}
		case "ruleset_name":
			if strVal, ok := value.(string); ok {
				a.RulesetName = &strVal
			}
		case "ruleset_source_type":
			if strVal, ok := value.(string); ok {
				a.RulesetSourceType = &strVal
			}
		case "source_version":
			if strVal, ok := value.(string); ok {
				a.SourceVersion = &strVal
			}
		case "ecosystem":
			if strVal, ok := value.(string); ok {
				a.Ecosystem = &strVal
			}
		case "is_republished":
			if boolVal, ok := value.(bool); ok {
				a.IsRepublished = &boolVal
			}
		case "package":
			if strVal, ok := value.(string); ok {
				a.PackageName = &strVal
			}
		case "version":
			if strVal, ok := value.(string); ok {
				a.PackageVersion = &strVal
			}
		case "integration":
			if boolVal, ok := value.(bool); ok {
				a.Integration = &boolVal
			}
		case "actor_is_bot":
			if boolVal, ok := value.(bool); ok {
				a.ActorIsBot = &boolVal
			}
		case "target_version":
			if strVal, ok := value.(string); ok {
				a.TargetVersion = &strVal
			}
		case "admin_enforced":
			if boolVal, ok := value.(bool); ok {
				a.AdminEnforced = &boolVal
			}
		case "required_approving_review_count":
			if floatVal, ok := value.(float64); ok {
				intVal := int64(floatVal)
				a.RequiredApprovingReviewCount = &intVal
			}
		case "require_code_owner_review":
			if boolVal, ok := value.(bool); ok {
				a.RequireCodeOwnerReview = &boolVal
			}
		case "signature_requirement_enforcement_level":
			if floatVal, ok := value.(float64); ok {
				intVal := int64(floatVal)
				a.SignatureRequirementEnforcementLevel = &intVal
			}
		case "package_published":
			if mapVal, ok := value.(map[string]interface{}); ok {
				a.PackagePublished = &mapVal
			}
		case "package_version_published":
			if mapVal, ok := value.(map[string]interface{}); ok {
				a.PackageVersionPublished = &mapVal
			}
		case "external_identity_name_id":
			if strVal, ok := value.(string); ok {
				a.ExternalIdentityNameID = &strVal
			}
		case "external_identity_username":
			if strVal, ok := value.(string); ok {
				a.ExternalIdentityUsername = &strVal
			}
		case "hashed_token":
			if strVal, ok := value.(string); ok {
				a.HashedToken = &strVal
			}
		case "org":
			if strVal, ok := value.(string); ok {
				a.Org = &strVal
			}
		case "org_id":
			if strVal, ok := value.(string); ok {
				a.OrgID = &strVal
			}
		case "repo":
			if strVal, ok := value.(string); ok {
				a.Repo = &strVal
			}
		case "repo_id":
			if strVal, ok := value.(string); ok {
				a.RepoID = &strVal
			}
		case "@timestamp":
			if floatVal, ok := value.(float64); ok {
				t := time.Unix(0, int64(floatVal)*int64(time.Millisecond))
				a.Timestamp = &t
			}
		case "token_id":
			if floatVal, ok := value.(float64); ok {
				intVal := int64(floatVal)
				a.TokenID = &intVal
			}
		case "review_id":
			if floatVal, ok := value.(float64); ok {
				intVal := int64(floatVal)
				a.ReviewID = &intVal
			}
		case "comment_id":
			if floatVal, ok := value.(float64); ok {
				intVal := int64(floatVal)
				a.CommentID = &intVal
			}
		case "token_scopes":
			if strVal, ok := value.(string); ok {
				a.TokenScopes = &strVal
			}
		case "user":
			if strVal, ok := value.(string); ok {
				a.User = &strVal
			}
		case "user_id":
			if floatVal, ok := value.(float64); ok {
				intVal := int64(floatVal)
				a.UserID = &intVal
			}
		default:
			// Add unknown fields to dynamicFields
			dynamicFields[key] = value
		}
	}

	// Marshal dynamic fields into JSON and store in AdditionalFields
	if len(dynamicFields) > 0 {
		a.AdditionalFields = &dynamicFields
	}
}
