package security_log

import (
	"fmt"
	"time"

	"github.com/turbot/tailpipe-plugin-sdk/schema"
)

// https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/security-log-events
type SecurityLog struct {
	schema.CommonFields

	// Common field for all events
	Timestamp  *time.Time `json:"timestamp"`
	DocumentId *string    `json:"document_id"`
	Action     *string    `json:"action"`

	// Other fields for events
	ActionsCacheId              *string           `json:"actions_cache_id,omitempty"`
	ActionsCacheKey             *string           `json:"actions_cache_key,omitempty"`
	ActionsCacheScope           *string           `json:"actions_cache_scope,omitempty"`
	ActionsCacheVersion         *string           `json:"actions_cache_version,omitempty"`
	Active                      *string           `json:"active,omitempty"`
	ActiveWas                   *string           `json:"active_was,omitempty"`
	Actor                       *string           `json:"actor,omitempty"`
	ActorId                     *int64            `json:"actor_id,omitempty"`
	ActorIsBot                  *bool             `json:"actor_is_bot,omitempty"`
	ApplicationClientId         *string           `json:"application_client_id,omitempty"`
	Approvers                   *string           `json:"approvers,omitempty"`
	ApproversWas                *string           `json:"approvers_was,omitempty"`
	BlockedUser                 *string           `json:"blocked_user,omitempty"`
	Branch                      *string           `json:"branch,omitempty"`
	Business                    *string           `json:"business,omitempty"`
	BusinessId                  *int64            `json:"business_id,omitempty"`
	CanAdminsBypass             *string           `json:"can_admins_bypass,omitempty"`
	Category                    *string           `json:"category,omitempty"`
	Cname                       *string           `json:"cname,omitempty"`
	Collaborator                *string           `json:"collaborator,omitempty"`
	CollaboratorType            *string           `json:"collaborator_type,omitempty"`
	ContentType                 *string           `json:"content_type,omitempty"`
	CreatedAt                   *time.Time        `json:"created_at,omitempty"`
	DevcontainerPath            *string           `json:"devcontainer_path,omitempty"`
	Domain                      *string           `json:"domain,omitempty"`
	Email                       *string           `json:"email,omitempty"`
	Emoji                       *string           `json:"emoji,omitempty"`
	EndDate                     *time.Time        `json:"end_date,omitempty"`
	EnvironmentName             *string           `json:"environment_name,omitempty"`
	Events                      []string          `json:"events,omitempty"`
	EventsWere                  *string           `json:"events_were,omitempty"`
	Explanation                 *string           `json:"explanation,omitempty"`
	Filename                    *string           `json:"filename,omitempty"`
	Fingerprint                 *string           `json:"fingerprint,omitempty"`
	GistId                      *string           `json:"gist_id,omitempty"`
	HashedToken                 *string           `json:"hashed_token,omitempty"`
	HeadBranch                  *string           `json:"head_branch,omitempty"`
	HeadSha                     *string           `json:"head_sha,omitempty"`
	HookId                      *string           `json:"hook_id,omitempty"`
	Integration                 *string           `json:"integration,omitempty"`
	Invitee                     *string           `json:"invitee,omitempty"`
	Inviter                     *string           `json:"inviter,omitempty"`
	Key                         *string           `json:"key,omitempty"`
	Limit                       *string           `json:"limit,omitempty"`
	LimitedAvailability         *string           `json:"limited_availability,omitempty"`
	MachineType                 *string           `json:"machine_type,omitempty"`
	Manager                     *string           `json:"manager,omitempty"`
	MarketplaceListing          *string           `json:"marketplace_listing,omitempty"`
	MergeQueueEnforcementLevel  *string           `json:"merge_queue_enforcement_level,omitempty"`
	Message                     *string           `json:"message,omitempty"`
	Name                        *string           `json:"name,omitempty"`
	NewAccess                   *string           `json:"new_access,omitempty"`
	NewNwo                      *string           `json:"new_nwo,omitempty"`
	NewPolicy                   *string           `json:"new_policy,omitempty"`
	NewRepoBaseRole             *string           `json:"new_repo_base_role,omitempty"`
	NewRepoPermission           *string           `json:"new_repo_permission,omitempty"`
	NewValue                    *string           `json:"new_value,omitempty"`
	Nickname                    *string           `json:"nickname,omitempty"`
	OauthApplication            *string           `json:"oauth_application,omitempty"`
	OauthApplicationId          *string           `json:"oauth_application_id,omitempty"`
	OauthApplicationName        *string           `json:"oauth_application_name,omitempty"`
	OldAccess                   *string           `json:"old_access,omitempty"`
	OldBaseRole                 *string           `json:"old_base_role,omitempty"`
	OldCname                    *string           `json:"old_cname,omitempty"`
	OldLogin                    *string           `json:"old_login,omitempty"`
	OldName                     *string           `json:"old_name,omitempty"`
	OldPermission               *string           `json:"old_permission,omitempty"`
	OldPolicy                   *string           `json:"old_policy,omitempty"`
	OldProjectRole              *string           `json:"old_project_role,omitempty"`
	OldRepoBaseRole             *string           `json:"old_repo_base_role,omitempty"`
	OldRepoPermission           *string           `json:"old_repo_permission,omitempty"`
	OldUser                     *string           `json:"old_user,omitempty"`
	OperationType               *string           `json:"operation_type,omitempty"`
	Org                         OrganizationName  `json:"org,omitempty"`
	OrgId                       OrganizationId    `json:"org_id,omitempty"`
	OriginRepository            *string           `json:"origin_repository,omitempty"`
	Owner                       *string           `json:"owner,omitempty"`
	OwnerType                   *string           `json:"owner_type,omitempty"`
	PasskeyNickname             *string           `json:"passkey_nickname,omitempty"`
	PatreonEmail                *string           `json:"patreon_email,omitempty"`
	PatreonUsername             *string           `json:"patreon_username,omitempty"`
	Permissions                 map[string]string `json:"permissions,omitempty"`
	PermissionsAdded            map[string]string `json:"permissions_added,omitempty"`
	PermissionsUnchanged        map[string]string `json:"permissions_unchanged,omitempty"`
	PermissionsUpgraded         map[string]string `json:"permissions_upgraded,omitempty"`
	Policy                      *string           `json:"policy,omitempty"`
	PreventSelfReview           *string           `json:"prevent_self_review,omitempty"`
	PreviousVisibility          *string           `json:"previous_visibility,omitempty"`
	PrimaryCategory             *string           `json:"primary_category,omitempty"`
	ProgrammaticAccessType      *string           `json:"programmatic_access_type,omitempty"`
	ProjectId                   *string           `json:"project_id,omitempty"`
	ProjectKind                 *string           `json:"project_kind,omitempty"`
	ProjectName                 *string           `json:"project_name,omitempty"`
	ProjectRole                 *string           `json:"project_role,omitempty"`
	PublicProject               *string           `json:"public_project,omitempty"`
	PublicRepo                  *string           `json:"public_repo,omitempty"`
	PullRequestId               *string           `json:"pull_request_id,omitempty"`
	Query                       *string           `json:"query,omitempty"`
	ReadOnly                    *string           `json:"read_only,omitempty"`
	Repo                        *string           `json:"repo,omitempty"`
	RepoId                      *int64            `json:"repo_id,omitempty"`
	RepoWas                     *string           `json:"repo_was,omitempty"`
	RepositoriesAdded           []int64           `json:"repositories_added,omitempty"`
	RepositoriesAddedNames      []string          `json:"repositories_added_names,omitempty"`
	RepositoriesRemoved         *string           `json:"repositories_removed,omitempty"`
	RepositoriesRemovedNames    *string           `json:"repositories_removed_names,omitempty"`
	Repository                  *string           `json:"repository,omitempty"`
	RepositoryId                *int64            `json:"repository_id,omitempty"`
	RepositorySelection         *string           `json:"repository_selection,omitempty"`
	RequestAccessSecurityHeader *string           `json:"request_access_security_header,omitempty"`
	RequestCategory             *string           `json:"request_category,omitempty"`
	RequestId                   *string           `json:"request_id,omitempty"`
	RequestMethod               *string           `json:"request_method,omitempty"`
	RequestedAt                 *time.Time        `json:"requested_at,omitempty"`
	Requester                   *string           `json:"requester,omitempty"`
	RequesterId                 *string           `json:"requester_id,omitempty"`

	// Present in personal access token events
	Repositories []int64 `json:"repositories,omitempty"`

	// Present in environment-related events
	EnvironmentId *int64 `json:"environment_id,omitempty"`

	// Present in events with value changes
	OldValue                        *string                  `json:"old_value,omitempty"`
	RulesetBypassActors             *string                  `json:"ruleset_bypass_actors,omitempty"`
	RulesetBypassActorsAdded        *string                  `json:"ruleset_bypass_actors_added,omitempty"`
	RulesetBypassActorsDeleted      *string                  `json:"ruleset_bypass_actors_deleted,omitempty"`
	RulesetBypassActorsUpdated      *string                  `json:"ruleset_bypass_actors_updated,omitempty"`
	RulesetConditions               []map[string]interface{} `json:"ruleset_conditions,omitempty"`
	RulesetConditionsAdded          *string                  `json:"ruleset_conditions_added,omitempty"`
	RulesetConditionsDeleted        *string                  `json:"ruleset_conditions_deleted,omitempty"`
	RulesetConditionsUpdated        *string                  `json:"ruleset_conditions_updated,omitempty"`
	RulesetEnforcement              *string                  `json:"ruleset_enforcement,omitempty"`
	RulesetId                       *int64                   `json:"ruleset_id,omitempty"`
	RulesetName                     *string                  `json:"ruleset_name,omitempty"`
	RulesetOldEnforcement           *string                  `json:"ruleset_old_enforcement,omitempty"`
	RulesetOldName                  *string                  `json:"ruleset_old_name,omitempty"`
	RulesetRules                    []map[string]interface{} `json:"ruleset_rules,omitempty"`
	RulesetRulesAdded               *string                  `json:"ruleset_rules_added,omitempty"`
	RulesetRulesDeleted             *string                  `json:"ruleset_rules_deleted,omitempty"`
	RulesetRulesUpdated             *string                  `json:"ruleset_rules_updated,omitempty"`
	RulesetSourceType               *string                  `json:"ruleset_source_type,omitempty"`
	RunNumber                       *string                  `json:"run_number,omitempty"`
	SeatAssignment                  *string                  `json:"seat_assignment,omitempty"`
	SecondaryCategory               *string                  `json:"secondary_category,omitempty"`
	SponsorsListingId               *string                  `json:"sponsors_listing_id,omitempty"`
	StartDate                       *time.Time               `json:"start_date,omitempty"`
	StartedAt                       *string                  `json:"started_at,omitempty"`
	State                           *string                  `json:"state,omitempty"`
	Team                            *string                  `json:"team,omitempty"`
	Title                           *string                  `json:"title,omitempty"`
	TokenId                         *int64                   `json:"token_id,omitempty"`
	TokenScopes                     *string                  `json:"token_scopes,omitempty"`
	Tool                            *string                  `json:"tool,omitempty"`
	Topic                           *string                  `json:"topic,omitempty"`
	TransferFrom                    *string                  `json:"transfer_from,omitempty"`
	TransferFromId                  *string                  `json:"transfer_from_id,omitempty"`
	TransferFromType                *string                  `json:"transfer_from_type,omitempty"`
	TransferTo                      *string                  `json:"transfer_to,omitempty"`
	TransferToId                    *string                  `json:"transfer_to_id,omitempty"`
	TransferToType                  *string                  `json:"transfer_to_type,omitempty"`
	TriggerId                       *string                  `json:"trigger_id,omitempty"`
	UpdatedAccessPolicy             *string                  `json:"updated_access_policy,omitempty"`
	User                            *string                  `json:"user,omitempty"`
	UserAgent                       *string                  `json:"user_agent,omitempty"`
	UserId                          *int64                   `json:"user_id,omitempty"`
	UserProgrammaticAccessId        *string                  `json:"user_programmatic_access_id,omitempty"`
	UserProgrammaticAccessName      *string                  `json:"user_programmatic_access_name,omitempty"`
	UserProgrammaticAccessRequestId *int64                   `json:"user_programmatic_access_request_id,omitempty"`
	Visibility                      *string                  `json:"visibility,omitempty"`
	WorkflowId                      *int64                   `json:"workflow_id,omitempty"`
	WorkflowRunId                   *string                  `json:"workflow_run_id,omitempty"`
}

// We can have org, and org_id value slice of int64 or int64
// - For oauth_authorization.create, 	user.failed_login we will have slice of int64
// > select distinct org from github_security_log
// +---------------------------------------------------------------+
// | org                                                           |
// +---------------------------------------------------------------+
// | map[name:turbotio names:<nil>]                                |
// | map[name:pro-cloud-49 names:<nil>]                            |
// | map[name:turbot names:<nil>]                                  |
// | map[name:<nil> names:[turbotio turbot pro-cloud-49 do-enter]] |
// | map[name:<nil> names:<nil>]                                   |
// | map[name:<nil> names:[]]                                      |
// +---------------------------------------------------------------+
// > select distinct org_id from github_security_log
// +----------------------------------------------------------+
// | org_id                                                   |
// +----------------------------------------------------------+
// | map[id:98822760 ids:<nil>]                               |
// | map[id:10854165 ids:<nil>]                               |
// | map[id:<nil> ids:<nil>]                                  |
// | map[id:<nil> ids:[]]                                     |
// | map[id:<nil> ids:[10854165 38865304 98822760 193256578]] |
// | map[id:38865304 ids:<nil>]                               |
// +----------------------------------------------------------+
type OrganizationId struct {
	Id  *int64
	Ids []int64
}

type OrganizationName struct {
	Name  *string
	Names []string
}

type RulesetCondition struct {
	ID         int64               `json:"id"`
	Parameters map[string][]string `json:"parameters"`
	Target     string              `json:"target"`
}

func (s *SecurityLog) GetColumnDescriptions() map[string]string {
	return map[string]string{
		"timestamp":                           "The timestamp when the security event occurred.",
		"document_id":                         "Unique identifier for the document in the security log.",
		"action":                              "The type of security action that was performed (e.g., repo.create, org.invite_member).",
		"actions_cache_id":                    "Identifier for the GitHub Actions cache involved in the event.",
		"actions_cache_key":                   "The key of the GitHub Actions cache.",
		"actions_cache_scope":                 "The scope of the GitHub Actions cache (repository, organization, etc.).",
		"actions_cache_version":               "The version of the GitHub Actions cache.",
		"active":                              "Current active status of the entity (true/false).",
		"active_was":                          "Previous active status of the entity before the change.",
		"actor":                               "The username of the user who performed the action.",
		"actor_id":                            "The unique identifier of the user who performed the action.",
		"actor_is_bot":                        "Whether the actor is a bot account (true/false).",
		"application_client_id":               "The client ID of the OAuth application involved in the event.",
		"approvers":                           "List of users who can approve the action or policy.",
		"approvers_was":                       "Previous list of approvers before the change.",
		"blocked_user":                        "The username of the user who was blocked.",
		"branch":                              "The branch name associated with the security event.",
		"business":                            "The business account name associated with the event.",
		"business_id":                         "The unique identifier of the business account.",
		"can_admins_bypass":                   "Whether administrators can bypass the security policy (true/false).",
		"category":                            "The category of the security event or action.",
		"cname":                               "The custom domain name (CNAME) associated with the event.",
		"collaborator":                        "The username of the collaborator involved in the event.",
		"collaborator_type":                   "The type of collaborator (outside, direct, etc.).",
		"content_type":                        "The MIME type of the content involved in the event.",
		"created_at":                          "The timestamp when the resource was created.",
		"devcontainer_path":                   "The path to the development container configuration.",
		"domain":                              "The domain name associated with the security event.",
		"email":                               "The email address associated with the event.",
		"emoji":                               "The emoji associated with the event (for reactions, etc.).",
		"end_date":                            "The end date of a time-based security policy or event.",
		"environment_name":                    "The name of the deployment environment.",
		"events":                              "List of events associated with a webhook or integration.",
		"events_were":                         "Previous list of events before the change.",
		"explanation":                         "Additional explanation or context for the security event.",
		"filename":                            "The name of the file involved in the security event.",
		"fingerprint":                         "The fingerprint of a security key or certificate.",
		"gist_id":                             "The unique identifier of the gist involved in the event.",
		"hashed_token":                        "The hashed version of an authentication token.",
		"head_branch":                         "The head branch of a pull request or merge.",
		"head_sha":                            "The SHA hash of the head commit.",
		"hook_id":                             "The unique identifier of the webhook.",
		"integration":                         "The name or identifier of the integration involved.",
		"invitee":                             "The username of the user who was invited.",
		"inviter":                             "The username of the user who sent the invitation.",
		"key":                                 "The SSH key or API key involved in the event.",
		"limit":                               "The rate limit or quota limit associated with the event.",
		"limited_availability":                "Whether the feature has limited availability (true/false).",
		"machine_type":                        "The type of machine used for GitHub Actions runners.",
		"manager":                             "The username of the user who manages the resource.",
		"marketplace_listing":                 "The GitHub Marketplace listing associated with the event.",
		"merge_queue_enforcement_level":       "The enforcement level of the merge queue policy.",
		"message":                             "The message or description associated with the event.",
		"name":                                "The name of the resource or entity involved in the event.",
		"new_access":                          "The new access level granted in the permission change.",
		"new_nwo":                             "The new name/owner combination for a repository transfer.",
		"new_policy":                          "The new security policy that was applied.",
		"new_repo_base_role":                  "The new base role for repository access.",
		"new_repo_permission":                 "The new repository permission level.",
		"new_value":                           "The new value after a configuration change.",
		"nickname":                            "The nickname or display name associated with the user.",
		"oauth_application":                   "The OAuth application involved in the authorization event.",
		"oauth_application_id":                "The unique identifier of the OAuth application.",
		"oauth_application_name":              "The name of the OAuth application.",
		"old_access":                          "The previous access level before the permission change.",
		"old_base_role":                       "The previous base role before the change.",
		"old_cname":                           "The previous custom domain name before the change.",
		"old_login":                           "The previous username before the account change.",
		"old_name":                            "The previous name of the resource before the change.",
		"old_permission":                      "The previous permission level before the change.",
		"old_policy":                          "The previous security policy before the change.",
		"old_project_role":                    "The previous project role before the change.",
		"old_repo_base_role":                  "The previous repository base role before the change.",
		"old_repo_permission":                 "The previous repository permission before the change.",
		"old_user":                            "The previous user before a transfer or change.",
		"operation_type":                      "The type of operation performed (create, update, delete, etc.).",
		"org":                                 "The organization name where the security event occurred.",
		"org_id":                              "The unique identifier of the organization.",
		"origin_repository":                   "The original repository in a fork or transfer operation.",
		"owner":                               "The owner of the repository or resource.",
		"owner_type":                          "The type of owner (User, Organization, etc.).",
		"passkey_nickname":                    "The nickname assigned to a passkey for identification.",
		"patreon_email":                       "The Patreon email address associated with sponsorship.",
		"patreon_username":                    "The Patreon username associated with sponsorship.",
		"permissions":                         "The permissions associated with the security event.",
		"permissions_added":                   "Permissions that were added in the change.",
		"permissions_unchanged":               "Permissions that remained unchanged.",
		"permissions_upgraded":                "Permissions that were upgraded or enhanced.",
		"policy":                              "The security policy applied to the resource.",
		"prevent_self_review":                 "Whether self-review is prevented in pull requests (true/false).",
		"previous_visibility":                 "The previous visibility setting before the change (public, private, internal).",
		"primary_category":                    "The primary category classification of the event.",
		"programmatic_access_type":            "The type of programmatic access (token, key, etc.).",
		"project_id":                          "The unique identifier of the project.",
		"project_kind":                        "The type or kind of project (classic, next-gen, etc.).",
		"project_name":                        "The name of the project involved in the event.",
		"project_role":                        "The role assigned within the project.",
		"public_project":                      "Whether the project is publicly visible (true/false).",
		"public_repo":                         "Whether the repository is publicly visible (true/false).",
		"pull_request_id":                     "The unique identifier of the pull request.",
		"query":                               "The search query or filter used in the event.",
		"read_only":                           "Whether the access is read-only (true/false).",
		"repo":                                "The repository name where the security event occurred.",
		"repo_id":                             "The unique identifier of the repository.",
		"repo_was":                            "The previous repository before a transfer or change.",
		"repositories_added":                  "List of repositories that were added to a scope or permission.",
		"repositories_added_names":            "Names of repositories that were added.",
		"repositories_removed":                "List of repositories that were removed from a scope or permission.",
		"repositories_removed_names":          "Names of repositories that were removed.",
		"repository":                          "The full name of the repository (owner/repo).",
		"repository_id":                       "The unique identifier of the repository.",
		"repository_selection":                "The repository selection criteria (all, selected, etc.).",
		"request_access_security_header":      "Security headers included in the access request.",
		"request_category":                    "The category of the access request.",
		"request_id":                          "The unique identifier of the request.",
		"request_method":                      "The HTTP method used in the request (GET, POST, etc.).",
		"requested_at":                        "The timestamp when the request was made.",
		"requester":                           "The username of the user who made the request.",
		"requester_id":                        "The unique identifier of the user who made the request.",
		"repositories":                        "Array of repository IDs associated with the security event.",
		"environment_id":                      "The unique identifier of the environment involved in the event.",
		"old_value":                           "The previous value before a configuration change.",
		"ruleset_bypass_actors":               "List of actors who can bypass the ruleset.",
		"ruleset_bypass_actors_added":         "Bypass actors that were added to the ruleset.",
		"ruleset_bypass_actors_deleted":       "Bypass actors that were removed from the ruleset.",
		"ruleset_bypass_actors_updated":       "Bypass actors that were updated in the ruleset.",
		"ruleset_conditions":                  "Conditions defined in the ruleset.",
		"ruleset_conditions_added":            "Conditions that were added to the ruleset.",
		"ruleset_conditions_deleted":          "Conditions that were removed from the ruleset.",
		"ruleset_conditions_updated":          "Conditions that were updated in the ruleset.",
		"ruleset_enforcement":                 "The enforcement level of the ruleset (active, evaluate, disabled).",
		"ruleset_id":                          "The unique identifier of the ruleset.",
		"ruleset_name":                        "The name of the ruleset.",
		"ruleset_old_enforcement":             "The previous enforcement level before the change.",
		"ruleset_old_name":                    "The previous name of the ruleset before the change.",
		"ruleset_rules":                       "The rules defined in the ruleset.",
		"ruleset_rules_added":                 "Rules that were added to the ruleset.",
		"ruleset_rules_deleted":               "Rules that were removed from the ruleset.",
		"ruleset_rules_updated":               "Rules that were updated in the ruleset.",
		"ruleset_source_type":                 "The source type of the ruleset (repository, organization).",
		"run_number":                          "The run number of the GitHub Actions workflow.",
		"seat_assignment":                     "The seat assignment information for licensed users.",
		"secondary_category":                  "The secondary category classification of the event.",
		"sponsors_listing_id":                 "The unique identifier of the sponsors listing.",
		"start_date":                          "The start date of a time-based security policy or event.",
		"started_at":                          "The timestamp when the process or workflow started.",
		"state":                               "The current state of the resource (active, inactive, pending, etc.).",
		"team":                                "The team name involved in the security event.",
		"title":                               "The title or name of the resource or event.",
		"token_id":                            "The unique identifier of the authentication token.",
		"token_scopes":                        "The scopes or permissions granted to the token.",
		"tool":                                "The tool or service that triggered the security event.",
		"topic":                               "The topic or subject associated with the event.",
		"transfer_from":                       "The source account in a transfer operation.",
		"transfer_from_id":                    "The unique identifier of the source account in a transfer.",
		"transfer_from_type":                  "The type of the source account in a transfer (User, Organization).",
		"transfer_to":                         "The destination account in a transfer operation.",
		"transfer_to_id":                      "The unique identifier of the destination account in a transfer.",
		"transfer_to_type":                    "The type of the destination account in a transfer (User, Organization).",
		"trigger_id":                          "The unique identifier of the trigger that caused the event.",
		"updated_access_policy":               "The updated access policy after the change.",
		"user":                                "The username of the user involved in the security event.",
		"user_agent":                          "The user agent string from the client that made the request.",
		"user_id":                             "The unique identifier of the user involved in the event.",
		"user_programmatic_access_id":         "The unique identifier of the user's programmatic access credential.",
		"user_programmatic_access_name":       "The name of the user's programmatic access credential.",
		"user_programmatic_access_request_id": "The unique identifier of the programmatic access request.",
		"visibility":                          "The visibility setting of the resource (public, private, internal).",
		"workflow_id":                         "The unique identifier of the GitHub Actions workflow.",
		"workflow_run_id":                     "The unique identifier of the GitHub Actions workflow run.",
		"tp_index":                            "The organization name or 'default' if not set.",
		"tp_ips":                              "IP addresses related to the event.",
		"tp_source_ip":                        "The IP address of the actor.",
	}
}

func (a *SecurityLog) mapSecurityLogFields(in map[string]interface{}) {
	// Create a map to hold dynamic fields
	dynamicFields := make(map[string]interface{})

	for key, value := range in {
		switch key {
		case "@timestamp":
			if floatVal, ok := value.(float64); ok {
				t := time.Unix(0, int64(floatVal)*int64(time.Millisecond))
				a.Timestamp = &t
			}
		case "_document_id":
			if strVal, ok := value.(string); ok {
				a.DocumentId = &strVal
			}
		case "action":
			if strVal, ok := value.(string); ok {
				a.Action = &strVal
			}
		case "actions_cache_id":
			if strVal, ok := value.(string); ok {
				a.ActionsCacheId = &strVal
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
		case "active":
			if strVal, ok := value.(string); ok {
				a.Active = &strVal
			}
		case "active_was":
			if strVal, ok := value.(string); ok {
				a.ActiveWas = &strVal
			}
		case "actor":
			if strVal, ok := value.(string); ok {
				a.Actor = &strVal
			}
		case "actor_id":
			intVal, err := toInt64(value)
			if err == nil {
				a.ActorId = &intVal
			}
		case "actor_is_bot":
			if boolValue, ok := value.(bool); ok {
				a.ActorIsBot = &boolValue
			}
		case "application_client_id":
			if strVal, ok := value.(string); ok {
				a.ApplicationClientId = &strVal
			}
		case "approvers":
			if strVal, ok := value.(string); ok {
				a.Approvers = &strVal
			}
		case "approvers_was":
			if strVal, ok := value.(string); ok {
				a.ApproversWas = &strVal
			}
		case "blocked_user":
			if strVal, ok := value.(string); ok {
				a.BlockedUser = &strVal
			}
		case "branch":
			if strVal, ok := value.(string); ok {
				a.Branch = &strVal
			}
		case "business":
			if strVal, ok := value.(string); ok {
				a.Business = &strVal
			}
		case "business_id":
			intVal, err := toInt64(value)
			if err == nil {
				a.BusinessId = &intVal
			}
		case "can_admins_bypass":
			if strVal, ok := value.(string); ok {
				a.CanAdminsBypass = &strVal
			}
		case "category":
			if strVal, ok := value.(string); ok {
				a.Category = &strVal
			}
		case "cname":
			if strVal, ok := value.(string); ok {
				a.Cname = &strVal
			}
		case "collaborator":
			if strVal, ok := value.(string); ok {
				a.Collaborator = &strVal
			}
		case "collaborator_type":
			if strVal, ok := value.(string); ok {
				a.CollaboratorType = &strVal
			}
		case "content_type":
			if strVal, ok := value.(string); ok {
				a.ContentType = &strVal
			}
		case "created_at":
			if floatVal, ok := value.(float64); ok {
				t := time.Unix(0, int64(floatVal)*int64(time.Millisecond))
				a.CreatedAt = &t
			}
		case "devcontainer_path":
			if strVal, ok := value.(string); ok {
				a.DevcontainerPath = &strVal
			}
		case "domain":
			if strVal, ok := value.(string); ok {
				a.Domain = &strVal
			}
		case "email":
			if strVal, ok := value.(string); ok {
				a.Email = &strVal
			}
		case "emoji":
			if strVal, ok := value.(string); ok {
				a.Emoji = &strVal
			}
		case "end_date":
			if floatVal, ok := value.(float64); ok {
				t := time.Unix(0, int64(floatVal)*int64(time.Millisecond))
				a.EndDate = &t
			}
		case "environment_name":
			if strVal, ok := value.(string); ok {
				a.EnvironmentName = &strVal
			}
		case "events":
			strArray, err := convertToStringArray(value)
			if err == nil {
				a.Events = strArray
			}
		case "events_were":
			if strVal, ok := value.(string); ok {
				a.EventsWere = &strVal
			}
		case "explanation":
			if strVal, ok := value.(string); ok {
				a.Explanation = &strVal
			}
		case "filename":
			if strVal, ok := value.(string); ok {
				a.Filename = &strVal
			}
		case "fingerprint":
			if strVal, ok := value.(string); ok {
				a.Fingerprint = &strVal
			}
		case "gist_id":
			if strVal, ok := value.(string); ok {
				a.GistId = &strVal
			}
		case "hashed_token":
			if strVal, ok := value.(string); ok {
				a.HashedToken = &strVal
			}
		case "head_branch":
			if strVal, ok := value.(string); ok {
				a.HeadBranch = &strVal
			}
		case "head_sha":
			if strVal, ok := value.(string); ok {
				a.HeadSha = &strVal
			}
		case "hook_id":
			if strVal, ok := value.(string); ok {
				a.HookId = &strVal
			}
		case "integration":
			if strVal, ok := value.(string); ok {
				a.Integration = &strVal
			}
		case "invitee":
			if strVal, ok := value.(string); ok {
				a.Invitee = &strVal
			}
		case "inviter":
			if strVal, ok := value.(string); ok {
				a.Inviter = &strVal
			}
		case "key":
			if strVal, ok := value.(string); ok {
				a.Key = &strVal
			}
		case "limit":
			if strVal, ok := value.(string); ok {
				a.Limit = &strVal
			}
		case "limited_availability":
			if strVal, ok := value.(string); ok {
				a.LimitedAvailability = &strVal
			}
		case "machine_type":
			if strVal, ok := value.(string); ok {
				a.MachineType = &strVal
			}
		case "manager":
			if strVal, ok := value.(string); ok {
				a.Manager = &strVal
			}
		case "marketplace_listing":
			if strVal, ok := value.(string); ok {
				a.MarketplaceListing = &strVal
			}
		case "merge_queue_enforcement_level":
			if strVal, ok := value.(string); ok {
				a.MergeQueueEnforcementLevel = &strVal
			}
		case "message":
			if strVal, ok := value.(string); ok {
				a.Message = &strVal
			}
		case "name":
			if strVal, ok := value.(string); ok {
				a.Name = &strVal
			}
		case "new_access":
			if strVal, ok := value.(string); ok {
				a.NewAccess = &strVal
			}
		case "new_nwo":
			if strVal, ok := value.(string); ok {
				a.NewNwo = &strVal
			}
		case "new_policy":
			if strVal, ok := value.(string); ok {
				a.NewPolicy = &strVal
			}
		case "new_repo_base_role":
			if strVal, ok := value.(string); ok {
				a.NewRepoBaseRole = &strVal
			}
		case "new_repo_permission":
			if strVal, ok := value.(string); ok {
				a.NewRepoPermission = &strVal
			}
		case "new_value":
			if strVal, ok := value.(string); ok {
				a.NewValue = &strVal
			}
		case "nickname":
			if strVal, ok := value.(string); ok {
				a.Nickname = &strVal
			}
		case "oauth_application":
			if strVal, ok := value.(string); ok {
				a.OauthApplication = &strVal
			}
		case "oauth_application_id":
			if strVal, ok := value.(string); ok {
				a.OauthApplicationId = &strVal
			}
		case "oauth_application_name":
			if strVal, ok := value.(string); ok {
				a.OauthApplicationName = &strVal
			}
		case "old_access":
			if strVal, ok := value.(string); ok {
				a.OldAccess = &strVal
			}
		case "old_base_role":
			if strVal, ok := value.(string); ok {
				a.OldBaseRole = &strVal
			}
		case "old_cname":
			if strVal, ok := value.(string); ok {
				a.OldCname = &strVal
			}
		case "old_login":
			if strVal, ok := value.(string); ok {
				a.OldLogin = &strVal
			}
		case "old_name":
			if strVal, ok := value.(string); ok {
				a.OldName = &strVal
			}
		case "old_permission":
			if strVal, ok := value.(string); ok {
				a.OldPermission = &strVal
			}
		case "old_policy":
			if strVal, ok := value.(string); ok {
				a.OldPolicy = &strVal
			}
		case "old_project_role":
			if strVal, ok := value.(string); ok {
				a.OldProjectRole = &strVal
			}
		case "old_repo_base_role":
			if strVal, ok := value.(string); ok {
				a.OldRepoBaseRole = &strVal
			}
		case "old_repo_permission":
			if strVal, ok := value.(string); ok {
				a.OldRepoPermission = &strVal
			}
		case "old_user":
			if strVal, ok := value.(string); ok {
				a.OldUser = &strVal
			}
		case "operation_type":
			if strVal, ok := value.(string); ok {
				a.OperationType = &strVal
			}
		case "org":
			if strVal, ok := value.(string); ok {
				a.Org.Name = &strVal
			}
			stringArr, err := convertToStringArray(value)
			if err == nil {
				a.Org.Names = stringArr
			}
		case "org_id":
			intVal, err := toInt64(value)
			if err == nil {
				a.OrgId.Id = &intVal
			}
			intArr, err := convertToInt64Slice(value)
			if err == nil {
				a.OrgId.Ids = intArr
			}
		case "origin_repository":
			if strVal, ok := value.(string); ok {
				a.OriginRepository = &strVal
			}
		case "owner":
			if strVal, ok := value.(string); ok {
				a.Owner = &strVal
			}
		case "owner_type":
			if strVal, ok := value.(string); ok {
				a.OwnerType = &strVal
			}
		case "passkey_nickname":
			if strVal, ok := value.(string); ok {
				a.PasskeyNickname = &strVal
			}
		case "patreon_email":
			if strVal, ok := value.(string); ok {
				a.PatreonEmail = &strVal
			}
		case "patreon_username":
			if strVal, ok := value.(string); ok {
				a.PatreonUsername = &strVal
			}
		case "permissions":
			mapVal, err := convertToMapStringString(value)
			if err == nil {
				a.Permissions = mapVal
			}

		case "permissions_added":
			mapVal, err := convertToMapStringString(value)
			if err == nil {
				a.PermissionsAdded = mapVal
			}
		case "permissions_unchanged":
			mapVal, err := convertToMapStringString(value)
			if err == nil {
				a.PermissionsUnchanged = mapVal
			}
		case "permissions_upgraded":
			mapVal, err := convertToMapStringString(value)
			if err == nil {
				a.PermissionsUpgraded = mapVal
			}
		case "policy":
			if strVal, ok := value.(string); ok {
				a.Policy = &strVal
			}
		case "prevent_self_review":
			if strVal, ok := value.(string); ok {
				a.PreventSelfReview = &strVal
			}
		case "previous_visibility":
			if strVal, ok := value.(string); ok {
				a.PreviousVisibility = &strVal
			}
		case "primary_category":
			if strVal, ok := value.(string); ok {
				a.PrimaryCategory = &strVal
			}
		case "programmatic_access_type":
			if strVal, ok := value.(string); ok {
				a.ProgrammaticAccessType = &strVal
			}
		case "project_id":
			if strVal, ok := value.(string); ok {
				a.ProjectId = &strVal
			}
		case "project_kind":
			if strVal, ok := value.(string); ok {
				a.ProjectKind = &strVal
			}
		case "project_name":
			if strVal, ok := value.(string); ok {
				a.ProjectName = &strVal
			}
		case "project_role":
			if strVal, ok := value.(string); ok {
				a.ProjectRole = &strVal
			}
		case "public_project":
			if strVal, ok := value.(string); ok {
				a.PublicProject = &strVal
			}
		case "public_repo":
			if strVal, ok := value.(string); ok {
				a.PublicRepo = &strVal
			}
		case "pull_request_id":
			if strVal, ok := value.(string); ok {
				a.PullRequestId = &strVal
			}
		case "query":
			if strVal, ok := value.(string); ok {
				a.Query = &strVal
			}
		case "read_only":
			if strVal, ok := value.(string); ok {
				a.ReadOnly = &strVal
			}
		case "repo":
			if strVal, ok := value.(string); ok {
				a.Repo = &strVal
			}
		case "repo_id":
			intVal, err := toInt64(value)
			if err == nil {
				a.RepoId = &intVal
			}
		case "repo_was":
			if strVal, ok := value.(string); ok {
				a.RepoWas = &strVal
			}
		case "repositories_added":
			intArr, err := convertToInt64Slice(value)
			if err == nil {
				a.RepositoriesAdded = intArr
			}
		case "repositories_added_names":
			stringSliceVal, err := convertToStringArray(value)
			if err == nil {
				a.RepositoriesAddedNames = stringSliceVal
			}
		case "repositories_removed":
			if strVal, ok := value.(string); ok {
				a.RepositoriesRemoved = &strVal
			}
		case "repositories_removed_names":
			if strVal, ok := value.(string); ok {
				a.RepositoriesRemovedNames = &strVal
			}
		case "repository":
			if strVal, ok := value.(string); ok {
				a.Repository = &strVal
			}
		case "repository_id":
			intVal, err := toInt64(value)
			if err == nil {
				a.RepositoryId = &intVal
			}
		case "repository_selection":
			if strVal, ok := value.(string); ok {
				a.RepositorySelection = &strVal
			}
		case "request_access_security_header":
			if strVal, ok := value.(string); ok {
				a.RequestAccessSecurityHeader = &strVal
			}
		case "request_category":
			if strVal, ok := value.(string); ok {
				a.RequestCategory = &strVal
			}
		case "request_id":
			if strVal, ok := value.(string); ok {
				a.RequestId = &strVal
			}
		case "request_method":
			if strVal, ok := value.(string); ok {
				a.RequestMethod = &strVal
			}
		case "requested_at":
			if floatVal, ok := value.(float64); ok {
				t := time.Unix(0, int64(floatVal)*int64(time.Millisecond))
				a.RequestedAt = &t
			}
		case "requester":
			if strVal, ok := value.(string); ok {
				a.Requester = &strVal
			}
		case "requester_id":
			if strVal, ok := value.(string); ok {
				a.RequesterId = &strVal
			}
		case "repositories":
			intArr, err := convertToInt64Slice(value)
			if err == nil {
				a.Repositories = intArr
			}
		case "environment_id":
			intVal, err := toInt64(value)
			if err == nil {
				a.EnvironmentId = &intVal
			}
		case "old_value":
			if strVal, ok := value.(string); ok {
				a.OldValue = &strVal
			}
		case "ruleset_bypass_actors":
			if strVal, ok := value.(string); ok {
				a.RulesetBypassActors = &strVal
			}
		case "ruleset_bypass_actors_added":
			if strVal, ok := value.(string); ok {
				a.RulesetBypassActorsAdded = &strVal
			}
		case "ruleset_bypass_actors_deleted":
			if strVal, ok := value.(string); ok {
				a.RulesetBypassActorsDeleted = &strVal
			}
		case "ruleset_bypass_actors_updated":
			if strVal, ok := value.(string); ok {
				a.RulesetBypassActorsUpdated = &strVal
			}
		case "ruleset_conditions":
			val, err := convertToSliceOfMap(value)
			if err == nil {
				a.RulesetConditions = val
			}
		case "ruleset_conditions_added":
			if strVal, ok := value.(string); ok {
				a.RulesetConditionsAdded = &strVal
			}
		case "ruleset_conditions_deleted":
			if strVal, ok := value.(string); ok {
				a.RulesetConditionsDeleted = &strVal
			}
		case "ruleset_conditions_updated":
			if strVal, ok := value.(string); ok {
				a.RulesetConditionsUpdated = &strVal
			}
		case "ruleset_enforcement":
			if strVal, ok := value.(string); ok {
				a.RulesetEnforcement = &strVal
			}
		case "ruleset_id":
			intVal, err := toInt64(value)
			if err == nil {
				a.RulesetId = &intVal
			}
		case "ruleset_name":
			if strVal, ok := value.(string); ok {
				a.RulesetName = &strVal
			}
		case "ruleset_old_enforcement":
			if strVal, ok := value.(string); ok {
				a.RulesetOldEnforcement = &strVal
			}
		case "ruleset_old_name":
			if strVal, ok := value.(string); ok {
				a.RulesetOldName = &strVal
			}
		case "ruleset_rules":
			val, err := convertToSliceOfMap(value)
			if err == nil {
				a.RulesetRules = val
			}
		case "ruleset_rules_added":
			if strVal, ok := value.(string); ok {
				a.RulesetRulesAdded = &strVal
			}
		case "ruleset_rules_deleted":
			if strVal, ok := value.(string); ok {
				a.RulesetRulesDeleted = &strVal
			}
		case "ruleset_rules_updated":
			if strVal, ok := value.(string); ok {
				a.RulesetRulesUpdated = &strVal
			}
		case "ruleset_source_type":
			if strVal, ok := value.(string); ok {
				a.RulesetSourceType = &strVal
			}
		case "run_number":
			if strVal, ok := value.(string); ok {
				a.RunNumber = &strVal
			}
		case "seat_assignment":
			if strVal, ok := value.(string); ok {
				a.SeatAssignment = &strVal
			}
		case "secondary_category":
			if strVal, ok := value.(string); ok {
				a.SecondaryCategory = &strVal
			}
		case "sponsors_listing_id":
			if strVal, ok := value.(string); ok {
				a.SponsorsListingId = &strVal
			}
		case "start_date":
			if floatVal, ok := value.(float64); ok {
				t := time.Unix(0, int64(floatVal)*int64(time.Millisecond))
				a.StartDate = &t
			}
		case "started_at":
			if strVal, ok := value.(string); ok {
				a.StartedAt = &strVal
			}
		case "state":
			if strVal, ok := value.(string); ok {
				a.State = &strVal
			}
		case "team":
			if strVal, ok := value.(string); ok {
				a.Team = &strVal
			}
		case "title":
			if strVal, ok := value.(string); ok {
				a.Title = &strVal
			}
		case "token_id":
			intVal, err := toInt64(value)
			if err == nil {
				a.TokenId = &intVal
			}
		case "token_scopes":
			if strVal, ok := value.(string); ok {
				a.TokenScopes = &strVal
			}
		case "tool":
			if strVal, ok := value.(string); ok {
				a.Tool = &strVal
			}
		case "topic":
			if strVal, ok := value.(string); ok {
				a.Topic = &strVal
			}
		case "transfer_from":
			if strVal, ok := value.(string); ok {
				a.TransferFrom = &strVal
			}
		case "transfer_from_id":
			if strVal, ok := value.(string); ok {
				a.TransferFromId = &strVal
			}
		case "transfer_from_type":
			if strVal, ok := value.(string); ok {
				a.TransferFromType = &strVal
			}
		case "transfer_to":
			if strVal, ok := value.(string); ok {
				a.TransferTo = &strVal
			}
		case "transfer_to_id":
			if strVal, ok := value.(string); ok {
				a.TransferToId = &strVal
			}
		case "transfer_to_type":
			if strVal, ok := value.(string); ok {
				a.TransferToType = &strVal
			}
		case "trigger_id":
			if strVal, ok := value.(string); ok {
				a.TriggerId = &strVal
			}
		case "updated_access_policy":
			if strVal, ok := value.(string); ok {
				a.UpdatedAccessPolicy = &strVal
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
			intVal, err := toInt64(value)
			if err == nil {
				a.UserId = &intVal
			}
		case "user_programmatic_access_id":
			if strVal, ok := value.(string); ok {
				a.UserProgrammaticAccessId = &strVal
			}
		case "user_programmatic_access_name":
			if strVal, ok := value.(string); ok {
				a.UserProgrammaticAccessName = &strVal
			}
		case "user_programmatic_access_request_id":
			intVal, err := toInt64(value)
			if err == nil {
				a.UserProgrammaticAccessRequestId = &intVal
			}
		case "visibility":
			if strVal, ok := value.(string); ok {
				a.Visibility = &strVal
			}
		case "workflow_id":
			intVal, err := toInt64(value)
			if err == nil {
				a.WorkflowId = &intVal
			}
		case "workflow_run_id":
			if strVal, ok := value.(string); ok {
				a.WorkflowRunId = &strVal
			}
		default:
			// Add unknown fields to dynamicFields
			dynamicFields[key] = value
		}
	}
}

// Helper functions

func convertToSliceOfMap(data interface{}) ([]map[string]interface{}, error) {
	rawSlice, ok := data.([]interface{})
	if !ok {
		return nil, fmt.Errorf("data is not a slice")
	}

	result := make([]map[string]interface{}, 0, len(rawSlice))
	for i, item := range rawSlice {
		m, ok := item.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("item at index %d is not a map[string]interface{}", i)
		}
		if idVal, ok := m["id"].(float64); ok {
			id := int64(idVal) // This safely converts 8.560519e+06 to 8560519
			m["id"] = id
		}
		result = append(result, m)
	}

	return result, nil
}

func convertToMapStringString(val interface{}) (map[string]string, error) {
	rawMap, ok := val.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("input is not a map[string]interface{}")
	}

	result := make(map[string]string)
	for k, v := range rawMap {
		str, ok := v.(string)
		if !ok {
			return nil, fmt.Errorf("value for key '%s' is not a string (type: %T)", k, v)
		}
		result[k] = str
	}

	return result, nil
}

func toInt64(val interface{}) (int64, error) {
	if val == nil {
		return 0, nil
	}
	switch v := val.(type) {
	case float64:
		return int64(v), nil
	case float32:
		return int64(v), nil
	case int:
		return int64(v), nil
	case int32:
		return int64(v), nil
	case int64:
		return v, nil
	case string:
		// optional: convert string to int64 if needed
		return 0, fmt.Errorf("cannot convert string to int64 directly: %s", v)
	default:
		return 0, fmt.Errorf("unsupported type: %T", val)
	}
}

func convertToStringArray(val interface{}) ([]string, error) {
	rawSlice, ok := val.([]interface{})
	if !ok {
		return nil, fmt.Errorf("value is not a slice")
	}

	result := make([]string, 0, len(rawSlice))
	for i, v := range rawSlice {
		str, ok := v.(string)
		if !ok {
			return nil, fmt.Errorf("element at index %d is not a string (type: %T)", i, v)
		}
		result = append(result, str)
	}

	return result, nil
}

func convertToInt64Slice(val interface{}) ([]int64, error) {
	rawSlice, ok := val.([]interface{})
	if !ok {
		return nil, fmt.Errorf("value is not a slice")
	}

	result := make([]int64, 0, len(rawSlice))
	for i, v := range rawSlice {
		num, ok := v.(float64) // JSON numbers are float64 by default
		if !ok {
			return nil, fmt.Errorf("element at index %d is not a float64 (type: %T)", i, v)
		}
		result = append(result, int64(num))
	}

	return result, nil
}
