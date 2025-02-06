package audit_log

import (
	"strconv"
	"time"

	"github.com/turbot/tailpipe-plugin-sdk/schema"
)

type AuditLogBatch struct {
	Records []AuditLog `json:"Records"`
}

type AuditLog struct {
	schema.CommonFields

	Action                   *string                 `json:"action,omitempty"`
	OperationType            *string                 `json:"operation_type,omitempty"`
	Actor                    *string                 `json:"actor,omitempty"`
	ActorID                  *int64                  `json:"actor_id,omitempty"`
	ActorIP                  *string                 `json:"actor_ip,omitempty"`
	ActorLocation            *map[string]interface{} `json:"actor_location,omitempty" parquet:"type=JSON"`
	Business                 *string                 `json:"business,omitempty"`
	BusinessID               *int64                  `json:"business_id,omitempty"`
	CreatedAt                *time.Time              `json:"created_at,omitempty"`
	DocumentID               *string                 `json:"document_id,omitempty"`
	ExternalIdentityNameID   *string                 `json:"external_identity_name_id,omitempty"`
	ExternalIdentityUsername *string                 `json:"external_identity_username,omitempty"`
	HashedToken              *string                 `json:"hashed_token,omitempty"`
	Org                      *string                 `json:"org,omitempty"`
	Repo                     *string                 `json:"repo,omitempty"`
	OrgID                    *string                 `json:"org_id,omitempty"`
	Timestamp                *time.Time              `json:"timestamp,omitempty"`
	TokenID                  *int64                  `json:"token_id,omitempty"`
	TokenScopes              *string                 `json:"token_scopes,omitempty"`
	User                     *string                 `json:"user,omitempty"`
	UserID                   *int64                  `json:"user_id,omitempty"`
	AdditionalFields         *map[string]interface{} `json:"additional_fields,omitempty" parquet:"type=JSON"`
}

type ActorLocation struct {
	CountryCode *string `json:"country_code,omitempty"`
}

func (c *AuditLog) GetColumnDescriptions() map[string]string {
	return map[string]string{
		"action":                     "The name of the action that was performed, for example 'user.login' or 'repo.create'.",
		"actor_id":                   "The ID of the actor who performed the action.",
		"actor_ip":                   "The IP address from which the action was performed.",
		"actor_location":             "A JSON object containing geographical information about the actor’s IP address.",
		"actor":                      "The actor who performed the action.",
		"additional_fields":          "A JSON object containing any extra metadata related to the event.",
		"business_id":                "The unique identifier of the business associated with the event.",
		"business":                   "The name of the business associated with the event, if applicable.",
		"created_at":                 "The time the audit log event was recorded in UTC.",
		"document_id":                "A unique identifier for an audit event.",
		"external_identity_name_id":  "The unique identifier of an external identity provider or linked identity.",
		"external_identity_username": "The username associated with an external identity provider.",
		"hashed_token":               "A hashed representation of the authentication token used in the event.",
		"operation_type":             "Indicates the type of operation performed with the event, such as create, modify, access, transfer or remove.",
		"org_id":                     "The unique identifier of the organization associated with the event.",
		"org":                        "The name of the organization associated with the event, if applicable.",
		"repo":                       "The name of the repository associated with the event, if applicable.",
		"timestamp":                  "The time the audit log event occurred, given as a Unix timestamp.",
		"token_id":                   "The unique identifier of the authentication token used.",
		"token_scopes":               "A comma-separated list of permissions associated with the authentication token.",
		"user_id":                    "The unique identifier of the user who performed the action.",
		"user":                       "The user that was affected by the action performed (if available).",

		// Override table-specific tp_* column descriptions
		"tp_index":     "The organization name, or GitHub package name that received the request.",
		"tp_ips":       "IP addresses associated with the event, including the source IP address.",
		"tp_source_ip": "The IP address of the actor.",
		"tp_timestamp": "The date and time the event occurred, in ISO 8601 format.",
	}
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
		case "repo", "repository":
			if strVal, ok := value.(string); ok {
				a.Repo = &strVal
			}
			dynamicFields[key] = value
		case "actor_ip":
			if strVal, ok := value.(string); ok {
				a.ActorIP = &strVal
			}
		case "operation_type":
			if strVal, ok := value.(string); ok {
				a.OperationType = &strVal
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
		case "_document_id":
			if strVal, ok := value.(string); ok {
				a.DocumentID = &strVal
			}
		case "external_identity_nameid":
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
			if floatVal, ok := value.(float64); ok {
				strVal := strconv.FormatInt(int64(floatVal), 10)
				a.OrgID = &strVal
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
