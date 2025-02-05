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
		"action":                     "The action performed.",
		"actor":                      "Actor that performed the action.",
		"actor_id":                   "The id of the actor who performed the action.",
		"actor_ip":                   "Actor IP (only included if explicitly enabled in your GitHub settings https://docs.github.com/en/enterprise-cloud@latest/admin/monitoring-activity-in-your-enterprise/reviewing-audit-logs-for-your-enterprise/displaying-ip-addresses-in-the-audit-log-for-your-enterprise).",
		"actor_location":             "Actor location.",
		"business":                   "The name of the business that relates to this action.",
		"business_id":                "ID of the enterprise affected by the action (if applicable).",
		"created_at":                 "Creation timestamp for audit event.",
		"document_id":                "Document id for the audit log events.",
		"external_identity_name_id":  "Displayed when SAML SSO identity was used as a means of authentication.",
		"external_identity_username": "Displayed when SAML SSO identity was used as a means of authentication with Enterprise Managed Users.",
		"hashed_token":               "Hash of the token used to perform this action (see https://docs.github.com/en/enterprise-cloud@latest/admin/monitoring-activity-in-your-enterprise/reviewing-audit-logs-for-your-enterprise/identifying-audit-log-events-performed-by-an-access-token#searching-on-github).",
		"org":                        "The Organization where the action was performed.",
		"org_id":                     "The Organization ID where the action was performed.",
		"timestamp":                  "Timestamp for the event.",
		"token_id":                   "ID of the token used in this action.",
		"token_scopes":               "List of scopes of the token used in this action.",
		"user":                       "User added/removed for certain permission.",
		"user_id":                    "The user ID.",
		"additional_fields":          "The additional properties of the action.",

		// Override table specific tp_* column descriptions
		"tp_index":     "The org Id or user name or user Id that received the request.",
		"tp_ips":       "IP addresses associated with the event, including the source IP address.",
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
