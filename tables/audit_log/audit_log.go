package audit_log

import (
	"strconv"
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
