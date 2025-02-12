package audit_log

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/turbot/tailpipe-plugin-sdk/table"
)

type AuditLogMapper struct {}

func (c *AuditLogMapper) Identifier() string {
	return "audit_log_mapper"
}

func (c *AuditLogMapper) Map(ctx context.Context, a any, _ ...table.MapOption[*AuditLog]) (*AuditLog, error) {
	var auditLog AuditLog
	var fields map[string]interface{}
	var jsonBytes []byte
	var err error

	// validate input type is string
	switch v := a.(type) {
	case *string:
		jsonBytes, err = c.decodeString(*v)
		if err != nil {
			return nil, fmt.Errorf("error decoding string: %w", err)
		}
	case string:
		jsonBytes, err = c.decodeString(v)
		if err != nil {
			return nil, fmt.Errorf("error decoding string: %w", err)
		}
	default:
		return nil, fmt.Errorf("expected string, *string got %T", a)
	}

	// Parse JSONL line
	err = json.Unmarshal([]byte(jsonBytes), &fields)
	if err != nil {
		return nil, fmt.Errorf("error in unmarshaling audit log: %w", err)
	}

	// We need this map because we need to manually parse the timestamp from int to timestamp 
	auditLog.mapAuditLogFields(fields)

	return &auditLog, nil
}

func (m *AuditLogMapper) decodeString(input string) ([]byte, error) {
	inputBytes := []byte(input)

	// Attempt Direct Json Unmarshalling
	var result map[string]interface{}
	err := json.Unmarshal(inputBytes, &result)
	if err == nil {
		return inputBytes, nil
	}

	// Attempt Unquoting
	var unescaped string
	err = json.Unmarshal([]byte(`"`+input+`"`), &unescaped) // Wrap the input in quotes to mimic a JSON string literal
	if err != nil {
		return nil, fmt.Errorf("failed to unescape JSON string: %w", err)
	}

	// Decode the unescaped string
	unescapedBytes := []byte(unescaped)
	err = json.Unmarshal(unescapedBytes, &result)
	if err != nil {
		return nil, fmt.Errorf("failed to decode unescaped JSON: %w", err)
	}

	return unescapedBytes, nil
}
