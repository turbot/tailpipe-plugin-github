package mappers

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/turbot/tailpipe-plugin-sdk/artifact_mapper"
)

type AuditLogMapper struct {
	logFormat string
}

// func NewAuditLogMapper(logFormat string) artifact_mapper.Mapper {
func NewAuditLogMapper() artifact_mapper.Mapper {
	return &AuditLogMapper{
		//logFormat: logFormat,
	}
}

func (c *AuditLogMapper) Identifier() string {
	return "audit_log_mapper"
}

// TODO: #refactor - can we make this more generic and add it to the SDK?
func (c *AuditLogMapper) Map(ctx context.Context, a any) ([]any, error) {
	var out []any

	// validate input type is string
	input, ok := a.(string)
	if !ok {
		return nil, fmt.Errorf("expected string, got %T", a)
	}

	// Parse JSONL line
	var fields map[string]interface{}
	err := json.Unmarshal([]byte(input), &fields)
	if err != nil {
		return nil, fmt.Errorf("error parsing JSONL line: %w", err)
	}

	out = append(out, fields)

	return out, nil
}
