package mappers

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/turbot/tailpipe-plugin-github/rows"
	"github.com/turbot/tailpipe-plugin-sdk/table"
)

type AuditLogMapper struct {
}

func NewAuditLogMapper() table.Mapper[*rows.AuditLog] {
	return &AuditLogMapper{}
}

func (c *AuditLogMapper) Identifier() string {
	return "audit_log_mapper"
}

func (c *AuditLogMapper) Map(ctx context.Context, a any) ([]*rows.AuditLog, error) {
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

	row := rows.NewAuditLog()
	row.FromMap(fields)

	return []*rows.AuditLog{row}, nil
}
