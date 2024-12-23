package mappers

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/turbot/tailpipe-plugin-sdk/table"

	"github.com/turbot/tailpipe-plugin-github/rows"
)

type AuditLogMapper struct {
}

func (c *AuditLogMapper) Identifier() string {
	return "audit_log_mapper"
}

func (c *AuditLogMapper) Map(ctx context.Context, a any, _ ...table.MapOption[*rows.AuditLog]) (*rows.AuditLog, error) {
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

	return row, nil
}
