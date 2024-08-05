package github_source

import "github.com/turbot/tailpipe-plugin-sdk/paging"

// TODO: #paging figure out paging for github audit logs - this is a placeholder

type AuditLogPaging struct {
}

func NewAuditLogPaging() *AuditLogPaging {
	return &AuditLogPaging{}
}

func (a *AuditLogPaging) Update(data paging.Data) error {
	return nil
}
