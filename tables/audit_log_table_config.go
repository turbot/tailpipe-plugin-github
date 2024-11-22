package tables

type AuditLogTableConfig struct {
}

func (a *AuditLogTableConfig) Identifier() string {
	return AuditLogTableIdentifier
}

func (a *AuditLogTableConfig) Validate() error {
	return nil
}
