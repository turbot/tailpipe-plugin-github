package tables

type AuditLogTableConfig struct {
	LogFormat *string `hcl:"log_format"`
}

func (a *AuditLogTableConfig) Validate() error {
	//TODO implement me
	return nil
}
