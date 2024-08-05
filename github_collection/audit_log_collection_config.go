package github_collection

type AuditLogCollectionConfig struct {
	LogFormat *string `hcl:"log_format"`
}

func (a *AuditLogCollectionConfig) Validate() error {
	//TODO implement me
	return nil
}
