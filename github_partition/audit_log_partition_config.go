package github_partition

type AuditLogPartitionConfig struct {
	LogFormat *string `hcl:"log_format"`
}

func (a *AuditLogPartitionConfig) Validate() error {
	//TODO implement me
	return nil
}
