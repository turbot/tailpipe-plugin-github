package config

const PluginName = "github"

type GitHubConnection struct {
}

func (c *GitHubConnection) Identifier() string {
	return PluginName
}

func (c *GitHubConnection) Validate() error {
	return nil
}
