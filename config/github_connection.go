package config

import "github.com/turbot/tailpipe-plugin-sdk/parse"

type GitHubConnection struct {
}

func NewGitHubConnection() parse.Config {
	return &GitHubConnection{}
}

func (c *GitHubConnection) Validate() error {
	return nil
}
