package config

import "github.com/turbot/tailpipe-plugin-sdk/parse"

type GithubConnection struct {
}

func NewGithubConnection() parse.Config {
	return &GithubConnection{}
}

func (c *GithubConnection) Validate() error {
	return nil
}
