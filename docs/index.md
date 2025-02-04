---
organization: Turbot
category: ["public cloud"]
icon_url: "/images/plugins/turbot/github.svg"
brand_color: "#191717"
display_name: "GitHub"
description: "Tailpipe plugin for collecting and querying various audit logs from GitHUb."
og_description: "Collect GitHub logs and query them instantly with SQL! Open source CLI. No DB required."
og_image: "/images/plugins/turbot/github-social-graphic.png"
---

# GitHub + Tailpipe

[Tailpipe](https://tailpipe.io) is an open-source CLI tool that allows you to collect logs and query them with SQL.

The [GitHub Plugin for Tailpipe](https://hub.tailpipe.io/plugins/turbot/github) allows you to collect and query GitHub logs using SQL to track activity, monitor trends, detect anomalies, and more!

- Documentation: [Table definitions & examples](https://hub.tailpipe.io/plugins/turbot/github/tables)
- Community: [Join #tailpipe on Slack →](https://turbot.com/community/join)
- Get involved: [Issues](https://github.com/turbot/tailpipe-plugin-github/issues)

<img src="https://raw.githubusercontent.com/turbot/tailpipe-plugin-github/main/docs/images/github_audit_log_terminal.png" width="50%" type="thumbnail"/>
<img src="https://raw.githubusercontent.com/turbot/tailpipe-plugin-github/main/docs/images/github_audit_log_mitre_dashboard.png" width="50%" type="thumbnail"/>

## Getting Started

Install Tailpipe from the [downloads](https://tailpipe.io/downloads) page:

```sh
# MacOS
brew install turbot/tap/tailpipe
```

```sh
# Linux or Windows (WSL)
sudo /bin/sh -c "$(curl -fsSL https://tailpipe.io/install/tailpipe.sh)"
```

Install the plugin:

```sh
tailpipe plugin install github
```

Configure your [connection credentials](https://hub.tailpipe.io/plugins/turbot/github#connection-credentials), table partition, and data source ([examples](https://hub.tailpipe.io/plugins/turbot/github/tables/github_audit_log#example-configurations)):

```sh
vi ~/.tailpipe/config/github.tpc
```

```hcl
partition "github_audit_log" "audit_log" {
  source "file"  {
	paths = ["/Users/dir/path"]
	file_layout = "export-turbot-%{NUMBER:prefix}.json"
  }
}
```

Download, enrich, and save logs from your source ([examples](https://tailpipe.io/docs/reference/cli/collect)):

```sh
tailpipe collect github_audit_log
```

Enter interactive query mode:

```sh
tailpipe query
```

Run a query:

```sql
select
  action,
  repo,
  count(*) as action_count
from
  github_audit_log
group by
  action,
  repo,
order by
  action_count desc;
```

```sh
+----------------------------------------------------------------------+-------------------------------------------------+--------------+
| action                                                               | repo                                            | action_count |
+----------------------------------------------------------------------+-------------------------------------------------+--------------+
| packages.package_version_published                                   | turbot/release                                  | 2495         |
| issue_comment.update                                                 | turbot/hub.guardrails.turbot.com                | 762          |
| issue_comment.update                                                 | turbot/turbot.com                               | 576          |
| pull_request.create                                                  | turbot/pipes                                    | 566          |
| pull_request.merge                                                   | turbot/pipes                                    | 419          |
| protected_branch.policy_override                                     | turbot/flowpipe                                 | 366          |
| pull_request_review_comment.create                                   | turbot/guardrails-samples                       | 324          |
| issue_comment.update                                                 | turbot/hub.flowpipe.io                          | 321          |
| pull_request.create                                                  | turbot/powerpipe                                | 275          |
| protected_branch.policy_override                                     | turbot/pipe-fittings                            | 268          |
| pull_request_review.submit                                           | turbot/steampipe-plugin-aws                     | 261          |
| pull_request.create                                                  | turbot/turbot.com                               | 257          |
| issue_comment.update                                                 | turbot/hub.powerpipe.io                         | 251          |
| pull_request.merge                                                   | turbot/turbot.com                               | 249          |
| pull_request.merge                                                   | turbot/powerpipe                                | 242          |
+----------------------------------------------------------------------+-------------------------------------------------+--------------+
```

## Detections as Code with Powerpipe

Pre-built dashboards and detections for the GitHub plugin are available in [Powerpipe](https://powerpipe.io) mods, helping you monitor and analyze activity across your GitHub accounts.

For example, the [GitHub Audit Logs Detections mod](https://hub.powerpipe.io/mods/turbot/tailpipe-mod-github-audit-log-detections) scans your audit logs for anomalies, such as monitor SSH key additions to user accounts, admin role assignments in GitHub teams.

Dashboards and detections are [open source](https://github.com/topics/tailpipe-mod), allowing easy customization and collaboration.

To get started, choose a mod from the [Powerpipe Hub](https://hub.powerpipe.io/?engines=tailpipe&q=github).
