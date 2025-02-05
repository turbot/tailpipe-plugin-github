---
organization: Turbot
category: ["software development"]
icon_url: "/images/plugins/turbot/github.svg"
brand_color: "#191717"
display_name: "GitHub"
description: "Tailpipe plugin for collecting and querying various audit logs from GitHub."
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

Configure your table partition and data source ([examples](https://hub.tailpipe.io/plugins/turbot/github/tables/github_audit_log#example-configurations)):

```sh
vi ~/.tailpipe/config/github.tpc
```

```hcl
partition "github_audit_log" "audit_log" {
  source "file"  {
    paths       = ["/Users/myuser/github_audit_logs"]
    file_layout = "%{DATA}.json.gz"
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
  count(*) as action_count
from
  github_audit_log
group by
  action
order by
  action_count desc;
```

```sh
+----------------------------------------+--------------+
| action                                 | action_count |
+----------------------------------------+--------------+
| pull_request.create                    | 9894         |
| pull_request.merge                     | 7440         |
| issue_comment.update                   | 5832         |
| packages.package_version_published     | 4990         |
| protected_branch.policy_override       | 4012         |
| pull_request_review.submit             | 3672         |
| pull_request_review_comment.create     | 2516         |
| pull_request.close                     | 2462         |
| pull_request.create_review_request     | 2438         |
| repository_vulnerability_alert.create  | 1972         |
| repository_vulnerability_alert.resolve | 1486         |
| repo.change_merge_setting              | 892          |
+----------------------------------------+--------------+
```
