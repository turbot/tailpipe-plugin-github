---
title: "Tailpipe Table: github_audit_log - Query GitHub Audit Logs"
description: "GitHub audit logs list events triggered by activities that affect your organization."
---

# Table: github_audit_log - Query GitHub audit logs

The `github_audit_log` table allows you to query data from [GitHub organization audit logs](https://docs.github.com/en/organizations/keeping-your-organization-secure/managing-security-settings-for-your-organization/reviewing-the-audit-log-for-your-organization). This table provides detailed information about activity performed within your GitHub organization, including the event name, source IP address, user identity, and more.

Limitations and notes:
- The table currently supports exported logs in JSON format.

## Configure

Create a [partition](https://tailpipe.io/docs/manage/partition) for `github_audit_log` ([examples](https://hub.tailpipe.io/plugins/turbot/github/tables/github_audit_log#example-configurations)):

```sh
vi ~/.tailpipe/config/github.tpc
```

```hcl
partition "github_audit_log" "my_logs" {
  source "file"  {
    paths       = ["/Users/myuser/github_audit_logs"]
    file_layout = "%{DATA}.json.gz"
  }
}
```

## Collect

[Collect](https://tailpipe.io/docs/manage/collection) logs for all `github_audit_log` partitions:

```sh
tailpipe collect github_audit_log
```

Or for a single partition:

```sh
tailpipe collect github_audit_log.my_logs
```

## Query

**[Explore 35+ example queries for this table →](https://hub.tailpipe.io/plugins/turbot/github/queries/github_audit_log)**

### Repositories made public

Track repositories that were made public to check for accidental visibility changes.

```sql
select
  timestamp,
  repo,
  actor
from
  github_audit_log
where
  action = 'repo.access'
  and (additional_fields ->> 'visibility') = 'public'
order by
  timestamp desc;
```

### Branch protection overrides

Find instances where a branch protection requirement was overridden by a repository administrator.

```sql
select
  timestamp,
  actor,
  actor_ip,
  repo,
  additional_fields ->> 'branch' as branch,
  additional_fields ->> 'reasons' as reasons
from
  github_audit_log
where
  action = 'protected_branch.policy_override'
order by
  created_at desc;
```

### Top 10 pull request authors

List the top 10 pull request authors and how many pull requests they've created.

```sql
select
  actor,
  count(*) as action_count
from
  github_audit_log
where
  action = 'pull_request.create'
group by
  actor
order by
  action_count desc
limit 10;
```

## Example Configurations

### Collect logs from local files

Collect GitHub audit logs exported locally as JSON.

```hcl
partition "github_audit_log" "my_logs" {
  source "file"  {
    paths       = ["/Users/myuser/github_audit_logs"]
    file_layout = "%{DATA}.json.gz"
  }
}
```

### Exclude comment events

Use the filter argument in your partition to filter out events, like issue and pull request review comments.

```hcl
partition "github_audit_log" "my_logs_issue_comment" {
  filter = "action not like 'issue_comment.%' and action not like 'pull_request_review_comment.%'"

  source "file"  {
    paths       = ["/Users/myuser/github_audit_logs"]
    file_layout = "%{DATA}.json.gz"
  }
}
```
