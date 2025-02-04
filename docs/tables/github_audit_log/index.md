---
title: "Tailpipe Table: github_audit_log - Query GitHub Audit Logs"
description: "GitHub Audit logs capture API activity and user actions within your GitHub account."
---

# Table: github_audit_log - Query GitHub Audit logs

The `github_audit_log` table allows you to query data from GitHub Audit logs. This table provides detailed information about activity performed within your GitHub account, including the event name, source IP address, user identity, and more.

## Configure

Create a [partition](https://tailpipe.io/docs/manage/partition) for `github_audit_log` ([examples](https://hub.tailpipe.io/plugins/turbot/github/tables/github_audit_log#example-configurations)):

```sh
vi ~/.tailpipe/config/github.tpc
```

```hcl
partition "github_audit_log" "my_logs" {
  source "file"  {
    paths = ["/path/to/your/local/dir"]
    file_layout = "export-turbot-%{NUMBER:prefix}.json"
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

**[Explore 100+ example queries for this table →](https://hub.tailpipe.io/plugins/turbot/github/queries/github_audit_log)**

### Suspicious repository deletions

Identify suspicious repository deletions by users.

```sql
select 
  actor, 
  repo, 
  created_at 
from
  github_audit_log 
where
  action = 'repo.destroy'
order by created_at desc;

```

### Force push detection

Detect force pushes to protected branches.

```sql
select 
  actor, 
  action,
  repo, 
  pull_request_url, 
  created_at 
from 
  github_audit_log 
where 
  action = 'protected_branch.force_push'
order by created_at desc;
```

### Repository visibility changes

Track public repository visibility changes.

```sql
select 
  actor, 
  repo, 
  visibility, 
  created_at 
from 
  github_audit_log 
where 
  action = 'repo.change_visibility' 
  and visibility = 'public'
order by created_at desc;
```

### Top 10 events

List the top 10 events group by repository and how many times they were called.

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
  action_count desc
limit 10;
```

## Example Configurations

### Collect logs from local files

You can also collect GitHub audit logs from local file.

```hcl
partition "github_audit_log" "audit_log" {
  source "file"  {
	paths = ["/Users/path/dir"]
	file_layout = "export-turbot-%{NUMBER:prefix}.json"
  }
}
```

### Exclude read-only events

Use the filter argument in your partition to exclude read-only events and reduce the size of local log storage.

```hcl
partition "github_audit_log" "my_logs_write" {
  # Avoid saving read-only events, which can drastically reduce local log size
  filter = "action ilike '%view%' or action ilike '%login%' or action ilike '%access%' or action ilike '%check%'"

  source "file"  {
	paths = ["/Users/path/dir"]
	file_layout = "export-turbot-%{NUMBER:prefix}.json"
  }
}
```