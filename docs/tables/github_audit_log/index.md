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

**[Explore 20+ example queries for this table →](https://hub.tailpipe.io/plugins/turbot/github/queries/github_audit_log)**

### Track enforced branch protection rule changes

Monitors modifications to branch protection rules to prevent unauthorized changes that could compromise repository security and compliance.

```sql
select 
  actor, 
  actor_ip, 
  org
from 
  github_audit_log 
where 
  action in ('repo.protected_branch.update_rule', 'repo.protected_branch.disable_rule')
order by 
  created_at desc;
```

### Force pushes against protected branches

Detects force pushes on protected branches to prevent history rewrites, ensuring code integrity and auditability.

```sql
select 
  actor, 
  action,
  created_at 
from 
  github_audit_log 
where 
  action = 'protected_branch.force_push'
order by 
  created_at desc;
```

### Repository visibility changed to public

Tracks changes in repository visibility to prevent accidental or unauthorized exposure of sensitive code.

```sql
select 
  actor,
  (additional_fields ->> 'visibility') as visibility,
  created_at 
from 
  github_audit_log 
where 
  action = 'repo.change_visibility'
  and visibility = 'public'
order by 
  created_at desc;
```

### Detect vulnerability alert disabled

Identifies repositories where security alerts were disabled, ensuring continuous vulnerability monitoring and risk mitigation.

```sql
select 
  actor, 
  org, 
  additional_fields, 
  created_at 
from 
  github_audit_log 
where 
  action = 'repo.disable_vulnerability_alerts'
order by 
  created_at desc;
```

## Example Configurations

### Collect logs from local files

Collect GitHub audit logs exported locally as JSON.

```hcl
partition "github_audit_log" "audit_log" {
  source "file"  {
    paths = ["/Users/path/dir"]
    file_layout = "export-turbot-%{NUMBER:prefix}.json"
  }
}
```

### Exclude read-only events

Use the filter argument in your partition to filter out events like issue comments.

```hcl
partition "github_audit_log" "my_logs_write" {
  filter = "action ilike '%issue_comment%'"

  source "file"  {
    paths = ["/Users/path/dir"]
    file_layout = "export-turbot-%{NUMBER:prefix}.json"
  }
}
```