---
title: "Tailpipe Table: github_security_log - Query GitHub Security Logs"
description: "GitHub security logs list events triggered by activities that affect your personal account security."
---

# Table: github_security_log - Query GitHub security logs

The `github_security_log` table allows you to query data from [GitHub security logs](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/reviewing-your-security-log). This table provides detailed information about security-related activity on your personal GitHub account, including sign-in events, SSH key changes, application authorizations, personal access token usage, and more.

Limitations and notes:

- The table currently supports exported logs in JSON format.
- Security logs are available for personal accounts and contain events related to account security.

## Configure

Create a [partition](https://tailpipe.io/docs/manage/partition) for `github_security_log` ([examples](https://hub.tailpipe.io/plugins/turbot/github/tables/github_security_log#example-configurations)):

```sh
vi ~/.tailpipe/config/github.tpc
```

```hcl
partition "github_security_log" "my_security_logs" {
  source "file"  {
    paths       = ["/Users/myuser/github_security_logs"]
    file_layout = `%{DATA}.json.gz`
  }
}
```

## Collect

[Collect](https://tailpipe.io/docs/manage/collection) logs for all `github_security_log` partitions:

```sh
tailpipe collect github_security_log
```

Or for a single partition:

```sh
tailpipe collect github_security_log.my_security_logs
```

## Query

**[Explore 33+ example queries for this table →](https://hub.tailpipe.io/plugins/turbot/github/queries/github_security_log)**

### Recent login attempts

Track recent login attempts to monitor account access.

```sql
select
  timestamp,
  action,
  actor,
  tp_source_ip
from
  github_security_log
where
  action like '%login%'
order by
  timestamp desc
limit 10;
```

### Personal access token activity

Monitor personal access token creation and usage.

```sql
select
  timestamp,
  action,
  actor,
  token_scopes,
  tp_source_ip
from
  github_security_log
where
  action like 'personal_access_token.%'
order by
  timestamp desc;
```

### Two-factor authentication changes

Track changes to two-factor authentication settings.

```sql
select
  timestamp,
  action,
  actor,
  tp_source_ip
from
  github_security_log
where
  action like 'two_factor_authentication.%'
order by
  timestamp desc;
```

### Repository-specific access events

Monitor security events for specific repositories using the repositories array.

```sql
select
  timestamp,
  action,
  actor,
  repositories,
  permissions
from
  github_security_log
where
  repositories is not null
  and action like 'personal_access_token.%'
order by
  timestamp desc;
```

### Environment-related security events

Track security events associated with specific environments.

```sql
select
  timestamp,
  action,
  actor,
  environment_id,
  environment_name
from
  github_security_log
where
  environment_id is not null
order by
  timestamp desc;
```

## Example Configurations

### Collect logs from local files

Collect GitHub security logs exported locally as JSON.

```hcl
partition "github_security_log" "my_security_logs" {
  source "file"  {
    paths       = ["/Users/myuser/github_security_logs"]
    file_layout = `%{DATA}.json.gz`
  }
}
```

### Filter for high-priority security events

Use the filter argument in your partition to focus on critical security events.

```hcl
partition "github_security_log" "critical_security_events" {
  filter = "action like '%login%' or action like 'two_factor_authentication.%' or action like 'personal_access_token.%'"

  source "file"  {
    paths       = ["/Users/myuser/github_security_logs"]
    file_layout = `%{DATA}.json.gz`
  }
}
```

### Exclude routine events

Filter out routine events to focus on security-relevant activities.

```hcl
partition "github_security_log" "security_alerts" {
  filter = "action not like 'user.show_private_contributions_count' and action not like 'user.hide_private_contributions_count'"

  source "file"  {
    paths       = ["/Users/myuser/github_security_logs"]
    file_layout = `%{DATA}.json.gz`
  }
}
```
