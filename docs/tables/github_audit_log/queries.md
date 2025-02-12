## Activity Examples

### Daily activity trends

Count events per day to identify activity trends over time.

```sql
select
  strftime(timestamp, '%Y-%m-%d') as event_date,
  count(*) as event_count
from
  github_audit_log
group by
  event_date
order by
  event_date asc;
```

### Top 10 events

List the 10 most frequently called actions.

```sql
select
  action,
  count(*) as action_count
from
  github_audit_log
group by
  action
order by
  action_count desc
limit 10;
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

### Bot activity

Count actions performed by bots.

```sql
select
  actor,
  action,
  count(*) as action_count
from
  github_audit_log
where
  (additional_fields -> 'actor_is_bot')
group by
  actor,
  action
order by
  action_count desc;
```

## Detection Examples

### Activity from unapproved IP addresses

Flag activity originating from IP addresses outside an approved list.

```sql
select
  timestamp,
  actor,
  actor_ip,
  action,
  org,
  repo
from
  github_audit_log
where
  tp_source_ip not in ('192.0.2.146', '206.253.208.100')
order by
  timestamp desc;
```

### Frequent user IP address changes

Flag users with frequent IP address changes, which may indicate unauthorized access attempts.

```sql
select
  actor,
  count(distinct tp_source_ip) as ip_changes
from
  github_audit_log
group by
  actor
having
  count(distinct tp_source_ip) > 10
order by
  ip_changes desc;
```

### Repository vulnerability alerts disabled

Detect when vulnerability alerts were disabled in a repository.

```sql
select
  timestamp,
  actor
  repo
from
  github_audit_log
where
  action = 'repository_vulnerability_alerts.disable'
order by
  timestamp desc;
```

### Repository secret scanning disabled

Detect when secret scanning was disabled in a repository.

```sql
select
  timestamp,
  actor,
  repo
from
  github_audit_log
where
  action = 'repository_secret_scanning.disable'
order by
  timestamp desc;
```

### Organization IP allow list modifications

Detect when IP allow lists are modified (only available in [GitHub Enterprise](https://docs.github.com/en/enterprise-cloud@latest/admin/overview/about-github-for-enterprises)), which can impact network access restrictions.

```sql
select
  timestamp,
  actor,
  action,
  org,
  additional_fields
from
  github_audit_log
where
  action like 'ip_allow_list.%'
  or action like 'ip_allow_list_entry.%'
order by
  timestamp desc;
```

## Operational Examples

### List organization membership changes

Track changes to organization memberships.

```sql
select
  timestamp,
  actor,
  action,
  user
from
  github_audit_log
where
  action in ('org.add_member', 'org.remove_member')
order by
  timestamp desc;
```

### List team membership changes

Track changes to team memberships.

```sql
select
  timestamp,
  actor,
  action,
  user,
  additional_fields ->> 'team' as team
from
  github_audit_log
where
  action in ('team.add_member', 'team.remove_member')
order by
  timestamp desc;
```

## Volume Examples

### Frequent branch protection overrides

Identify repository administrators who frequently override branch protection requirements.

```sql
select
  actor,
  repo,
  additional_fields ->> 'branch' as branch,
  count(*) as branch_protection_overrides
from
  github_audit_log
where
  action = 'protected_branch.policy_override'
group by
  actor,
  repo,
  branch
having
  branch_protection_overrides > 20
order by
  branch_protection_overrides desc;
```

### Frequent personal access token access grants

Identify users who frequently grant fine-grained personal access tokens access to resources, which may indicate excessive or unintended token usage.

```sql
select
  actor,
  count(*) as access_token_grants
from
  github_audit_log
where
  action = 'personal_access_token.access_granted'
group by
  actor
having
  access_token_grants > 5
order by
  access_token_grants desc;
```

## Baseline Examples

### Activity outside of normal hours

Flag activity occurring outside of standard working hours, e.g., activity bewteen 8 PM and 6 AM.

```sql
select
  timestamp,
  actor,
  actor_ip,
  action,
  repo
from
  github_audit_log
where
  (
    cast(strftime(timestamp, '%H') as integer) >= 20 -- 8 PM
    or cast(strftime(timestamp, '%H') as integer) < 6 -- 6 AM
  )
  and actor is not null
order by
  timestamp desc;
```
