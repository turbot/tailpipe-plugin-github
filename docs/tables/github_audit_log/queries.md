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
  repo,
  count(*) as action_count
from
  github_audit_log
where
  actor is not null -- Exclude system events
  and action = 'pull_request.create'
group by
  actor
order by
  action_count desc
limit 10;
```

### Activity from unapproved IP addresses

Identify activities originating from IP addresses that are not in the approved list.

```sql
select
  actor,
  timestamp,
  tp_source_ip
from
  github_audit_log
where
  and tp_source_ip not in ('192.0.2.146', '206.253.208.100')
group by
  actor,
  tp_source_ip;
```

## GitHub Security Threat Detection Queries

### Disabled security features

Tracks actions that disable critical security features, which may indicate potential security risks.

```sql
select
  timestamp,
  actor,
  action,
  repo
from
  github_audit_log
where
  action in ('dependabot_alerts.disable', 'secret_scanning.disable')
group by
  actor,
  action;
```

### Frequent IP address changes

Flags users with frequent IP address changes, which may indicate unauthorized access attempts.

```sql
select
  actor,
  tp_source_ip,
  count(*) as ip_changes
from
  github_audit_log
group by
  actor,
  tp_source_ip
having
  count(distinct tp_source_ip) > 5;
```

### Vulnerability alerts disabled

Tracks instances where users disable vulnerability alerts, which may limit awareness of security issues.

```sql
select
  timestamp,
  actor,
  actor_ip,
  org
from
  github_audit_log
where
  action = 'repository_vulnerability_alerts.disable'
group by
  actor;
```

### IP allow list modifications

Identifies users who modify IP allow lists, which can impact network access restrictions.

```sql
select
  timestamp,
  actor,
  action,
  repo
from
  github_audit_log
where
  action in ('ip_allow_list_entry.create', 'ip_allow_list_entry.destroy')
  and actor_ip in ('192.0.2.146', '206.253.208.100');
```

### Secret scanning disabled

Tracks instances where users disable secret scanning, reducing the ability to detect exposed credentials.

```sql
select
  timestamp,
  actor,
  action,
  additional_fields ->> 'public_repo' as public_repo,
  additional_fields ->> 'user_agent' as user_agent,
from
  github_audit_log
where
  action = 'repository_secret_scanning.disable';
```

## Volume Examples

### Frequent repository visibility changes to public

Identifies users who have changed repository visibility to public multiple times, which may increase the risk of unintended data exposure.

```sql
select
  actor,
  count(*) as visibility_changes
from
  github_audit_log
where
  action = 'repo.access'
  and (additional_fields ->> 'visibility') = 'public'
group by
  actor
having
  visibility_changes > 3;
```

### Frequent personal access token access granted

Identifies users who frequently grant fine-grained personal access tokens access to resources, which may indicate excessive or unintended token usage.

```sql
select
  actor,
  count(*) as token_access_count
from
  github_audit_log
where
  action = 'personal_access_token.access_granted'
group by
  actor
having
  token_access_count > 5;
```

### Frequent branch protection overrides

Identifies repository administrators who frequently override branch protection requirements, which may impact enforcement of repository policies.

```sql
select
  actor,
  additional_fields ->> 'branch' as branch,
  count(*) as branch_protection_changes
from
  github_audit_log
where
  action = 'protected_branch.policy_override'
group by
  actor,
  branch
having
  branch_protection_changes > 3;
```

## Baseline Examples

### Activity outside of normal hours

Flag activity occurring outside of standard working hours, e.g., activity bewteen 8 PM and 6 AM.

```sql
select
  timestamp,
  action,
  actor,
  repo,
  operation_type
from
  github_audit_log
where
  cast(strftime(timestamp, '%H') as integer) >= 20 -- 8 PM
  or cast(strftime(timestamp, '%H') as integer) < 6 -- 6 AM
order by
  timestamp desc;
```

## Operational Examples

### Issue comment updated or deleted by bot

Identifies issue comments that were updated or deleted by a bot, helping track automated modifications and prevent unintended content changes.

```sql
select
  timestamp,
  actor,
  action,
  repo as repository,
  operation_type,
  (additional_fields ->> 'programmatic_access_type') as programmatic_access_type,
  (additional_fields ->> 'actor_is_bot') as actor_is_bot
from
  github_audit_log
where
  action in ('issue_comment.update', 'issue_comment.destroy')
  and actor_is_bot;
```

### Repository default workflow permission changes

Tracks modifications to the workflow execution settings, including restricting workflows from forks.

```sql
select
  timestamp,
  actor,
  repo,
  operation_type,
  (additional_fields ->> 'public_repo') as is_public_repo,
  created_at
from
  github_audit_log
where
  action = 'repo.set_default_workflow_permissions'
order by
  created_at desc;
```

### List Organization Membership Changes

Monitor users being added or removed from an organization.

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

### Monitor Team and Role Assignments

Identify when users are added or removed from teams.

```sql
select
  timestamp,
  actor,
  action,
  user,
  additional_fields ->> 'team' as team_name
from
  github_audit_log
where
  action in ('team.add_member', 'team.remove_member')
order by
  timestamp desc;
```
