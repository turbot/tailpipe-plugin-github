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

### Top 10 pull requester authors

List the top 10 pull request authors and how many pull requests they've created.

```sql
select
  actor,
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

### Frequent changes to security settings

Flags users who frequently modify security-related settings or secrets, potentially indicating suspicious activity.

```sql
select
  actor,
  count(*) as setting_changes
from
  github_audit_log
where
  action in ('org.update_actions_settings', 'org.update_actions_secret')
group by
  actor
having
  setting_changes > 3;
```

### Disabled security features

Tracks actions that disable critical security features, which may indicate potential security risks.

```sql
select
  actor,
  action,
  count(*) as disable_actions
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

### Frequent code deletion

Identifies users who frequently remove repository topics, which may impact project organization and discoverability.

```sql
select
  actor,
  count(*) as code_deletions
from
  github_audit_log
where
  action = 'repo.remove_topic'
group by
  actor
having
  code_deletions > 3;
```

### Vulnerability alerts disabled

Tracks instances where users disable vulnerability alerts, which may limit awareness of security issues.

```sql
select
  actor,
  actor_ip,
  timestamp,
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
  actor,
  timestamp,
  action,
  repo
from
  github_audit_log
where
  action in ('ip_allow_list_entry.create', 'ip_allow_list_entry.destroy');
```

### Secret scanning disabled

Tracks instances where users disable secret scanning, reducing the ability to detect exposed credentials.

```sql
select
  actor,
  action,
  timestamp,
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
  count(*) as branch_protection_changes
from
  github_audit_log
where
  action = 'protected_branch.update_admin_enforced'
group by
  actor
having
  branch_protection_changes > 3;
```

## Operational Examples

### Issue comment updated or deleted by bot

Identifies issue comments that were updated or deleted by a bot, helping track automated modifications and prevent unintended content changes.

```sql
select
  actor,
  action,
  timestamp,
  repo as repository,
  (additional_fields ->> 'programmatic_access_type') as programmatic_access_type,
  (additional_fields ->> 'operation_type') as operation_type,
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
  actor,
  timestamp,
  (additional_fields ->> 'repo') as repository,
  (additional_fields ->> 'operation_type') as operation_type,
  (additional_fields ->> 'public_repo') as is_public_repo,
  created_at
from
  github_audit_log
where
  action = 'repo.set_default_workflow_permissions'
order by
  created_at desc;
```

### Most recent pull request reviews

Retrieves pull request reviews submitted in the last two days.

```sql
select
  actor,
  timestamp,
  (additional_fields ->> 'pull_request_title') as pull_request_title,
  (additional_fields ->> 'pull_request_url') as pull_request_url
from
  github_audit_log 
where 
  action = 'pull_request_review.submit'
  and timestamp >= cast(current_timestamp as timestamp) - interval '2 days';
```

### Advanced security disabled in repositories

Identifies instances where advanced security features were disabled for a repository.

```sql
select
  actor,
  timestamp,
  repo
from
  github_audit_log 
where 
  action = 'repo.advanced_security_disabled';
```