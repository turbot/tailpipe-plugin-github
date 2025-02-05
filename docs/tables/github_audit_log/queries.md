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

List the 10 most frequently called events.

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

### Top 10 actors

Retrieve the top 10 actors based on their activity or influence within the GitHub organization.

```sql
select
  actor,
  count(*) as action_count
from
  github_audit_log
group by
  actor
order by
  action_count desc
limit 10;
```

### Activity from unapproved IP addresses

Flag activity originating from IP addresses outside an approved list.

```sql
select
  actor,
  tp_source_ip
from
  github_audit_log
where
  and tp_source_ip not in ('trusted_ip_1', 'trusted_ip_2')
group by
  actor, 
  tp_source_ip;
```

## GitHub Security Threat Detection Queries

### Identify changes to sensitive settings

Flags users who frequently modify security-related settings, potentially indicating tampering.

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

### Detect bulk member removals

Flags bulk removal of members, which could indicate malicious intent or unauthorized actions.

```sql
select
  actor,
  count(*) as members_removed
from
  github_audit_log
where
  action = 'org.remove_member'
group by
  actor
having
  members_removed > 5;
```

### Detect disabled security features

Monitors for actions that disable critical security features, potentially compromising security.

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

### Detect suspicious IP address changes

Monitors users with frequent IP address changes, which could indicate unauthorized access attempts.

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

### Identify frequent code deletion events

Flags users who delete code frequently, potentially indicating unauthorized actions.

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

### Identify disabled vulnerability alerts

Detects actors who frequently disable vulnerability alerts, which may indicate attempts to obscure vulnerabilities.

```sql
select
  actor,
  count(*) as vulnerability_alerts_disabled
from
  github_audit_log
where
  action = 'repository_vulnerability_alerts.disable'
group by
  actor
having
  vulnerability_alerts_disabled > 2;
```

### Detect IP allow list changes

Flags users who alter IP allow lists, potentially bypassing security controls.

```sql
select
  actor,
  count(*) as ip_allow_list_changes
from
  github_audit_log
where
  action in ('ip_allow_list_entry.create', 'ip_allow_list_entry.destroy')
group by
  actor
having
  ip_allow_list_changes > 2;
```

### Detect disabled secret scanning

Flags actors disabling secret scanning, potentially compromising security.

```sql
select
  actor,
  count(*) as secret_scanning_disabled
from
  github_audit_log
where
  action = 'secret_scanning.disable'
group by
  actor;
```

## Volume Examples

### Identify excessive repository visibility changes

Detects frequent changes to repository visibility, which could signal unauthorized actions.

```sql
select
  actor,
  count(*) as visibility_changes
from
  github_audit_log
where
  action = 'repository_visibility_change.enable'
group by
  actor
having
  visibility_changes > 3;
```

### Frequent personal access token access

Flags actors frequently accessing resources using personal access tokens, which may indicate token abuse.

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

### Identify frequent branch protection changes

Flags actors who frequently modify branch protection settings, which may indicate tampering.

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
  (additional_fields ->> 'repo') as repository,
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
``