
## GitHub Security Threat Detection Queries

### Identify frequent repository deletions
Detects users who delete repositories frequently, potentially indicating unauthorized actions.

```sql
select
  actor,
  count(*) as repo_deletes
from
  github_audit_log
where
  action = 'repo.destroy'
group by
  actor
having
  repo_deletes > 3;
```

### Detect access from non-whitelisted locations
Flags access from unapproved locations, which may indicate unauthorized access or policy violations.

```sql
select
  actor,
  tp_source_location 
from
  github_audit_log 
where
  tp_source_location not in ('trusted_location_1', 'trusted_location_2') 
group by
  actor, 
  tp_source_location;
```

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

### Detect unusual access hours
Identifies access outside of standard working hours, which could signal suspicious activity.

```sql
select
  actor,
  date_part('hour', CAST(timestamp AS TIMESTAMP)) as access_hour,
  count(*) as access_count
from
  github_audit_log
group by
  actor, access_hour
having
  access_hour not between 8 and 18;
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
  actor, action;
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
  actor, tp_source_ip
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

### Detect non-standard devices or browsers
Flags login attempts from unrecognized devices or browsers, which could indicate suspicious access.

```sql
select
  actor,
  user_agent,
  count(*) as device_logins
from
  github_audit_log
group by
  actor, user_agent
having
  device_logins > 1;
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

### Identify frequent repository transfers
Detects users who frequently transfer repositories, which may indicate unauthorized actions.

```sql
select
  actor,
  count(*) as repo_transfers
from
  github_audit_log
where
  action = 'repo.transfer'
group by
  actor
having
  repo_transfers > 2;
```

### Detect disabled advanced security features
Monitors actors disabling advanced security features, potentially reducing security controls.

```sql
select
  actor,
  count(*) as advanced_security_disabled
from
  github_audit_log
where
  action in ('repo.advanced_security_disabled', 'org.advanced_security_disabled_on_all_repos')
group by
  actor;
```

### Detect frequent personal access token access
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

### Detect changes to code scanning settings
Flags actors who modify code scanning settings, potentially obscuring security issues.

```sql
select
  actor,
  count(*) as scanning_changes
from
  github_audit_log
where
  action in ('repo.codeql_enabled', 'repo.codeql_disabled')
group by
  actor;
```

### Detect programmatic access from unknown IPs
Identifies suspicious programmatic access from unknown IP addresses.

```sql
select
  actor,
  tp_source_ip
from
  github_audit_log
where
  programmatic_access_type is not null
  and tp_source_ip not in ('trusted_ip_1', 'trusted_ip_2')
group by
  actor, tp_source_ip;
```

### Identify frequent branch deletion
Flags users who delete branches often, potentially indicating unauthorized tampering.

```sql
select
  actor,
  count(*) as branch_deletions
from
  github_audit_log
where
  action = 'protected_branch.destroy'
group by
  actor
having
  branch_deletions > 3;
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

## Operational Examples

### Detect issue comment updated or deleted by bot
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

### Identify repository default workflow permission changes
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