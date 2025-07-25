## Authentication Examples

### Failed Login Attempts

Identify failed login attempts that might indicate security threats.

```sql
select
  timestamp,
  actor,
  tp_source_ip,
  user_agent
from
  github_security_log
where
  action = 'user.failed_login'
order by
  timestamp desc;
```

```yaml
folder: Authentication
```

### Two-Factor Authentication Events

Monitor all two-factor authentication related activities.

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

```yaml
folder: Authentication
```

### Successful Two-Factor Recovery

Track when two-factor authentication recovery codes were used.

```sql
select
  timestamp,
  actor,
  tp_source_ip,
  user_agent
from
  github_security_log
where
  action = 'two_factor_authentication.recovery_codes_used'
order by
  timestamp desc;
```

```yaml
folder: Authentication
```

## Access Token Examples

### Personal Access Token Creation

Monitor creation of new personal access tokens.

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
  action = 'personal_access_token.create'
order by
  timestamp desc;
```

```yaml
folder: Access Tokens
```

### Personal Access Token Usage

Track usage of personal access tokens for API access.

```sql
select
  timestamp,
  action,
  actor,
  token_id,
  token_scopes
from
  github_security_log
where
  action in ('personal_access_token.access_granted', 'personal_access_token.access_revoked')
order by
  timestamp desc;
```

```yaml
folder: Access Tokens
```

### OAuth Application Authorizations

Monitor OAuth application authorization events.

```sql
select
  timestamp,
  action,
  actor,
  oauth_application_name,
  oauth_application_id
from
  github_security_log
where
  action like 'oauth_authorization.%'
order by
  timestamp desc;
```

```yaml
folder: Access Tokens
```

### Token Regeneration Events

Track when authentication tokens were regenerated.

```sql
select
  timestamp,
  action,
  actor,
  token_id,
  tp_source_ip
from
  github_security_log
where
  action like '%regenerate%'
order by
  timestamp desc;
```

```yaml
folder: Access Tokens
```

### Repository-Specific Token Access

Monitor personal access tokens granted access to specific repositories.

```sql
select
  timestamp,
  action,
  actor,
  repositories,
  permissions,
  repository_selection
from
  github_security_log
where
  repositories is not null
  and action in ('personal_access_token.access_granted', 'personal_access_token.request_created')
order by
  timestamp desc;
```

```yaml
folder: Access Tokens
```

### Token Permission Changes

Track changes in token permissions using the old_value field.

```sql
select
  timestamp,
  action,
  actor,
  permissions_added,
  permissions_unchanged,
  permissions_upgraded,
  old_value,
  new_value
from
  github_security_log
where
  action = 'personal_access_token.request_created'
  and (permissions_added is not null or permissions_upgraded is not null)
order by
  timestamp desc;
```

```yaml
folder: Access Tokens
```

## SSH Key Management

### SSH Key Creation and Deletion

Monitor SSH key lifecycle events.

```sql
select
  timestamp,
  action,
  actor,
  key,
  fingerprint
from
  github_security_log
where
  action in ('public_key.create', 'public_key.delete')
order by
  timestamp desc;
```

```yaml
folder: SSH Keys
```

### Git Signing SSH Key Events

Track Git signing SSH key management.

```sql
select
  timestamp,
  action,
  actor,
  fingerprint
from
  github_security_log
where
  action like 'git_signing_ssh_public_key.%'
order by
  timestamp desc;
```

```yaml
folder: SSH Keys
```

### SSH Key Verification Events

Monitor SSH key verification status changes.

```sql
select
  timestamp,
  action,
  actor,
  key,
  fingerprint
from
  github_security_log
where
  action in ('public_key.verify', 'public_key.unverify', 'public_key.verification_failure')
order by
  timestamp desc;
```

```yaml
folder: SSH Keys
```

## Device and Security Management

### New Device Usage

Track when accounts are accessed from new devices.

```sql
select
  timestamp,
  actor,
  tp_source_ip,
  user_agent
from
  github_security_log
where
  action = 'user.new_device_used'
order by
  timestamp desc;
```

```yaml
folder: Device Security
```

### Passkey Registration

Monitor passkey registration and removal events.

```sql
select
  timestamp,
  action,
  actor,
  passkey_nickname
from
  github_security_log
where
  action in ('passkey.register', 'passkey.remove')
order by
  timestamp desc;
```

```yaml
folder: Device Security
```

### Security Key Management

Track security key registration and removal.

```sql
select
  timestamp,
  action,
  actor,
  fingerprint
from
  github_security_log
where
  action in ('security_key.register', 'security_key.remove')
order by
  timestamp desc;
```

```yaml
folder: Device Security
```

### Trusted Device Events

Monitor trusted device registration and removal.

```sql
select
  timestamp,
  action,
  actor,
  tp_source_ip
from
  github_security_log
where
  action in ('trusted_device.register', 'trusted_device.remove')
order by
  timestamp desc;
```

```yaml
folder: Device Security
```

## Account Management

### Email Address Changes

Track email address additions and removals.

```sql
select
  timestamp,
  action,
  actor,
  email
from
  github_security_log
where
  action in ('user.add_email', 'user.remove_email')
order by
  timestamp desc;
```

```yaml
folder: Account Management
```

### Password Changes

Monitor password change events.

```sql
select
  timestamp,
  actor,
  tp_source_ip,
  user_agent
from
  github_security_log
where
  action = 'user.change_password'
order by
  timestamp desc;
```

```yaml
folder: Account Management
```

### Profile Picture Updates

Track profile picture change events.

```sql
select
  timestamp,
  actor,
  tp_source_ip
from
  github_security_log
where
  action = 'profile_picture.update'
order by
  timestamp desc;
```

```yaml
folder: Account Management
```

## Suspicious Activity Detection

### Multiple Failed Logins

Identify potential brute force attacks with multiple failed logins.

```sql
select
  tp_source_ip,
  count(*) as failed_attempts,
  min(timestamp) as first_attempt,
  max(timestamp) as last_attempt
from
  github_security_log
where
  action = 'user.failed_login'
  and timestamp >= current_timestamp - interval '1 hour'
group by
  tp_source_ip
having
  count(*) >= 3
order by
  failed_attempts desc;
```

```yaml
folder: Security Analysis
```

### Unusual IP Address Activity

Detect access from new or unusual IP addresses.

```sql
select
  timestamp,
  actor,
  tp_source_ip,
  action,
  user_agent
from
  github_security_log
where
  tp_source_ip not in (
    select distinct tp_source_ip
    from github_security_log
    where timestamp < current_timestamp - interval '30 days'
  )
  and timestamp >= current_timestamp - interval '7 days'
order by
  timestamp desc;
```

```yaml
folder: Security Analysis
```

### Rapid Token Creation

Identify potential automated token creation attempts.

```sql
select
  actor,
  count(*) as token_creations,
  min(timestamp) as first_creation,
  max(timestamp) as last_creation
from
  github_security_log
where
  action = 'personal_access_token.create'
  and timestamp >= current_timestamp - interval '1 hour'
group by
  actor
having
  count(*) > 5
order by
  token_creations desc;
```

```yaml
folder: Security Analysis
```

## Operational Monitoring

### Daily Security Event Trends

Analyze security event patterns over time.

```sql
select
  date_trunc('day', timestamp) as event_date,
  action,
  count(*) as event_count
from
  github_security_log
where
  timestamp >= current_timestamp - interval '30 days'
group by
  event_date, action
order by
  event_date desc, event_count desc;
```

```yaml
folder: Operational
```

### Most Active Hours

Identify peak activity hours for security events.

```sql
select
  extract(hour from timestamp) as hour_of_day,
  count(*) as event_count
from
  github_security_log
where
  timestamp >= current_timestamp - interval '7 days'
group by
  hour_of_day
order by
  hour_of_day;
```

```yaml
folder: Operational
```

### Top Security Actions

List the most common security actions performed.

```sql
select
  action,
  count(*) as action_count
from
  github_security_log
group by
  action
order by
  action_count desc
limit 20;
```

```yaml
folder: Operational
```

### User Agent Analysis

Analyze user agents to understand client applications being used.

```sql
select
  user_agent,
  count(*) as usage_count,
  count(distinct actor) as unique_users
from
  github_security_log
where
  user_agent is not null
  and timestamp >= current_timestamp - interval '7 days'
group by
  user_agent
order by
  usage_count desc
limit 15;
```

```yaml
folder: Operational
```

## Integration Security

### Integration Secret Management

Monitor integration secret lifecycle events.

```sql
select
  timestamp,
  action,
  actor,
  integration
from
  github_security_log
where
  action like '%integration_secret%'
order by
  timestamp desc;
```

```yaml
folder: Integration Security
```

### OAuth Application Management

Track OAuth application lifecycle events.

```sql
select
  timestamp,
  action,
  actor,
  oauth_application_name,
  oauth_application_id
from
  github_security_log
where
  action like 'oauth_application.%'
order by
  timestamp desc;
```

```yaml
folder: Integration Security
```

### Webhook Configuration Changes

Monitor webhook-related security events.

```sql
select
  timestamp,
  action,
  actor,
  hook_id
from
  github_security_log
where
  action like 'hook.%'
order by
  timestamp desc;
```

```yaml
folder: Integration Security
```

## Environment Security

### Environment Secret Management

Monitor environment secret lifecycle events.

```sql
select
  timestamp,
  action,
  actor,
  environment_id,
  environment_name,
  key
from
  github_security_log
where
  action like 'environment.%secret%'
  and environment_id is not null
order by
  timestamp desc;
```

```yaml
folder: Environment Security
```

### Environment Protection Rule Changes

Track changes to environment protection rules.

```sql
select
  timestamp,
  action,
  actor,
  environment_id,
  environment_name,
  old_value,
  new_value
from
  github_security_log
where
  action like 'environment.%protection_rule%'
order by
  timestamp desc;
```

```yaml
folder: Environment Security
```

### Environment Variable Updates

Monitor environment variable changes with before/after values.

```sql
select
  timestamp,
  action,
  actor,
  environment_name,
  key,
  old_value,
  new_value
from
  github_security_log
where
  action in ('environment.create_actions_variable', 'environment.update_actions_variable', 'environment.remove_actions_variable')
order by
  timestamp desc;
```

```yaml
folder: Environment Security
```

## Repository Access Analysis

### Repository Access Patterns

Track which repositories are most frequently accessed via security events.

```sql
with repo_access as (
  select
    unnest(repositories) as repo_id,
    action,
    actor,
    timestamp
  from
    github_security_log
  where
    repositories is not null
)
select
  repo_id,
  count(*) as access_events,
  count(distinct actor) as unique_actors,
  max(timestamp) as last_access
from
  repo_access
group by
  repo_id
order by
  access_events desc
limit 20;
```

```yaml
folder: Repository Security
```
