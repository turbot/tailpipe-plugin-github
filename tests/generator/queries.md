# GitHub Security Threat Detection Queries

Each query is crafted to identify potential security risks in GitHub activity logs. These queries analyze actions in the `github_audit_log` table based on common indicators of unauthorized access, unusual behavior, or tampering with sensitive configurations.

---

## 1. Detect Frequent Logins from Different Locations
Flags accounts logging in from multiple locations within a short timeframe, indicating possible credential sharing or compromise.

```sql
select
  user,
  count(distinct tp_source_location) as distinct_locations
from
  github_audit_log
where
  action = 'login'
  and tp_date >= current_date - interval '1 day'
group by
  user
having
  distinct_locations > 1;
```

---

## 2. Identify Accounts with Multiple Failed Login Attempts
Highlights accounts with multiple failed login attempts, suggesting brute force or unauthorized access attempts.

```sql
select
  user,
  count(*) as failed_logins
from
  github_audit_log
where
  action = 'login.failed'
group by
  user
having
  failed_logins > 3;
```

---

## 3. Monitor Changes to Repository Security Settings
Flags modifications to repository security settings, indicating possible tampering with security controls.

```sql
select
  user,
  repo,
  count(*) as security_changes
from
  github_audit_log
where
  action = 'repository_security_configuration.update'
group by
  user, repo
having
  security_changes > 1;
```

---

## 4. Detect Use of API Tokens from New Locations
Identifies API token usage from previously unseen locations, suggesting potential token leakage.

```sql
select
  user,
  tp_source_location,
  token_id
from
  github_audit_log
where
  action = 'token.usage'
  and tp_source_location not in (
      select tp_source_location
      from github_audit_log
      where action = 'token.usage'
      and user = github_audit_log.user
  )
group by
  user, tp_source_location, token_id;
```

---

## 5. Detect Unusual Repository Deletion Activity
Flags users who deleted multiple repositories within a short period, indicating potential unauthorized or destructive actions.

```sql
select
  user,
  count(*) as repo_deletions
from
  github_audit_log
where
  action = 'repository.delete'
  and tp_date >= current_date - interval '1 day'
group by
  user
having
  repo_deletions > 1;
```

---

## 6. Detect Unauthorized Access to Sensitive Repositories
Flags access to sensitive repositories by unauthorized accounts, indicating a potential security breach.

```sql
select
  user,
  repo
from
  github_audit_log
where
  action = 'repository.access'
  and public_repo = false
  and user not in ('trusted_user1', 'trusted_user2')
group by
  user, repo;
```

---

## 7. Identify High Frequency of Permission Changes
Flags accounts with frequent permission changes, indicating potential privilege escalation or policy violations.

```sql
select
  user,
  count(*) as permission_changes
from
  github_audit_log
where
  action = 'permission.update'
group by
  user
having
  permission_changes > 3;
```

---

## 8. Detect API Token Usage by Bot Accounts
Flags bot accounts using API tokens, which may indicate misuse of privileged access.

```sql
select
  user,
  token_id
from
  github_audit_log
where
  actor_is_bot = true
  and action = 'token.usage'
group by
  user, token_id;
```

---

## 9. Monitor High Volume of Pull Request Creation
Identifies users creating a high number of pull requests, which could be indicative of a spam attack or an automated process.

```sql
select
  user,
  count(*) as pull_request_count
from
  github_audit_log
where
  action = 'pull_request.create'
group by
  user
having
  pull_request_count > 10;
```

---

## 10. Detect Suspicious Repository Forking Activity
Flags accounts that fork multiple repositories within a short timeframe, suggesting data exfiltration or unauthorized cloning.

```sql
select
  user,
  count(*) as fork_count
from
  github_audit_log
where
  action = 'repository.fork'
  and tp_date >= current_date - interval '1 day'
group by
  user
having
  fork_count > 3;
```

---

## 11. Identify Abnormal Increases in Repository Access
Detects users with a sudden increase in access to repositories, which may indicate privilege misuse or exploration.

```sql
select
  user,
  count(*) as recent_access
from
  github_audit_log
where
  action = 'repository.access'
  and tp_date >= current_date - interval '1 day'
group by
  user
having
  recent_access > 5;
```

---

## 12. Detect Login Attempts from High-Risk Locations
Flags login attempts from high-risk or blacklisted locations, which may indicate attempted unauthorized access.

```sql
select
  user,
  tp_source_location
from
  github_audit_log
where
  action = 'login'
  and tp_source_location in ('high_risk_location_1', 'high_risk_location_2')
group by
  user, tp_source_location;
```

---

## 13. Identify Unusual Activity on Private Repositories
Flags users with activity on private repositories outside of regular hours, indicating potential unauthorized access.

```sql
select
  user,
  repo,
  count(*) as access_count
from
  github_audit_log
where
  action = 'repository.access'
  and public_repo = false
  and extract(hour from timestamp) not between 9 and 17
group by
  user, repo
having
  access_count > 1;
```

---

## 14. Monitor Sudden Changes in Repository Access Pattern
Identifies users with a sudden shift in repository access patterns, suggesting potential misuse or credential compromise.

```sql
with recent_access as (
  select
    user,
    count(*) as access_count
  from
    github_audit_log
  where
    action = 'repository.access'
    and tp_date >= current_date - interval '1 day'
  group by
    user
)
select
  user
from
  recent_access
where
  access_count > (select avg(access_count) from recent_access) * 2;
```

---

## 15. Detect Multiple Accesses from Different IPs in Short Time
Flags accounts accessing from multiple IP addresses within a short timeframe, indicating potential misuse or compromise.

```sql
select
  user,
  count(distinct tp_source_ip) as distinct_ips
from
  github_audit_log
where
  tp_date >= current_date - interval '1 day'
group by
  user
having
  distinct_ips > 1;
```

---

## 16. Monitor High Volume of Failed API Requests
Identifies accounts with high numbers of failed API requests, suggesting misconfiguration or potential abuse attempts.

```sql
select
  user,
  count(*) as failed_api_requests
from
  github_audit_log
where
  action = 'api_request.failed'
group by
  user
having
  failed_api_requests > 5;
```

---

## 17. Detect Unusual Push Activity
Flags accounts with an unusual volume of pushes, indicating potential misuse or automation abuse.

```sql
select
  user,
  count(*) as push_count
from
  github_audit_log
where
  action = 'push'
  and tp_date >= current_date - interval '20 day'
group by
  user
having
  push_count > 20;
```

---

## 18. Identify Sudden Changes in Access Frequency
Detects sudden changes in access frequency, which may indicate unauthorized use or exploration.

```sql
select
  user,
  count(*) as access_count
from
  github_audit_log
where
  action = 'repository.access'
  and tp_date >= current_date - interval '7 days'
group by
  user
having
  access_count > (select avg(access_count) * 2 from github_audit_log where action = 'repository.access');
```

---

## 19. Detect Pull Requests from New Untrusted Accounts
Flags pull requests created by newly registered or untrusted accounts, which may indicate potential spam or phishing.

```sql
select
  user,
  pull_request_id
from
  github_audit_log
where
  action = 'pull_request.create'
  and user not in ('trusted_account_1', 'trusted_account_2')
group by
  user, pull_request_id;
```

---

## 20. Monitor Unexpected High Volume of Code Changes
Flags users making a high volume of code changes in a short period, indicating potential misuse or automation abuse.

```sql
select
  user,
  count(*) as code_changes
from
  github_audit_log
where
  action in ('commit', 'push')
  and tp_date >= current_date - interval '1 day'
group by
  user
having
  code_changes > 15;
```

---