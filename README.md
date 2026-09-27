## Overview

Investigation of a simulated compromise on host `portal-app03`, correlating SSH authentication logs (`syslog`) and web portal access logs (`access_combined`). Unlike a typical brute-force flood, this attacker used a **slow, low-volume password spray**, one login attempt per username, rotated across four source IPs on the same subnet, spread over several hours to avoid tripping simple failed-login thresholds. Once a valid account was compromised, the attacker abused an **Insecure Direct Object Reference (IDOR)** in a backup-download endpoint to enumerate and download files they had no business accessing.

## Environment

| Item | Value |
|---|---|
| Index | `practice_log2` |
| Sourcetypes | `syslog` (SSH/auth), `access_combined` (web access) |
| Hosts | `portal-app03`|
| Log date | 2026-10-03 |
| Attacker IPs | `45.155.204.11`, `.22`, `.33`, `.44` (same /24 subnet) |
| Compromised account | `rvillanueva`, via IP `45.155.204.33` |

## Methodology

### 1. Failed logins by source IP (baseline check)

```spl
index="practice_log2" "failed"
| rex "(?<user>\w+) from"
| rex "from (?<src_ip>\d+\.\d+\.\d+\.\d+)"
| stats dc(user) as distinct_users, values(user) as usernames by src_ip
| sort -distinct_users
```
**Result:** Each of the four attacker IPs shows a low raw failure count individually, but each one targets 5–6 **different** usernames rather than repeating one — the signature of a spray, not a flood. A naive `stats count by src_ip` would have missed this, since no single IP crosses an obvious volume threshold.

<img width="1217" height="684" alt="Screenshot (511)" src="https://github.com/user-attachments/assets/180c93a5-ba13-409c-962f-92cf2cd84be4" />

---

### 2. Spray time span

```spl
index="practice_log2" "failed"
| rex "(?<user>\w+) from (?<src_ip>\d+\.\d+\.\d+\.\d+)"
| stats dc(user) as distinct_users, values(user) as usernames, earliest(_time) as first_seen, latest(_time) as last_seen by src_ip
| eval first_seen=strftime(first_seen,"%Y-%m-%d %H:%M:%S")
| eval last_seen=strftime(last_seen,"%Y-%m-%d %H:%M:%S")
| sort -distinct_users
```
**Result:** The spray runs from roughly 09:10 to 14:04 — nearly 5 hours — with attempts deliberately spaced minutes apart and rotated across IPs on the same `/24` subnet, consistent with automated spray tooling designed to blend into normal traffic and evade per-IP rate limiting.

<img width="1485" height="687" alt="Screenshot 2026-09-27 191329" src="https://github.com/user-attachments/assets/d728278d-4cf8-4098-a04e-74515aec8c4e" />

---

### 3. Successful login

```spl
index="practice_log2" "accepted" "45.155.204."
| rex "for (?<user>\w+) from (?<src_ip>\d+\.\d+\.\d+\.\d+)"
| table user, src_ip, _time
```
**Result:** At **14:21:00**, the spray succeeded. `rvillanueva`'s password was accepted from `45.155.204.33`, ending the spray campaign.

<img width="1487" height="219" alt="Screenshot 2026-09-27 1915061" src="https://github.com/user-attachments/assets/515174ba-d3e0-47fb-8c44-5f00f6021f4a" />

---

### 4. IDOR enumeration on backup downloads

```spl
index="practice_log2" sourcetype="access_combined" "45.155.204.33"
| table _time, uri
| sort _time
```
**Result:** Starting at 14:29:00, the attacker browsed the portal briefly, then requested `/backups/download?file_id=` with sequentially incrementing IDs (1001 through 1014). No SQL injection or exploitation was needed. Simply changing a number in the URL exposed files belonging to other backups, indicating the endpoint does not verify the requester is authorized to access each specific file.

<img width="1486" height="744" alt="Screenshot 2026-09-27 1917402" src="https://github.com/user-attachments/assets/9d14f58d-f44a-4fb8-a234-e82985af5949" />

---

### 5. Scope of data downloaded

```spl
index="practice_log2" sourcetype="access_combined" "45.155.204.33" "/backups/download"
| stats count as downloaded, sum(bytes) as total_bytes
```
**Result:** 15 files were tried to be downloaded the attacker with a size of more than ~30MB

<img width="1485" height="183" alt="Screenshot 2026-09-27 1919073" src="https://github.com/user-attachments/assets/2e3ecfca-03a0-40e6-aecc-d9920956321b" />

---

### 6. One blocked request

```spl
index="practice_log2" sourcetype="access_combined" "45.155.204.33" "403"
| table uri, _raw
```
**Result:** `file_id=1009` was denied (HTTP 403) — some access control exists on at least one file — but this did not stop the attacker from continuing to the next ID and successfully downloading the remaining 13.

<img width="1483" height="194" alt="Screenshot 2026-09-27 1923594" src="https://github.com/user-attachments/assets/5bd7047e-2e3a-4d22-96e2-56f37aaf1f47" />

---

### 7. Largest file taken

```spl
index="practice_log2" sourcetype="access_combined" "45.155.204.33"
| sort -bytes
| table bytes, uri
```
**Result:** `file_id=1013` was by far the largest download (~18 MB), dwarfing the other backup files (roughly 0.5–2.2 MB each). It is likely a full database or archive backup rather than an incremental one.

<img width="1485" height="397" alt="Screenshot 2026-09-27 1924545" src="https://github.com/user-attachments/assets/b48bba1d-dff0-40db-955a-23d81d192303" />

---

## Timeline

| Time | Event |
|---|---|
| 09:10 – 14:04 | Slow password spray: 22 usernames tried, one attempt each, rotated across 4 IPs on the same subnet |
| 14:21 | Spray succeeds. `rvillanueva`'s password accepted from `45.155.204.33` |
| 14:21 | SSH session opened for `rvillanueva` |
| 14:29 | (8 min after login) Attacker begins browsing the web portal from the same IP |
| 14:29 – 14:30 | Sequential IDOR enumeration of `/backups/download?file_id=1001` through `1014` |
| 14:29 | `file_id=1009` blocked (403), the only exception in the sequence |
| 14:30 | Largest file downloaded, `file_id=1013`|

## Findings summary

| Technique | Vulnerability exploited | What it gave the attacker |
|---|---|---|
| Slow password spray | Weak/reused password on `rvillanueva`'s account; no spray-pattern detection (only per-IP/per-user thresholds) | Valid portal login credentials |
| IDOR on backup endpoint | No per-file authorization check, only that a valid session exists | Access to 13 backup files belonging to other data, including one large (~18 MB) archive |

As with the prior investigation, these are two distinct weaknesses used in sequence, not one vulnerability enabling the other: a stronger password policy would have stopped the spray but not the IDOR; fixing the IDOR would have stopped the data theft even if the account had still been compromised.

## Recommendations

- Detect password spray patterns explicitly — alert on a source IP (or subnet) triggering failed logins against many distinct usernames within a time window, not just high volume against one account
- Enforce MFA on all accounts, especially ones with portal/backup access
- Fix the IDOR: verify the authenticated user is authorized for the *specific* `file_id` requested, not just that they are logged in
- Investigate why `file_id=1009` was blocked but the rest were not — apply that control consistently across all files
- Alert on sequential/incrementing parameter values in URLs, a common signature of enumeration attacks
- Alert on unusually large or repeated file downloads from a single session

---

*Logs analyzed in Splunk (index `practice_log2`). SPL queries and results above reproduce the investigation steps for reference. All data is synthetic and generated for practice purposes.*
