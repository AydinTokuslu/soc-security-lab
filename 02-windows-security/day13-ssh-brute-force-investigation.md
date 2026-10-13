# Day 13 — SSH Brute Force Detection & Incident Investigation

## 1. Objective

The objective of this lab was to investigate SSH authentication events on a Linux system, identify repeated failed login attempts, correlate source IP addresses with authentication activity, and validate a basic brute-force detection rule.

## 2. Lab Environment

| Component | Configuration |
|---|---|
| Virtualization | VMware Workstation |
| SSH Server | Kali Linux |
| SSH Server IP | 192.168.187.129 |
| SSH Client | Windows 10 |
| SSH Client IP | 192.168.187.132 |
| Protocol | SSH / TCP 22 |
| Target Account | aydintokuslu |
| Log Source | systemd journal / ssh.service |

All authentication attempts were performed in an authorized, isolated home laboratory.

## 3. SSH Service Verification

The OpenSSH server package was installed but initially inactive.

The service was started manually:

```bash
sudo systemctl start ssh
systemctl status ssh --no-pager
sudo ss -tlnp | grep sshd
```

The SSH service successfully started and listened on TCP port 22 over IPv4 and IPv6.

Connectivity from Windows 10 was verified using:

```powershell
Test-NetConnection 192.168.187.129 -Port 22
```

Result: `TcpTestSucceeded : True`

## 4. Authentication Event Investigation

A successful SSH authentication was first observed at 16:02:22.

```text
Accepted password for aydintokuslu from 192.168.187.132 port 61722 ssh2
```

A separate failed authentication occurred at 16:05:33.

```text
Failed password for aydintokuslu from 192.168.187.132 port 58282 ssh2
```

Five additional failed authentication attempts were then deliberately generated from the Windows 10 client.

### Authentication Timeline

| Timestamp | Event | Source IP |
|---|---|---|
| 16:02:22 | Successful password authentication | 192.168.187.132 |
| 16:05:33 | Failed password authentication | 192.168.187.132 |
| 16:07:37 | Failed password authentication | 192.168.187.132 |
| 16:07:42 | Failed password authentication | 192.168.187.132 |
| 16:07:47 | Failed password authentication | 192.168.187.132 |
| 16:07:53 | Failed password authentication | 192.168.187.132 |
| 16:08:05 | Failed password authentication | 192.168.187.132 |

The five simulated failures occurred within 28 seconds.

## 5. Log Analysis

SSH authentication events were investigated using:

```bash
sudo journalctl -u ssh --since "10 minutes ago" --no-pager
```

Relevant events included:

- `Accepted password`: successful authentication
- `Failed password`: failed authentication attempt
- `pam_unix(sshd:auth): authentication failure`: PAM authentication failure
- `Connection reset ... [preauth]`: connection terminated before authentication was completed

PAM authentication failures and corresponding SSH failed-password messages were not counted as separate login attempts.

## 6. Detection Rule Validation

The following detection logic was evaluated:

**Trigger an alert when the same source IP generates at least five failed SSH password authentications against the same user within 60 seconds.**

The laboratory events met this condition.

A time-window-based count was performed using:

```bash
sudo journalctl -u ssh --since "2026-10-13 16:07:30" --until "2026-10-13 16:08:10" --no-pager | grep "Failed password" | wc -l
```

Result:

```text
5
```

Source IP aggregation was performed using:

```bash
sudo journalctl -u ssh --since "2026-10-13 16:07:30" --until "2026-10-13 16:08:10" --no-pager | grep "Failed password" | awk '{for(i=1;i<=NF;i++) if($i=="from") print $(i+1)}' | sort | uniq -c | sort -nr
```

Result:

```text
5 192.168.187.132
```

The observed events met the laboratory threshold. Detection was validated manually rather than through a deployed SIEM alert.

## 7. Incident Assessment

| Field | Finding |
|---|---|
| Detection | Repeated SSH Authentication Failures |
| Source IP | 192.168.187.132 |
| Destination IP | 192.168.187.129 |
| Target Account | aydintokuslu |
| Failed Attempts | 5 within 28 seconds |
| Authentication Method | Password |
| Successful Login After Failures | Not observed in the provided evidence |
| Classification | Authorized Brute-Force Simulation |
| Severity | Low (laboratory context) |
| Account Compromise | No evidence observed |

The pattern demonstrates behavior that may trigger brute-force detection in a production SOC.

However, the activity was intentionally generated for testing. No unauthorized access or account compromise was identified.

## 8. Recommended Defensive Measures

For a production Linux environment, relevant security controls include:

- Restricting SSH access to trusted networks.
- Disabling password-based authentication where SSH keys can be used securely.
- Applying rate limiting or tools such as Fail2ban.
- Monitoring repeated authentication failures.
- Correlating failed authentication attempts with subsequent successful logins.
- Centralizing SSH logs in a SIEM platform.

## 9. Conclusion

This laboratory demonstrated how a SOC analyst can investigate SSH authentication activity using Linux system logs.

Key skills practiced:

- SSH service verification
- Authentication log analysis
- Identification of failed and successful SSH logins
- Source IP correlation
- Time-window-based event counting
- Brute-force detection logic
- Incident classification and documentation

**Final Assessment:** The laboratory successfully reproduced and identified repeated SSH authentication failures originating from a single source IP. The activity was authorized, and no account compromise was observed.