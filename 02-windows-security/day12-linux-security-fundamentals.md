# Day 12 — Linux Security Fundamentals & Authentication Log Analysis

## 1. Objective

Investigate Linux user accounts, privilege assignments, file permissions, running processes, services, network listeners, and authentication events using a Kali Linux virtual machine.

## 2. Lab Environment

- **Operating System:** Kali GNU/Linux Rolling
- **Kernel:** 6.19.14+kali-amd64
- **Virtualization:** VMware
- **Hostname:** kali
- **User:** aydintokuslu
- **Network:** VMware NAT
- **IP Address:** 192.168.187.129

## 3. User and Privilege Analysis

Commands used:

```bash
whoami
id
hostnamectl
getent passwd
sudo -l
```

Findings:

- The active user has UID 1000.
- The account belongs to the `sudo` group.
- The account can execute all commands through sudo under the current sudo policy.
- The root account has UID 0.
- No additional UID 0 accounts were observed in the reviewed account list.

**Security relevance:** Excessive privileges can increase the impact of account compromise. Administrative access should follow the principle of least privilege.

## 4. File Permission Analysis

Commands used:

```bash
ls -ld /home/aydintokuslu
ls -l /etc/passwd /etc/shadow /etc/sudoers
```

Observed permissions:

| Resource | Permissions |
|---|---|
| /home/aydintokuslu | drwx------ |
| /etc/passwd | -rw-r--r-- |
| /etc/shadow | -rw-r----- |
| /etc/sudoers | -r--r----- |

No unexpected permissions were identified in the reviewed resources.

## 5. Process and Service Analysis

Commands used:

```bash
ps aux --sort=-%cpu | head -15
ps -U root -u root -o pid,ppid,user,comm --sort=pid | head -25
systemctl list-units --type=service --state=running --no-pager
sudo ss -tulnp
```

Findings:

- Standard system and desktop processes were observed.
- Twenty running system services were listed.
- NetworkManager, cron, systemd-journald, and VMware Tools were running.
- No listening TCP/UDP sockets were reported by the socket inspection command.
- The SSH server was not observed among the running services.

## 6. Authentication Log Investigation

**Incident:** Local authentication failure

**Date:** October 13, 2026

**Affected account:** aydintokuslu

**Authentication mechanism:** PAM / LightDM

### Timeline

| Time | Event |
|---|---|
| 09:47:56 | LightDM greeter session opened |
| 09:48:37 | Password verification failed |
| 09:48:37 | PAM authentication failure recorded |
| 09:48:49 | User session successfully opened |
| 09:48:49 | X11 user session created |
| 09:58:24 | User session closed |
| 10:00:39 | User successfully logged in after reboot |

### Evidence

```text
unix_chkpwd: password check failed for user (aydintokuslu)

pam_unix(lightdm:auth): authentication failure

pam_unix(lightdm:session): session opened for user aydintokuslu(uid=1000)
```

### Analysis

The event originated from the local graphical login service rather than a remote SSH connection.

One authentication failure was followed by a successful login approximately 12 seconds later.

No evidence of repeated password guessing or remote brute-force activity was identified within the reviewed log window.

### Classification

- **Severity:** Low
- **Disposition:** Likely Benign
- **Confidence:** Moderate
- **Recommended Action:** No immediate response required; retain evidence and investigate if similar failures recur unexpectedly.

## 7. Network Configuration Observation

NetworkManager reported an IP configuration failure during startup:

```text
state change: ip-config -> failed
reason 'ip-config-unavailable'
```

The system subsequently attempted to reactivate the network connection.

Later connectivity tests confirmed a valid DHCP address, working default route, external IP reachability, and DNS resolution.

This suggests a transient startup connectivity issue, although the underlying cause was not conclusively established.

## 8. Key Lessons Learned

- Linux uses UID, GID, groups, and sudo policies to manage privileges.
- File permissions control access to sensitive system resources.
- Process and service analysis helps identify potentially suspicious activity.
- `journalctl` provides valuable authentication and system event evidence.
- A single failed authentication event does not automatically indicate an attack.
- SOC investigations should correlate events chronologically before assigning severity.

## 9. Conclusion

The Kali Linux environment was examined using standard Linux administration and security investigation commands.

One local authentication failure was identified and correlated with a subsequent successful login.

The reviewed evidence supports a likely benign classification, with no clear indicators of malicious activity.