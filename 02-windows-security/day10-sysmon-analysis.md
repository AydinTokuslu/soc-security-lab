# Day 10 — Sysmon Event Analysis

## 1. Objective

Install and configure Microsoft Sysmon on a Windows 10 virtual machine and investigate process creation, DNS queries, and network connections using Sysmon event logs.

## 2. Lab Environment

- Operating System: Windows 10 Pro
- Hostname: DESKTOP-5NH986E
- Domain: corp.example.test
- Monitoring Tool: Microsoft Sysmon v15.22
- Log Source: Microsoft-Windows-Sysmon/Operational
- Network: VMware NAT (192.168.187.132)

## 3. Sysmon Configuration

Sysmon was installed successfully and configured to collect the following event types:

| Event ID | Description |
|---|---|
| 1 | Process Creation |
| 3 | Network Connection |
| 22 | DNS Query |

SHA-256 hashing was enabled.

## 4. Process Creation Analysis

A Notepad process was launched from PowerShell.

Observed evidence:

- Image: C:\Windows\System32\notepad.exe
- Process ID: 7308
- Parent Image: powershell.exe
- Parent Process ID: 4204
- User: DESKTOP-5NH986E\aydin
- Integrity Level: High
- Event ID: 1

Sysmon provided additional telemetry such as ProcessGuid, ParentProcessGuid, command-line information, and the executable's SHA-256 hash.

## 5. DNS Query Analysis

A DNS query was generated using PowerShell.

Observed evidence:

- Event ID: 22
- QueryName: www.microsoft.com
- QueryStatus: 0
- Process: powershell.exe
- Process ID: 4204
- Returned IPv4 address: 2.23.246.101

The response included CNAME records associated with Akamai CDN infrastructure.

## 6. Network Connection Analysis

A TCP connection test was performed using Test-NetConnection.

Observed evidence:

- Event ID: 3
- Process: powershell.exe
- Source IP: 192.168.187.132
- Destination IP: 23.52.181.212
- Destination Port: 443
- Protocol: TCP
- Initiated: true
- TCP connection test: Successful

## 7. Event Correlation

Sysmon events were correlated using the ProcessGuid of the PowerShell process.

The investigation linked:

- Process creation events involving Notepad and Sysmon
- DNS queries for www.microsoft.com
- An outbound TCP connection to port 443

The process creation events were linked through ParentProcessGuid, while the DNS and network events used the process's own ProcessGuid.

The DNS and network events involved the same PowerShell process, although the observed DNS responses and connection destination did not all contain the same IP address.

## 8. Security Assessment

**Classification: Benign — Authorized Lab Activity**

All observed actions were deliberately generated during the security laboratory exercise.

No malicious activity was identified from the collected evidence.

## 9. Key Lessons Learned

- Sysmon provides detailed endpoint telemetry beyond standard Windows Security Event Logs.
- Event ID 1 identifies process creation and parent-child relationships.
- Event ID 22 records DNS queries and their associated processes.
- Event ID 3 records network connection metadata.
- ProcessGuid helps correlate events belonging to the same process.
- Multiple event types should be correlated before assessing potentially suspicious behavior.