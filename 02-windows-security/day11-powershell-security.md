# Day 11 — PowerShell Security and Threat Detection

## 1. Objective

Investigate PowerShell activity using Windows Event Logs and Sysmon telemetry. Enable Script Block Logging and Module Logging, identify command execution, correlate events, and detect potentially suspicious PowerShell patterns.

## 2. Lab Environment

- Operating System: Windows 10 Pro
- Active Directory Domain: corp.example.test
- Workstation: DESKTOP-5NH986E
- Test User: DESKTOP-5NH986E\aydin
- Tools: Windows PowerShell 5.1, Windows Event Logs, Sysmon

## 3. Script Block Logging — Event ID 4104

Enabled PowerShell Script Block Logging through Windows Registry policy settings.

Configuration:

- Registry Path: `HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging`
- EnableScriptBlockLogging: `1`

Executed the following command:

```powershell
Get-LocalUser
```

Observed Event ID 4104:

- TimeCreated: 2026-10-12 17:47:15
- ProcessId: 9520
- ScriptBlockText: `Get-LocalUser`

The event confirmed that PowerShell recorded the processed script block.

## 4. Sysmon Process Correlation

Investigated Sysmon Event ID 1 to identify the PowerShell process responsible for the activity.

Observed evidence:

- Process: `powershell.exe`
- ProcessId: `9520`
- User: `DESKTOP-5NH986E\aydin`
- Parent Process: `explorer.exe`
- Integrity Level: High
- TimeCreated: 2026-10-12 17:47:07
- ProcessGuid: `{abf01ad6-f2eb-6acc-8702-000000000c00}`

The PowerShell Event ID 4104 record contained the same ProcessId (`9520`), confirming process-level correlation between the two log sources.

## 5. Module Logging — Event ID 4103

Enabled PowerShell Module Logging through Windows Registry policy settings.

Configuration:

- EnableModuleLogging: `1`
- ModuleNames: `*`

After restarting PowerShell, executed:

```powershell
Get-LocalUser
```

Observed Event ID 4103:

- TimeCreated: 2026-10-12 18:05:26
- CommandInvocation: `Get-LocalUser`
- Command Type: Cmdlet
- User: `DESKTOP-5NH986E\aydin`
- Host Application: `powershell.exe`

Additional Module Logging records included `Out-Default` parameter values containing local account names.

## 6. Suspicious PowerShell Pattern Detection

Performed a controlled detection test using:

```powershell
Invoke-Expression "'SOC Lab Detection Test'"
```

The command produced the expected text without downloading files or modifying system configuration.

Observed Event ID 4104:

- TimeCreated: 2026-10-12 18:14:36
- ProcessId: 5420
- ScriptBlockText: `Invoke-Expression "'SOC Lab Detection Test'"`

The test demonstrated how potentially suspicious PowerShell command patterns can be identified through Script Block Logging.

Other PowerShell patterns relevant to security investigations include:

- `EncodedCommand`
- `Invoke-WebRequest`
- `DownloadString`
- `Invoke-Expression`

These patterns are investigation indicators, not standalone evidence of malicious activity.

## 7. MITRE ATT&CK Mapping

**T1087.001 — Account Discovery: Local Account**

The `Get-LocalUser` command can be used to enumerate local accounts. In this exercise, it was executed as part of authorized laboratory activity.

The `Invoke-Expression` test demonstrated dynamic expression execution but did not establish malicious behavior.

## 8. Security Assessment

**Classification: Benign — Authorized Lab Activity**

No malicious activity was identified.

The investigation demonstrated successful collection and analysis of:

- PowerShell Script Block Logging (4104)
- PowerShell Module Logging (4103)
- Sysmon Process Creation (1)
- Process-level event correlation
- Controlled PowerShell command-pattern detection

## 9. Key Lessons Learned

- Event ID 4104 records PowerShell script block content.
- Event ID 4103 provides command invocation and module logging details.
- Sysmon Event ID 1 records process creation and parent-child relationships.
- Process IDs, timestamps, and user context support event correlation.
- Security investigation commands may generate additional log entries.
- Suspicious command patterns require contextual analysis before classification.
- Logging configuration must be validated using actual events.