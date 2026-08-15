# Investigation Report

## Just Another Day

Nimbus Health // Security Operations · Case NH-INC-2026-0311

---

# Part A, Core

## 1. Front matter

| **Field**            | **Value**                                                             |
| -------------------- | --------------------------------------------------------------------- |
| Report title         | Just Another Day, Investigation Report, NH-INC-2026-0311              |
| Case reference       | NH-INC-2026-0311 *(analyst-assigned; no SOC case ID was issued for this hunt)* |
| Author               | [ANALYST], SOC / Cyber Range Operations (on shift)                    |
| Version              | 1.0                                                                   |
| Date issued (UTC)    | 2026-08-15                                                            |
| Classification / TLP | TLP:AMBER, internal + trusted-party distribution                      |
| Distribution         | SOC, Clinic IT, HR, Legal/Privacy, Incident Response                  |

### Revision history

| **Version** | **Date (UTC)** | **Author** | **Change**                                                    |
| ----------- | -------------- | ---------- | ------------------------------------------------------------- |
| 1.0         | 2026-08-15     | [ANALYST]  | Initial issue, investigation complete, compromise confirmed.  |

---

## 2. Executive summary

**This is a confirmed external breach, not a staffing matter.** On 11 March 2026 an outsider used the correct passwords for two Nimbus Health employees to sign in from the public internet, and spent just under two hours inside the clinic's systems. They read the personal records of every member of staff, hid a copy of a payroll file inside the billing area under a false name, and altered a record that documents who approved billing work. The intrusion ran uninterrupted and was found by proactive hunting five months later, not by an alert.

**Exposure.** Payroll records for six named employees were accessed, along with compensation, bonus, performance-management and awards material. Legal and Privacy should begin a notification assessment immediately; whether notification is mandatory depends on which data elements those records contain, which has not yet been confirmed. Separately, the record showing who reviewed and approved billing work was altered, so the integrity of the billing approval trail cannot currently be relied on. Two staff credentials must be treated as compromised, and a third, privileged account is implicated in earlier activity that has not yet been investigated.

**What has to change.** The cause was not a sophisticated attack. Remote access to clinic computers was reachable from the open internet and required only a password. Closing that route and requiring a second factor would have stopped this in its first minute, regardless of how the passwords were obtained. How they were obtained cannot be determined from the records available here, and answering that question requires sources outside this investigation.

The intruder needed no virus, no hacking tool and no software flaw. Everything was done with programs already built into Windows, using accounts that were allowed to do most of what was done. Where a genuine permission boundary existed the intruder was stopped, and simply switched to a second employee's account to get past it. That switch, from one outside address, is the single clearest reason the clinic's own explanation of a curious employee cannot be correct: no member of staff holds a colleague's password.

## 3. Scope and data sources

| **Data source**                                    | **Platform**                | **Period examined**      | **Confidence in coverage**                                          |
| -------------------------------------------------- | --------------------------- | ------------------------ | ------------------------------------------------------------------- |
| DeviceLogonEvents (authentication, logon type, source address) | law-cyber-range (Sentinel / MDE) | 2026-03-08 to 2026-03-18 | High; all queries returned, both external and internal sources present |
| DeviceProcessEvents (execution + full command line) | law-cyber-range             | 2026-03-08 to 2026-03-18 | High; command lines populated throughout                            |
| DeviceFileEvents (create, modify, rename)           | law-cyber-range             | 2026-03-08 to 2026-03-18 | High on client hosts; server-side share writes attributed to SYSTEM  |
| DeviceNetworkInfo (host-to-IP resolution)           | law-cyber-range             | 2026-03-08 to 2026-03-18 | Medium; snapshot table, three addresses unresolvable                |
| DeviceEvents                                        | law-cyber-range             | 2026-03-08 to 2026-03-18 | Not exhaustively reviewed; see gaps                                 |

### Evidence verification

Every value in this report was re-read off the query result it is attached to during a cold verification pass, not carried forward from drafting notes. Where a value could not be re-verified against a retained result, it is marked inline **[unverified]** and listed in Appendix D. Result tables state the scope of the query that produced them, because several counts differ between host-scoped and estate-scoped runs of otherwise similar queries.

Scope was bound to hosts matching `nh-*` and to the 8–18 March 2026 window on every query. The workspace is shared and holds a separate, unrelated incident on the same estate in May 2026; that activity is excluded by the time bind and is out of scope.

### Gaps and blind spots (required):

- **No network-flow or outbound-connection review.** `DeviceNetworkEvents` was not swept for traffic to the operator addresses, so exfiltration is assessed from staging behaviour rather than observed transfer.

- **RDP clipboard and drive redirection are unlogged.** `rdpclip.exe` was running in both operator sessions. File contents moved through the clipboard or a redirected drive would leave no trace in any table used here, which is the most likely explanation for the absence of exfiltration evidence.

- **Server-side share writes carry no user identity.** File events on `nh-fs-01` for SMB writes are logged under the SYSTEM account via `ntoskrnl.exe`, because the kernel SMB service performs the write. Attribution in those cases relies on correlating jump-list shortcut creation in the client's `AppData\...\Recent` folder. Where no shortcut exists, the writing user cannot be identified.

- **Three internal source addresses could not be resolved.** 10.0.8.6, 10.0.8.8 and 10.0.8.9 appear as logon sources but return nothing in `DeviceNetworkInfo`. These may be devices outside MDE coverage, which would itself be a monitoring gap.

- **The 9 March activity was identified but not worked.** It uses the same external infrastructure and includes domain controller access. It is very likely the same actor at an earlier stage and may hold the true point of initial compromise.

- **Credential-compromise vector is out of scope of this telemetry.** Establishing how the passwords were obtained requires mail gateway logs, endpoint telemetry from unmanaged devices, and credential-exposure monitoring, none of which are in this workspace.

---

## 4. UTC timeline

All times 11 March 2026 unless stated.

| **Time (UTC)**      | **Event**                                                                                                   | **Source**          | **Evidence ref** |
| ------------------- | ----------------------------------------------------------------------------------------------------------- | ------------------- | ---------------- |
| 2026-03-09 01:17–05:52 | nh-admin RemoteInteractive sessions from 193.36.225.245 across six hosts including nh-dc-01.               | DeviceLogonEvents   | F4               |
| 2026-03-09 04:40–04:45 | `net localgroup "Remote Desktop Users"` executed three times on nh-wks-clin-01 and nh-dc-01 as nh-admin.   | DeviceProcessEvents | F4, B-3          |
| 12:00:01            | `cscript.exe //B //Nologo "C:\scripts\billing-baseline.vbs"`: scheduled task, benign, source of Batch logons. | DeviceProcessEvents | F5               |
| 12:06:47            | RDP session established on nh-wks-bill-01 from 193.36.225.245 (`TSTheme.exe`, `rdpclip.exe`).                | DeviceProcessEvents | F1               |
| 12:10:57 → 12:13:11 | Notepad opens four files on `\\NH-FS-01\Billing\2026-03`: two Approved invoices, reconciliation, audit trail. | DeviceProcessEvents | F8, B-4          |
| 12:42:05            | `cmd.exe` console opened. No shell existed in the session before this point.                                 | DeviceProcessEvents | F5               |
| 12:42:12 → 12:44:39 | Orientation burst: `whoami`, `hostname`, `net use`, `net view`, `net view \\NH-FS-01`.                       | DeviceProcessEvents | F5, B-1          |
| 12:49:55 / 12:50:21 | HR\Compensation compensation change log and merit increase review opened as j.morris.                        | DeviceProcessEvents | F9               |
| 12:51:08            | c.wright RDP session established on nh-wks-hr-01 from 193.36.225.245.                                        | DeviceLogonEvents   | F3               |
| 12:54:46 → 12:57:39 | Six `payroll_review_*` files accessed (achen, mperez, cwright, dpatel, lrodriguez, jmorris). Four within 75 ms. | DeviceFileEvents    | F9, B-5          |
| 12:59:21            | `temp_payroll_review_jmorris_20260311.txt.txt` renamed in `C:\Shares\HR\2026-03\Payroll`.                     | DeviceFileEvents    | F10              |
| 12:59:24            | j.morris opens the staged temp file from nh-wks-bill-01.                                                     | DeviceProcessEvents | F10              |
| 13:00:06            | `HR\Awards\quarterly_awards_shortlist_20260310.txt` opened as j.morris.                                      | DeviceProcessEvents | F9               |
| 13:01:47            | File created at `C:\Shares\Billing\2026-03\Exceptions\temp_payroll_review_jmorris_20260311.txt.txt`.          | DeviceFileEvents    | F10, B-6         |
| 13:02:01            | Renamed to `payroll_exception_reference_20260311.txt.txt`.                                                   | DeviceFileEvents    | F10, B-6         |
| 13:16:00 → 13:17:35 | `"net.exe" view`, then `"net.exe" view /domain:nimbus` under PowerShell.                                      | DeviceProcessEvents | F6, B-2          |
| 13:18:08 → 13:20:19 | `"ARP.EXE" -a`, then six `nslookup` queries: 10.1.0.233, .234, .235, 10.1.7.255, 224.0.0.22, 10.1.0.1.        | DeviceProcessEvents | F6, B-2          |
| 13:27:05            | RDP to nh-wks-it-01 from 10.1.0.207 (nh-wks-bill-01). Profile creation only, no operator activity.            | DeviceLogonEvents   | F7, N1           |
| 13:36:50            | RDP to nh-fs-01 from 10.1.0.207 (nh-wks-bill-01).                                                            | DeviceLogonEvents   | F7               |
| 13:37:15            | `__PSScriptPolicyTest_*.ps1` / `.psm1` written to Temp: AMSI artefact, PowerShell script block executed.     | DeviceFileEvents    | F11              |
| 13:37:23            | `"whoami.exe" /groups` on nh-fs-01.                                                                          | DeviceProcessEvents | F11              |
| ~13:37 **[unverified]** | `"net.exe" share`: local share names and physical paths enumerated. Command confirmed; exact timestamp not re-read off a retained result. | DeviceProcessEvents | F11, D1          |
| 13:40:08            | `payroll_review_dpatel_20260311.txt` created in `C:\Users\j.morris\Documents` via `explorer.exe`.              | DeviceFileEvents    | F11, B-7         |
| 13:48:15            | Final RemoteInteractive logon recorded for j.morris from 193.36.225.245.                                      | DeviceLogonEvents   | F1               |
| 14:02:11            | `bonus_eligibility_summary_20260311.txt` created in `C:\Shares\HR\2026-03\Compensation`. Attribution unresolved. | DeviceFileEvents    | N7               |
| 14:02:14            | `pip_notice_EMP-81153_20260311.txt` created in `C:\Shares\HR\2026-03\PIPs`. Attribution unresolved.           | DeviceFileEvents    | N7               |
| 14:03:43            | `admin_audit_marker.txt` modified at HR share root. Attribution unresolved.                                   | DeviceFileEvents    | N7               |

---

## 5. Findings

### F1, Initial access by RDP from external infrastructure using valid credentials

**State it:** The j.morris account was driven over Remote Desktop from public internet addresses, not from a clinic workstation.

**Show it:** DeviceLogonEvents on nh-wks-bill-01 shows two billing analysts, j.morris and d.patel. Both record high-volume console activity. Only j.morris records `LogonSuccess` with `LogonType == RemoteInteractive` and a routable source address: 193.36.225.245 and 136.144.33.18. Neither address is within an RFC 1918 range. d.patel never appears with a public source and serves as the control baseline.

**Query:**

```kusto
let startDate = datetime(2026-03-08);
let endDate   = datetime(2026-03-18);
DeviceLogonEvents                              // law-cyber-range
| where TimeGenerated between (startDate .. endDate)
| where DeviceName startswith "nh-wks-bill-01"
| summarize Events=count(), First=min(TimeGenerated), Last=max(TimeGenerated)
          by AccountName, DeviceName, ActionType, RemoteIP, LogonType
| sort by Events desc
```

**Result:**

*Scope: nh-wks-bill-01 only, 08–18 March. Estate-scoped runs of a similar query return different totals: j.morris shows 284 blank-source successes across all hosts, so the two are not interchangeable.*

| Account  | LogonType           | RemoteIP        | Events | Assessment                  |
| -------- | ------------------- | --------------- | ------ | --------------------------- |
| j.morris | Success, blank source | (none)        | 222    | Genuine analyst at the desk |
| j.morris | Batch               | (none)          | 204    | `billing-baseline.vbs` task |
| j.morris | RemoteInteractive   | 136.144.33.18   | 4      | Operator                    |
| j.morris | RemoteInteractive   | 193.36.225.245  | 2      | Operator                    |
| j.morris | Unlock              | 193.36.225.245  | 1      | Operator, 12:06:48.669      |
| d.patel  | Success, blank source | (none)        | 189    | Control, no external source |

<img width="1725" height="872" alt="01-f1-logon-distribution" src="https://github.com/user-attachments/assets/044a7fe7-99a4-4a1b-a280-486a3c25389d" />

*Initial distribution by account, action type and source. j.morris and d.patel dominate; the administrator failures from seven public addresses are opportunistic scanning, not the operator.*

<img width="1948" height="590" alt="02-f1-logontype-breakdown" src="https://github.com/user-attachments/assets/f038524a-66c2-4559-a0e6-574a59068848" />

*Adding LogonType separates console work from RDP. The RemoteInteractive successes carry public source addresses.*

**Interpret it:** Containment requires credential revocation and removal of the remote access surface, not a permissions review of the analyst's role. The presence of a clean second analyst on the same host is what makes "logs in remotely" an anomaly rather than an assumption.

---

### F2, No brute force; the credentials were known before the sessions began

**State it:** Access was not obtained by guessing. The failure pattern is inconsistent with password attack and consistent with credentials already held.

**Show it:** j.morris records five `LogonFailed` events from 193.36.225.245 followed by success. nh-admin records four from the same address. Both accounts subsequently succeed from 136.144.33.18 and 172.245.102.94 with no preceding failures at all. By contrast, the built-in administrator account records 425 failures across seven external addresses on nh-wks-bill-01 alone (the largest single source contributing 127) and never succeeds. That total is from the visible result rows for one host and is a floor, not an estate-wide figure.

**Query:**

```kusto
let startDate = datetime(2026-03-08);
let endDate   = datetime(2026-03-18);
DeviceLogonEvents                              // law-cyber-range
| where TimeGenerated between (startDate .. endDate)
| where DeviceName startswith "nh-"
| where AccountName in ("j.morris", "nh-admin")
| summarize count() by AccountName, ActionType, RemoteIP
```

**Result:**

| Account  | RemoteIP        | LogonFailed | LogonSuccess | Reading                        |
| -------- | --------------- | ----------- | ------------ | ------------------------------ |
| j.morris | 193.36.225.245  | 5           | 23           | Fumble, then working password  |
| nh-admin | 193.36.225.245  | 4           | 43           | Same pattern                   |
| j.morris | 136.144.33.18   | 0           | 15           | Succeeded cold                 |
| nh-admin | 136.144.33.18   | 0           | 6            | Succeeded cold                 |
| nh-admin | 172.245.102.94  | 0           | 10           | Succeeded cold                 |
| administrator | 7 external addresses | 425 | 0        | Opportunistic spray, excluded  |

<img width="823" height="1265" alt="03-f2-success-failure-by-ip" src="https://github.com/user-attachments/assets/aea005cd-1a7f-4937-b41f-16135a94198b" />

*Failure counts per account and source. Four to five failures then success is not credential guessing; later addresses succeed with none.*

**Interpret it:** A password reset alone is a valid containment step here, unlike a token-replay intrusion, but it does not address how the credentials were obtained in the first place. That question is unresolved and is the leading follow-up item.

---

### F3, A second staff account driven from the same external address

**State it:** Two unrelated employee accounts were operated from one external address during the same session, which forecloses the insider explanation.

**Show it:** Scoping to successful `RemoteInteractive` logons with a populated source address across the estate shows c.wright authenticating to nh-wks-hr-01 from 193.36.225.245 at 12:51:08, three minutes after the j.morris session read HR\Compensation from nh-wks-bill-01, and three minutes before payroll files began opening on the HR host. The privileged nh-admin account appears from the same three external addresses.

Note that 172.245.102.94 is a public address despite its appearance; the private range is 172.16.0.0/12, which ends at 172.31.

**Query:**

```kusto
let startDate = datetime(2026-03-08);
let endDate   = datetime(2026-03-18);
DeviceLogonEvents                              // law-cyber-range
| where TimeGenerated between (startDate .. endDate)
| where DeviceName startswith "nh-"
| where ActionType == "LogonSuccess"
| where LogonType == "RemoteInteractive"
| where isnotempty(RemoteIP)
| project TimeGenerated, DeviceName, AccountName, RemoteIP, RemoteDeviceName
| sort by TimeGenerated asc
```

**Result:**

| Time (UTC) | Account  | Host           | RemoteIP       |
| ---------- | -------- | -------------- | -------------- |
| 12:51:08   | c.wright | nh-wks-hr-01   | 193.36.225.245 |
| 12:53:06   | c.wright | nh-wks-hr-01   | 10.0.8.9       |
| 13:27:05   | j.morris | nh-wks-it-01   | 10.1.0.207     |
| 13:36:50   | j.morris | nh-fs-01       | 10.1.0.207     |
| 13:48:15   | j.morris | nh-wks-bill-01 | 193.36.225.245 |

*The 12:06:48.669 event that begins the j.morris session on nh-wks-bill-01 is logged as `LogonType == Unlock`, not `RemoteInteractive`, and so does not appear in this result. It is the resumption of an existing RDP session from 193.36.225.245; the `RemoteInteractive` rows for that host and address carry a first-seen of 9 March 02:28:07 and a last-seen of 11 March 13:48:15. The session-establishment timestamp used throughout the timeline is taken from the process log (`TSTheme.exe` / `rdpclip.exe` at 12:06:47), not from this table.*

<img width="1928" height="981" alt="04-f3-second-account-same-ip" src="https://github.com/user-attachments/assets/ec2d4bf8-2090-41f9-a20b-f81406b8a3cf" />

*The nh-admin account appears from the same three external addresses as j.morris on nh-wks-bill-01.*

**Interpret it:** The account switch is operationally motivated: the billing credential could reach `HR\Compensation` but not `HR\Payroll`. Containment must cover both identities. One employee does not hold a colleague's password, so the insider hypothesis fails on this finding alone.

---

### F4, nh-admin is legitimate automation, separately abused on 9 March

**State it:** nh-admin is a genuine service account, not an actor-created one, but it was used by the same external infrastructure two days before the main incident.

**Show it:** The account records over 1,200 successful logons from a single internal host (10.1.0.233), plus link-local IPv6 and blank-source entries, and no `Interactive` console logons anywhere in the window. That profile is automation. Separately, between 01:17 and 05:52 on 9 March it records RemoteInteractive sessions from 193.36.225.245 across six hosts including nh-dc-01, and executes group enumeration.

Distinguishing the enumeration from surrounding noise required a frequency test. Sorting 9 March process activity by volume returns only OneDrive deleting its own stale installer and bare `powershell.exe` with no arguments. Testing `localgroup` across the full ten-day window returns six rows: three commands, each duplicated by the `net.exe` → `net1.exe` handoff, confined to a 92-second burst.

**Query:**

```kusto
DeviceProcessEvents                            // law-cyber-range
| where TimeGenerated between (datetime(2026-03-08) .. datetime(2026-03-18))
| where DeviceName startswith "nh-"
| where ProcessCommandLine has "localgroup"
| project TimeGenerated, DeviceName, AccountName, ProcessCommandLine
| sort by TimeGenerated asc
```

**Result:**

| Time (UTC)          | Host            | Account  | Command                                   |
| ------------------- | --------------- | -------- | ----------------------------------------- |
| 2026-03-09 04:40:08 | nh-wks-clin-01  | nh-admin | `net localgroup "Remote Desktop Users"`   |
| 2026-03-09 04:45:03 | nh-dc-01        | nh-admin | `net localgroup "Remote Desktop Users"`   |
| 2026-03-09 04:45:32 | nh-wks-clin-01  | nh-admin | `net localgroup "Remote Desktop Users"`   |

Three executions in 92 seconds. No other day in the window contains this command.

<img width="1647" height="1171" alt="05-f4-onedrive-noise-vs-localgroup" src="https://github.com/user-attachments/assets/5b381fb9-9c04-4cbd-8590-bc8ad8dc3b07" />

*Full command lines separate OneDrive self-maintenance from real enumeration. The repeated `cmd /q /c del` entries are OneDrive removing its own stale installer.*

<img width="1065" height="320" alt="06-f4-localgroup-full-window" src="https://github.com/user-attachments/assets/0659f90e-259a-4472-9e8c-7e907590068b" />

*The same command tested across ten days: one burst, one account, no recurrence.*

**Interpret it:** The enumeration targets who holds RDP rights, on a workstation and then on the domain controller. That is target selection for the access method actually used two days later. This strand was not worked to completion and is the first priority for follow-up; it may hold the true point of initial compromise.

---

### F5, Orientation reconnaissance under an interactive shell

**State it:** After browsing files for half an hour, the operator opened a console and ran a five-command orientation sequence ending on the file server that later became the collection target.

**Show it:** Process telemetry for the account is dominated by session plumbing. Filtering to children of `cmd.exe` and `powershell.exe` isolates typed commands. No shell exists in the session until 12:42:05; the first command follows seven seconds later.

**Query:**

```kusto
DeviceProcessEvents                            // law-cyber-range
| where TimeGenerated between (datetime(2026-03-11 12:42) .. datetime(2026-03-11 13:25))
| where DeviceName startswith "nh-wks-bill-01"
| where AccountName =~ "j.morris"
| where InitiatingProcessFileName in~ ("cmd.exe","powershell.exe","conhost.exe")
| project TimeGenerated, FileName, ProcessCommandLine, InitiatingProcessFileName
| sort by TimeGenerated asc
```

**Result:**

| Time (UTC) | Command                  | Parent  | Purpose                          |
| ---------- | ------------------------ | ------- | -------------------------------- |
| 12:42:12   | `whoami`                 | cmd.exe | Identity                         |
| 12:43:31   | `hostname`               | cmd.exe | Host                             |
| 12:43:41   | `net use`                | cmd.exe | Existing mapped drives           |
| 12:44:10   | `net view`               | cmd.exe | Network                          |
| 12:44:39   | `net view \\NH-FS-01`    | cmd.exe | Shares on one named server       |

<img width="907" height="1239" alt="07-f5-process-volume-noise" src="https://github.com/user-attachments/assets/70608dd0-2d55-4299-b1b7-a815a86b67d9" />

*Sorting by execution count returns only Windows and Edge maintenance. Operator commands are rare and sit at the opposite end of the distribution.*

<img width="1742" height="1291" alt="08-f5-session-boundary" src="https://github.com/user-attachments/assets/feac094f-7557-4f5f-8412-ddbaf634e233" />

*RDP session establishment at 12:06, four Notepad opens against the billing share, then the console at 12:42:05.*

<img width="937" height="874" alt="09-f5-bearings-burst" src="https://github.com/user-attachments/assets/70147b24-c4bc-415e-8253-49f5a8d93d3e" />

*Parent-process filtering isolates the cmd.exe burst and the later PowerShell phase.*

<img width="1391" height="1551" alt="10-f5-discovery-sweep-estate" src="https://github.com/user-attachments/assets/d411f053-1407-4541-9571-f789c95e4721" />

*All discovery activity in the window. The recurring `ipconfig /all` + `netstat` pairs run under the SYSTEM account and are scheduled monitoring, not the operator.*

**Interpret it:** The progression (identity, host, mapped drives, network, one named server) is a standard orientation pattern and terminates by selecting the target. Parent-process filtering rather than keyword matching is what made it visible; a keyword list finds only commands the analyst thought to search for.

---

### F6, Domain and subnet mapping using passive techniques

**State it:** A second reconnaissance phase 31 minutes later, under a different shell, mapped the domain and the local subnet without generating scan traffic.

**Show it:** From 13:16 the parent process changes from `cmd.exe` to `powershell.exe`. `net view /domain:nimbus` asks the domain controller to enumerate every registered machine. `arp -a` reads the local ARP cache, which lists layer-2 neighbours the host has recently contacted. Six `nslookup` queries then resolve those addresses to hostnames.

**Query:**

```kusto
DeviceProcessEvents                            // law-cyber-range
| where TimeGenerated between (datetime(2026-03-11 13:10) .. datetime(2026-03-11 13:25))
| where DeviceName startswith "nh-wks-bill-01"
| where InitiatingProcessFileName in~ ("cmd.exe","powershell.exe")
| project TimeGenerated, FileName, ProcessCommandLine
| sort by TimeGenerated asc
```

**Result:**

| Time (UTC) | Command                        | Yields                                    |
| ---------- | ------------------------------ | ----------------------------------------- |
| 13:16:00   | `"net.exe" view`               | Visible machines                          |
| 13:17:35   | `"net.exe" view /domain:nimbus` | Every machine registered in the domain   |
| 13:18:08   | `"ARP.EXE" -a`                 | Live layer-2 neighbours, passively        |
| 13:18:51   | `"nslookup.exe" 10.1.0.233`    | Reverse resolution                        |
| 13:18:59   | `"nslookup.exe" 10.1.0.234`    | Reverse resolution                        |
| 13:19:14   | `"nslookup.exe" 10.1.0.235`    | Resolves to nh-dc-01                      |
| 13:19:35   | `"nslookup.exe" 10.1.7.255`    | Broadcast address, subnet probing        |
| 13:20:04   | `"nslookup.exe" 224.0.0.22`    | Multicast address, subnet probing        |
| 13:20:19   | `"nslookup.exe" 10.1.0.1`      | Gateway                                   |

**Interpret it:** ARP cache plus reverse DNS converts a list of addresses into a labelled network map using only the host's existing cache and its configured resolver. No packets are sent to the targets, so a network sensor sees nothing. Seven minutes after the last lookup the first lateral hop occurs. The mapping is what makes the hop targeted rather than blind.

---

### F7, Lateral movement to two hosts, launched from the beachhead

**State it:** Both onward hops originated from the billing workstation, not from the internet, making nh-wks-bill-01 the beachhead rather than the destination.

**Show it:** The 13:27 and 13:36 sessions carry `RemoteIP = 10.1.0.207`. `DeviceNetworkInfo` resolves that address to nh-wks-bill-01, and 10.1.0.235 to nh-dc-01.

**Query:**

```kusto
let startDate = datetime(2026-03-08);
let endDate   = datetime(2026-03-18);
DeviceNetworkInfo                              // law-cyber-range
| where TimeGenerated between (startDate .. endDate)
| where DeviceName startswith "nh-"
| mv-expand parse_json(IPAddresses)
| extend IP = tostring(IPAddresses.IPAddress)
| where IP in ("10.0.8.8", "10.0.8.9", "10.1.0.207", "10.1.0.235", "10.0.8.6")
| distinct DeviceName, IP
```

**Result:**

| IP          | Host           | Note                                    |
| ----------- | -------------- | --------------------------------------- |
| 10.1.0.207  | nh-wks-bill-01 | Source of both lateral hops             |
| 10.1.0.235  | nh-dc-01       | Domain controller                       |
| 10.0.8.6 / 10.0.8.8 / 10.0.8.9 | unresolved | See gaps; possibly outside MDE coverage |

<img width="1947" height="1165" alt="11-f7-estate-remoteinteractive" src="https://github.com/user-attachments/assets/4b83d538-b747-49f2-8906-45255e506272" />

*Remote sessions across the estate, 8–18 March. The 11 March internal sources are the lateral movement.*

<img width="803" height="506" alt="12-f7-internal-ip-resolution" src="https://github.com/user-attachments/assets/fc23db01-f0a9-4ed2-807e-a3f4d62821bb" />

*Resolution of the internal source addresses.*

**Interpret it:** Workstation-to-server RDP is the movement mechanism. Restricting interactive logon rights so that workstation accounts cannot open sessions to servers would have blocked both hops without affecting the analyst's normal work.

---

### F8, One hop produced no activity: a tested negative

**State it:** The account reached nh-wks-it-01 and did nothing there. The only activity was Windows creating a user profile.

**Show it:** File telemetry for the host shows approximately forty `FileCreated` events spanning 13:27:08.390 to 13:27:47.115, about thirty-nine seconds in total. Every one was initiated by a system process. Process telemetry shows eight entries, every one carrying a first-logon switch. No console was opened; no file outside the user profile was touched. Three tables were checked.

**Query:**

```kusto
DeviceProcessEvents                            // law-cyber-range
| where TimeGenerated between (datetime(2026-03-11 12:00) .. datetime(2026-03-11 19:00))
| where DeviceName startswith "nh-wks-it-01"
| where AccountName =~ "j.morris"
| where InitiatingProcessFileName in~ ("cmd.exe","powershell.exe","conhost.exe","explorer.exe")
| project TimeGenerated, FileName, ProcessCommandLine, InitiatingProcessFileName
| sort by TimeGenerated asc
```

**Result:**

| Time (UTC) | Command                                              | Reading                    |
| ---------- | ---------------------------------------------------- | -------------------------- |
| 13:27:10   | `"unregmp2.exe" /FirstLogon`                         | Profile provisioning       |
| 13:27:10   | `"ie4uinit.exe" -UserConfig`                         | Profile provisioning       |
| 13:27:11   | `"setup.exe" --configure-user-settings ... --msedge` | Edge provisioning          |
| 13:27:31   | `"fsquirt.exe" -Register`                            | Profile provisioning       |
| 13:27:41   | `"OneDriveSetup.exe" /thfirstsetup`                  | Profile provisioning       |
| 13:27:41   | `"msedge.exe" --no-startup-window --win-session-start` | Session-start hook       |

No `cmd.exe`, no `powershell.exe`, no console anywhere in the session.

<img width="1568" height="1513" alt="13-f8-it01-file-events" src="https://github.com/user-attachments/assets/af5d9542-75b6-4c54-a742-70007caf1a13" />

*Approximately forty file creations across thirty-nine seconds, all initiated by system processes.*

<img width="1412" height="628" alt="14-f8-it01-process-events" src="https://github.com/user-attachments/assets/819bf9b0-53c8-4900-8f1d-3c4c9f994ead" />

*Every command carries a first-logon switch. No shell was opened.*

**Interpret it:** The profile creation establishes that j.morris had never logged on to this host before. A first-ever logon that produces no work reads as target assessment: the operator looked at the IT workstation, found nothing worth taking, and moved to the file server nine minutes later. The same profile-creation burst occurs on nh-fs-01 at 13:36: identical starting conditions, divergent outcomes. That is what makes this a finding rather than an absence of evidence.

---

### F9, Access beyond the role, into billing sign-off and then HR

**State it:** A submissions-role account read files from every downstream billing stage and then from four HR categories, ending with payroll records for the entire staff.

**Show it:** The j.morris role corresponds to the Pending stage of the billing workflow, where the scheduled task writes new claim files. The account opened files in Approved (sign-off), Reconciliation and AuditTrail, then moved to `\\NH-FS-01\HR\`. When it reached the limit of its permissions, the c.wright account took over for the Payroll folder.

**Query:**

```kusto
DeviceProcessEvents                            // law-cyber-range
| where TimeGenerated between (datetime(2026-03-11 12:00) .. datetime(2026-03-11 19:00))
| where ProcessCommandLine contains "NH-FS-01"
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine
| sort by TimeGenerated asc
```

**Result:**

| Time (UTC) | Account  | Path                                                        | Role fit          |
| ---------- | -------- | ----------------------------------------------------------- | ----------------- |
| 12:10:57   | j.morris | `Billing\2026-03\Approved\approved_pending_invoice_INV-664215_20260310.txt` | Out of role       |
| 12:11:56   | j.morris | `Billing\2026-03\Approved\approved_pending_invoice_INV-773221_20260311.txt` | Out of role       |
| 12:12:29   | j.morris | `Billing\2026-03\Reconciliation\billing_reconciliation_20260311.txt` | Out of role       |
| 12:13:11   | j.morris | `Billing\2026-03\AuditTrail\review_audit_20260311.txt`        | Out of role, modified |
| 12:49:55   | j.morris | `HR\2026-03\Compensation\compensation_change_log_20260310.txt` | Out of department |
| 12:50:21   | j.morris | `HR\2026-03\Compensation\merit_increase_review_20260309.txt`  | Out of department |
| 12:54–12:58 | c.wright | `HR\2026-03\Payroll\payroll_review_{achen,mperez,cwright,dpatel,lrodriguez,jmorris}_20260311.txt` | Second account required |
| 12:59:24   | j.morris | `HR\2026-03\Payroll\temp_payroll_review_jmorris_20260311.txt.txt` | Staged copy       |
| 13:00:06   | j.morris | `HR\2026-03\Awards\quarterly_awards_shortlist_20260310.txt`   | Out of department |

<img width="1722" height="815" alt="15-f9-notepad-file-access" src="https://github.com/user-attachments/assets/0a65a406-462e-406b-a83b-2109c46465b2" />

*The full sequence of documents opened, showing the billing reads, the HR compensation access, the c.wright payroll reads, and the staged temp file.*

<img width="1723" height="976" alt="16-f9-fs01-share-telemetry" src="https://github.com/user-attachments/assets/1231edec-dfe4-47b0-a2cf-e876225b1563" />

*Share-side file telemetry for the same activity.*

<img width="1696" height="542" alt="17-f9-hr-share-events" src="https://github.com/user-attachments/assets/bc85811d-a80a-4bf9-8a0a-e1ba0f0768c1" />

*HR share events including the unattributed 14:02–14:03 entries.*

**Interpret it:** Two distinct impacts. The payroll and compensation access is a confidentiality breach covering the entire staff roster. The modification of `review_audit_20260311.txt` is an integrity impact: every other file in this incident was read, and this one was altered. Interference with the record of who reviewed what is a separate harm from data theft and should be treated as such. Four of the six payroll files were opened in Notepad within a 75 ms span (12:58:09.429 to 12:58:09.504, from `DeviceProcessEvents`), which is inconsistent with a person reading documents and indicates a bulk or multi-select operation. The corresponding share-side `FileModified` events are spread across 12:55:07 to 12:58:42 and are not the 75 ms cluster.

---

### F10, Payroll data relocated across shares and renamed to blend in

**State it:** HR payroll material was copied into the billing share and renamed to resemble a billing exception document, sitting among genuine ones.

**Show it:** Three file events, 160 seconds apart in total, reconstruct the concealment.

**Query:**

```kusto
DeviceFileEvents                               // law-cyber-range
| where TimeGenerated between (datetime(2026-03-11 12:45) .. datetime(2026-03-11 19:00))
| where FileName contains "payroll_review" or FileName contains "temp_"
| project TimeGenerated, DeviceName, ActionType, FileName, FolderPath,
          InitiatingProcessFileName, InitiatingProcessAccountName
| sort by TimeGenerated asc
```

**Result:**

| Time (UTC) | ActionType  | Path                                                                              |
| ---------- | ----------- | --------------------------------------------------------------------------------- |
| 12:59:21   | FileRenamed | `C:\Shares\HR\2026-03\Payroll\temp_payroll_review_jmorris_20260311.txt.txt`         |
| 13:01:47   | FileCreated | `C:\Shares\Billing\2026-03\Exceptions\temp_payroll_review_jmorris_20260311.txt.txt` |
| 13:02:01   | FileRenamed | `C:\Shares\Billing\2026-03\Exceptions\payroll_exception_reference_20260311.txt.txt` |

The destination folder already held a genuine `billing_exceptions_20260311.txt`.

<img width="1740" height="1146" alt="18-f10-payroll-rename-chain" src="https://github.com/user-attachments/assets/12f9c92d-18ef-47de-97a0-c0898d351048" />

*Payroll access, staging, and the collection of d.patel's file into a local profile.*

<img width="1722" height="1580" alt="19-f10-exceptions-folder" src="https://github.com/user-attachments/assets/b37358bb-4063-4612-acff-7fe1e28a5ab8" />

*The staged file arriving at 13:01:47 and its rename fourteen seconds later.*

**Interpret it:** This is the most deliberate act in the incident and the clearest evidence of intent. Its operational effect is that the data became reachable through the billing credential alone; after 13:02 the c.wright account was not used again. The doubled `.txt.txt` extension is a durable hunting pattern for staged content in this estate.

---

### F11, Local staging on the file server

**State it:** After enumerating its own rights and the server's shares, the operator copied a colleague's payroll record into the local user profile on nh-fs-01.

**Show it:** Twenty-three seconds after the session landed, `whoami /groups` dumped full token group membership. On a file server, group membership is access, since share and NTFS permissions are granted to groups. `net.exe share` then listed local share names together with the physical paths behind them, which explains navigation directly to `C:\Shares\HR\2026-03\Payroll` rather than through the UNC namespace. **[unverified: the command is confirmed and its position in the sequence is established, but no retained result carries its exact timestamp; see Appendix D.]** AMSI script-policy artefacts at 13:37:15 confirm a PowerShell script block executed.

**Query:**

```kusto
DeviceFileEvents                               // law-cyber-range
| where TimeGenerated between (datetime(2026-03-11 13:36) .. datetime(2026-03-12 06:00))
| where DeviceName startswith "nh-fs-01"
| where InitiatingProcessAccountName =~ "j.morris"
| project TimeGenerated, ActionType, FileName, FolderPath, InitiatingProcessFileName
| sort by TimeGenerated asc
```

**Result:**

| Time (UTC) | ActionType   | Path                                                        | Initiating process |
| ---------- | ------------ | ----------------------------------------------------------- | ------------------ |
| 13:36:53–13:37:12 | FileCreated ×10 | `C:\Users\j.morris\AppData\...` profile provisioning | system processes   |
| 13:37:15   | FileCreated  | `...\Temp\2\__PSScriptPolicyTest_*.ps1` / `.psm1`             | powershell.exe     |
| 13:40:08   | FileCreated  | `C:\Users\j.morris\Documents\payroll_review_dpatel_20260311.txt` | explorer.exe    |
| 13:40:08   | FileModified | same path                                                    | explorer.exe       |
| 13:40:13   | FileCreated  | `...\Windows\Recent\payroll_review_dpatel_20260311.lnk`        | explorer.exe       |

<img width="1743" height="818" alt="20-f11-fs01-local-staging" src="https://github.com/user-attachments/assets/17afa659-f492-4b81-8b23-98ca6eae5b99" />

*Profile creation, the PowerShell artefact, and the collection of d.patel's payroll file at 13:40:08.*

<img width="1777" height="1591" alt="21-f11-fs01-session-start" src="https://github.com/user-attachments/assets/5288df42-cef0-4289-be3f-a41610b071af" />

*The RDP session establishing on the file server at 13:36:49.*

**Interpret it:** `explorer.exe` as the initiating process means a manual GUI copy inside the RDP session, not scripted collection. The file belongs to d.patel, the same account that served as this investigation's control baseline. The shortcut in `Recent` confirms the file was opened after copying. A second staging location, distinct from the cross-share plant in F10.

---

## 6. Negative findings

| **Looked for**                                          | **Where**                                             | **Method applied**                                                                                              | **Conclusion**                                                                                                                                     |
| ------------------------------------------------------- | ----------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------- |
| **N1** Operator activity on nh-wks-it-01                | DeviceProcessEvents, DeviceFileEvents, DeviceEvents    | Full window, no command filter; then filtered to shell parents                                                    | None. Only first-logon profile provisioning, all system-initiated. The hop is a red herring. Absence is the finding (F8).                          |
| **N2** Malware or dropped binaries                      | DeviceProcessEvents, estate-wide                       | Reviewed every executed binary and its path across both operator sessions                                         | None. Every binary was native and pre-existing: whoami, hostname, net, net1, arp, nslookup, notepad, explorer.                                     |
| **N3** Exploitation or privilege escalation             | DeviceProcessEvents, DeviceLogonEvents                 | Checked for anomalous parent-child chains, token manipulation, service abuse, escalation tooling                  | None. Access at every stage came from valid credentials and existing share permissions.                                                            |
| **N4** Brute force or password spraying by the operator | DeviceLogonEvents                                      | Counted failures per account per source address and compared against the known spray on the administrator account | None. Four to five failures then success; three later sessions succeeded with zero failures (F2).                                                  |
| **N5** Archiving or transfer tooling                    | DeviceProcessEvents, DeviceFileEvents                  | Searched for zip/7z/rar/rclone execution and for archive files created in the window                              | None. The only `.zip` files are Azure guest-agent diagnostic bundles written by `collectguestlogs.exe` on a recurring schedule across all hosts.   |
| **N6** Patient or clinical data access                  | DeviceFileEvents, DeviceProcessEvents                  | Reviewed all activity against `\\NH-FS-01\Clinical\` in the window; compared initiating process and cadence against the operator's known pattern | No operator access. The only Clinical-share activity is `patient_intake_queue_20260311` modified by `wscript.exe` as a.chen at 14:06:03, 15:06:30 and 16:09:55: hourly, script-initiated, attributed to a named clinical user, matching no operator behaviour. Neither compromised account touched the share. **Still recommend independent verification before closure**, given the healthcare setting. |
| **N7** Attribution for the 14:02–14:03 HR file events   | DeviceFileEvents                                       | Compared the initiating process of the three events against both the estate's HR content generator and the operator's known write pattern, using results already retained | **Assessed, moderate confidence: operator-attributable.** The estate's HR content generation runs under `wscript.exe` attributed to a named user (observed 12:09:20 and 12:09:23 writing `salary_adjustment_queue` and `personnel_review_queue`). The three 14:02–14:03 events are `ntoskrnl.exe` / SYSTEM remote-SMB writes, the same signature as the confirmed operator writes at 12:59:21, 13:01:47 and 13:02:01, and a different signature from the generator. No jump-list shortcut exists to confirm the user. **One query closes this**; see Appendix D, D3. |

---

## 7. MITRE ATT&CK mapping

| **Tactic**                    | **Technique**                                        | **ID**        | **Evidence ref**                          |
| ----------------------------- | ---------------------------------------------------- | ------------- | ----------------------------------------- |
| Initial Access                | External Remote Services                             | T1133         | F1, RDP reachable from the internet       |
| Initial Access / Persistence  | Valid Accounts: Domain Accounts                      | T1078.002     | F1, F2, F3                                |
| Discovery                     | System Owner/User Discovery                          | T1033         | F5 `whoami`; F11 `whoami /groups`         |
| Discovery                     | System Information Discovery                         | T1082         | F5 `hostname`                             |
| Discovery                     | System Network Configuration Discovery               | T1016         | F6 `arp -a`                               |
| Discovery                     | Remote System Discovery                              | T1018         | F6 `net view /domain:nimbus`, nslookup sweep |
| Discovery                     | Network Share Discovery                              | T1135         | F5 `net use`, `net view \\NH-FS-01`; F11 `net share` |
| Discovery                     | Permission Groups Discovery: Local Groups            | T1069.001     | F4, `net localgroup "Remote Desktop Users"` |
| Lateral Movement              | Remote Services: Remote Desktop Protocol             | T1021.001     | F7, hops from the beachhead               |
| Collection                    | Data from Network Shared Drive                       | T1039         | F9, HR and Billing shares                 |
| Collection                    | Data Staged: Local Data Staging                      | T1074.001     | F11, copy into the local profile          |
| Collection                    | Data Staged: Remote Data Staging                     | T1074.002     | F10, cross-share plant                    |
| Defense Evasion               | Masquerading: Match Legitimate Name or Location      | T1036.005     | F10, rename to `payroll_exception_reference` |
| Impact / Defense Evasion      | Indicator Removal / Stored Data Manipulation         | T1070 / T1565.001 | F9, `review_audit_20260311.txt` modified |
| Exfiltration (suspected)      | Exfiltration Over Alternative Protocol               | T1048         | B2.1; RDP clipboard/drive redirection available, not confirmed |

---

## 8. Recommendations

*Ranked by leverage, not cost. The single highest-leverage control here is architectural: the estate exposed RDP directly to the internet, and the credential that reached it needed no second factor.*

| **#** | **Recommendation**                                                                                                                                                                  | **Addresses**                    | **Priority** | **Owner**             |
| ----- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | -------------------------------- | ------------ | --------------------- |
| 1     | Remove direct RDP exposure to the internet on all `nh-*` hosts; place remote access behind a VPN or RD Gateway. The 425+ failed administrator logons from seven addresses confirm the surface is being continuously scanned by unrelated parties. | External access surface (F1, F2) | Critical     | IT / Network          |
| 2     | Require phishing-resistant MFA for all remote access. The intrusion required only a correct password; a second factor would have stopped it at 12:06 regardless of how the credential was obtained. | Valid-account access (F1, F3)    | Critical     | Identity / IT         |
| 3     | Reset credentials and revoke sessions for j.morris and c.wright; audit and rotate nh-admin. Investigate the 9 March nh-admin activity, including the domain controller sessions, as a separate case; it may hold the true point of initial compromise. | Compromised identities (F3, F4)  | Critical     | SOC / AD team         |
| 4     | Review share permissions on `nh-fs-01` against role. A submissions-role account reaching Approved, Reconciliation, AuditTrail and HR\Compensation indicates permissions granted by convenience. Least privilege would have reduced this incident to a fraction of its scope. | Out-of-role access (F9)          | High         | IT / Data owners      |
| 5     | Restrict interactive logon rights so workstation accounts cannot open RDP sessions to servers. This blocks both lateral hops (F7) without affecting normal work.                     | Lateral movement (F7)            | High         | AD team               |
| 6     | Protect billing audit-trail files as append-only, or hold them where only the workflow service can write. Record integrity should not depend on user permissions.                    | Integrity impact (F9)            | High         | IT / Billing owners   |
| 7     | Disable RDP clipboard and drive redirection where not operationally required. This is the most likely exfiltration channel in this incident and the one that left no evidence.        | Exfiltration channel (B2.1)      | Medium       | IT                    |
| 8     | Implement the four detection rules in B2.7. Each corresponds to a step that generated telemetry and produced no alert-driven referral; all four would have fired on 11 March. Confirm current alert coverage first (Appendix D, D2).           | Detection coverage          | Medium       | Detection engineering |

---

# Part B, Tail

**Decision gate:** A compromise was confirmed. B2 (Incident) is completed below. B1 (Threat Hunt) is marked "N/A, no compromise confirmed"; its hypothesis is retained as the opening lead.

### B1, Threat Hunt tail

**Status:** N/A, compromise confirmed. Retained only as the opening lead below.

**Opening-lead hypothesis (falsifiable):** A billing account flagged for odd behaviour is being used by someone other than its owner, and the activity extends beyond the account's role. **PROVED** (see B2).

**Counter-hypothesis tested and rejected:** The activity is a curious or departing employee using retained access. Rejected on four independent grounds: external session sources (F1), two staff accounts driven from one address (F3), theft of both other account holders' own payroll records (F9, F11), and deliberate concealment through cross-share relocation and rename (F10).

### B2, Incident tail

*Framing per NIST SP 800-61r3 (CSF 2.0 Functions); containment/eradication/recovery per SANS PICERL.*

### B2.1 Impact and dwell time

| **Field**                      | **Value**                                                                                                                                                                          |
| ------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| First malicious activity (UTC) | 2026-03-09 01:17 (nh-admin from 193.36.225.245, see F4); 2026-03-11 12:06:47 for the primary incident                                                                              |
| First detection (UTC)          | **[unverified]** No alert was observed, but `SecurityAlert` and `SecurityIncident` were not queried in this investigation. Absence of detection is asserted from the absence of any alert-driven referral, not from a direct query; see Appendix D, D2.                                                                                     |
| Dwell time to detection        | No detection established. Approximately 1h 42m of hands-on-keyboard activity on 11 March (12:06:47 to 13:48:15), uninterrupted.                                                                               |
| Time to containment            | Not yet contained at time of writing; see B2.3                                                                                                                                     |
| Data confirmed accessed        | Payroll reviews for six employees; compensation change log; merit increase review; quarterly awards shortlist; two approved invoices; billing reconciliation; billing audit trail   |
| Data confirmed staged          | `payroll_exception_reference_20260311.txt.txt` (HR payroll, planted in the billing share); `payroll_review_dpatel_20260311.txt` (copied to a local profile on nh-fs-01)             |
| Data confirmed exfiltrated     | **None proven.** No archiving tool, no observed outbound transfer. RDP clipboard and drive redirection were available throughout and would leave no trace; assume exfiltration.     |
| Integrity impact               | `review_audit_20260311.txt` modified, the record of reviewer actions in the billing workflow                                                                                      |
| Business impact                | Staff-wide HR confidentiality breach; billing workflow integrity compromised; two credentials confirmed compromised, a third (nh-admin) implicated                                 |

*Accessed vs staged vs exfiltrated are kept separate. Opening a file is access; relocating or copying it is staging; only observed transfer out of the estate is exfiltration. Nothing here reaches the third category on evidence.*

### B2.2 Root cause

This was not caused by a clever attack. It was caused by two ordinary conditions meeting.

The first is that Remote Desktop was reachable from the open internet on clinic workstations. The 425-plus failed sign-in attempts against the built-in administrator account, arriving from seven unrelated addresses during the same period, show that this surface was being scanned continuously by parties with no connection to this incident. Any working credential would have opened it.

The second is that a working credential existed outside the clinic. The password succeeded on the first or second attempt from three different addresses, so it was known in advance rather than discovered. How it came to be known cannot be established from the telemetry in this workspace; phishing, an information-stealing infection on an unmanaged device, and reuse of a credential exposed in a third-party breach are all consistent with what is here.

Underneath both sits a permissions problem that determined how much damage followed. A billing submissions account could read the sign-off stage, the reconciliation record, the audit trail, and HR compensation material. Nothing in the intrusion had to defeat a control to reach that data; the account was simply allowed to. The second account was recruited only when the first met an actual permission boundary at `HR\Payroll`, which demonstrates that boundaries, where they existed, worked.

No exploitation, no malware, and no privilege escalation was required at any stage.

### B2.3 Containment, eradication, recovery

*For each action: the naive move it rejects, then the correct one.*

| **Phase** | **Action (correct)**                                                                                                          | **Naive move it rejects**                                                                                                                          | **Owner / verify**                    |
| --------- | ------------------------------------------------------------------------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------- |
| Contain   | Remove RDP exposure at the perimeter for all `nh-*` hosts before or alongside credential resets.                              | Reset passwords first. The surface remains open and any other held credential still works.                                                        | IT / Network, verify from outside     |
| Contain   | Reset credentials and revoke sessions for **both** j.morris and c.wright; audit nh-admin.                                     | Reset only the account named in the review. The second identity is the one that reached payroll.                                                  | Identity, confirm no active sessions  |
| Contain   | Treat the three external addresses as detection IOCs; block only as a short-term measure.                                     | Block the three IPs and consider it contained. Addresses are trivially rotated and the exposure, not the address, is the problem.                 | SOC                                   |
| Eradicate | Preserve and hash `payroll_exception_reference_20260311.txt.txt` before removal; then delete it from the billing share.        | Delete the planted file immediately. It is the strongest single artefact of intent and is needed for the HR notification assessment.               | IR, chain of custody per B2.5         |
| Eradicate | Remove `C:\Users\j.morris\Documents\payroll_review_dpatel_20260311.txt` from nh-fs-01 and delete the stale profile.            | Remove the file only. The profile itself is an artefact of the intrusion and its `Recent` folder holds attribution evidence; capture it first.     | IT, after evidence capture            |
| Eradicate | Restore `review_audit_20260311.txt` from backup after diffing against the live copy to establish what was altered.             | Restore from backup immediately. The difference between the two versions is the evidence of the integrity impact.                                 | Billing owners, diff before restore   |
| Eradicate | Sweep both shares for other files with doubled extensions or names inconsistent with their folder.                            | Assume one planted file. The technique is cheap to repeat and only one instance was confirmed.                                                    | IT, verify against N6                 |
| Recover   | Review and reduce share permissions before re-enabling the accounts.                                                          | Re-enable accounts with permissions unchanged. The scope of any repeat incident would be identical.                                               | IT / Data owners                      |
| Recover   | Complete the 9 March investigation (F4) before declaring the incident closed.                                                 | Close on the 11 March activity alone. The earlier strand includes domain controller access and is not understood.                                 | SOC                                   |

### B2.4 Indicators of compromise (ordered by Pyramid of Pain)

| **Type**             | **Indicator**                                                                              | **Context**                                              | **Confidence** |
| -------------------- | -------------------------------------------------------------------------------------------- | -------------------------------------------------------- | -------------- |
| TTP (hardest)        | Cross-share relocation of departmental data followed by rename within seconds                | Concealment signature (F10)                              | High           |
| TTP                  | One external source address authenticating as two or more distinct user accounts             | Operator switching credentials (F3)                      | High           |
| TTP                  | `whoami` → `hostname` → `net use` → `net view` → `net view \\<host>` under `cmd.exe`         | Orientation burst (F5)                                   | High           |
| TTP                  | `arp -a` followed by sequential reverse-DNS lookups                                          | Passive network mapping (F6)                             | High           |
| TTP                  | `net view /domain:` executed by a non-administrative user account                            | Domain enumeration (F6)                                  | High           |
| Artefact             | Doubled `.txt.txt` extension on files in departmental shares                                 | Staged content pattern (F10)                             | High           |
| File                 | `payroll_exception_reference_20260311.txt.txt` in `Billing\2026-03\Exceptions`               | Planted HR payroll data                                  | High           |
| File                 | `C:\Users\j.morris\Documents\payroll_review_dpatel_20260311.txt` on nh-fs-01                 | Locally staged payroll record                            | High           |
| Account              | c.wright RemoteInteractive from an external address                                          | Second compromised identity                              | High           |
| Host / IP (cheapest) | 193.36.225.245, 136.144.33.18, 172.245.102.94                                                | Operator exit addresses; monitor, do not treat as containment | Medium    |

*Addresses are cheap for the adversary to change; the behavioural patterns are not. Spend detection effort at the top of the table.*

### B2.5 Chain of custody

| **Evidence item**                                     | **Collected (UTC)** | **By**    | **Hash**                   | **Storage**                            |
| ------------------------------------------------------ | ------------------- | --------- | -------------------------- | -------------------------------------- |
| `payroll_exception_reference_20260311.txt.txt`         | [pending]           | [ANALYST] | [to compute on collection] | Case evidence store, NH-INC-2026-0311  |
| `payroll_review_dpatel_20260311.txt` (nh-fs-01 profile) | [pending]           | [ANALYST] | [to compute]               | Restricted, PII; access-logged         |
| `review_audit_20260311.txt` (live + backup copy)       | [pending]           | [ANALYST] | [to compute, both]         | Case evidence store; diff retained     |
| KQL query exports (all findings)                        | 2026-08-15          | [ANALYST] | [to compute]               | Case evidence store                    |
| Screenshot exhibits (F1–F11)                            | 2026-08-15          | [ANALYST] | [to compute]               | Case evidence store                    |

### B2.6 Regulatory notification

| **Field**              | **Value**                                                                                                                                                                              |
| ---------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Personal data involved | Yes. Payroll review records for six named employees; compensation change log; merit increase review; bonus eligibility summary and a performance improvement plan notice (both attribution-unresolved, N7). |
| Data elements          | To be confirmed by inspection of the recovered files. Payroll and compensation records commonly contain name, salary, and may contain identification numbers; the specific elements determine whether notification is triggered. |
| Regulation(s) engaged  | US state breach-notification laws (employment records). HIPAA is **not** engaged on current evidence, as no patient or clinical data was observed accessed, but see N6, which notes that this requires independent verification given the healthcare setting. |
| Notification required  | Undetermined pending the data-element review above. Employee-record breaches trigger notification in most states where an identification number is present.                            |
| Deadline (UTC)         | Runs from discovery, not remediation. Per-state clocks apply.                                                                                                                          |
| Notified (UTC)         | [pending Legal/Privacy action]                                                                                                                                                          |

*Two subjects warrant specific mention: c.wright, whose own payroll record was taken using her own compromised account, and d.patel, whose record was staged locally and who was otherwise uninvolved.*

### B2.7 Detection engineering

Each rule corresponds to a step in this incident that generated telemetry and produced no alert-driven referral. All four would have fired on 11 March. Existing alert coverage should be confirmed by query before these are described as new (Appendix D, D2).

**D1. External RDP success**

*The single highest-value rule for this estate. Fires at 12:06:48, before any data is touched.*

```kusto
DeviceLogonEvents
| where ActionType == "LogonSuccess" and LogonType == "RemoteInteractive"
| where isnotempty(RemoteIP)
| where not(ipv4_is_private(RemoteIP))
| project TimeGenerated, DeviceName, AccountName, RemoteIP
```

**D2. One external source, multiple accounts**

*Catches the credential switch at 12:51, and is resistant to address rotation because it keys on behaviour.*

```kusto
DeviceLogonEvents
| where ActionType == "LogonSuccess" and isnotempty(RemoteIP)
| where not(ipv4_is_private(RemoteIP))
| summarize Accounts = dcount(AccountName), Names = make_set(AccountName)
          by RemoteIP, bin(TimeGenerated, 1h)
| where Accounts > 1
```

**D3. Discovery burst under an interactive shell**

*Fires on the orientation burst at 12:44. Keys on the parent process, so it catches commands not on any keyword list.*

```kusto
DeviceProcessEvents
| where InitiatingProcessFileName in~ ("cmd.exe", "powershell.exe")
| where FileName in~ ("whoami.exe","hostname.exe","net.exe","net1.exe","arp.exe","nslookup.exe")
| summarize Commands = dcount(FileName), Ran = make_set(ProcessCommandLine)
          by DeviceName, AccountName, bin(TimeGenerated, 5m)
| where Commands >= 3
```

**D4. Cross-departmental file relocation**

*Fires on the plant at 13:01:47, before the rename that would hide it from a name-based search.*

```kusto
DeviceFileEvents
| where ActionType in ("FileCreated", "FileRenamed")
| where FolderPath contains "\\Shares\\"
| extend Share = extract(@"\\Shares\\([^\\]+)", 1, FolderPath)
| where FileName has_any ("payroll", "compensation", "salary", "pip_")
| where Share !~ "HR"
```

---

**Appendices**

## Appendix A, Full queries

The queries below are the ones run during the investigation, grouped by the question each answered. All are bound to the 8–18 March 2026 window and scoped to `nh-*` hosts. The workspace is shared and holds a separate May 2026 incident, so the time bind and host scope are load-bearing, not cosmetic.

### Scoping and account identification

**Baseline distribution on the billing workstation (F1)**

*Distribution before detail. Reveals both analysts, the scheduled task, and the administrator spray in one query.*

```kusto
let targetDevice = "nh-";
let startDate = datetime(2026-03-08);
let endDate   = datetime(2026-03-18);
DeviceLogonEvents
| where DeviceName startswith targetDevice and DeviceName contains "bill"
| where TimeGenerated between (startDate .. endDate)
| summarize Events=count(), First=min(TimeGenerated), Last=max(TimeGenerated)
          by AccountName, DeviceName, ActionType, RemoteIP, LogonType
| sort by Events desc
```

**Successful remote sessions across the estate (F3, F7)**

*Drops the single-host filter; the DeviceName column becomes the lateral-movement map.*

```kusto
let startDate = datetime(2026-03-08);
let endDate   = datetime(2026-03-18);
DeviceLogonEvents
| where TimeGenerated between (startDate .. endDate)
| where DeviceName startswith "nh-"
| where ActionType == "LogonSuccess"
| where LogonType == "RemoteInteractive"
| where isnotempty(RemoteIP)
| project TimeGenerated, DeviceName, AccountName, RemoteIP, RemoteDeviceName
| sort by TimeGenerated asc
```

**Failure profile per account and source (F2)**

*The discriminator between brute force and pre-held credentials.*

```kusto
let startDate = datetime(2026-03-08);
let endDate   = datetime(2026-03-18);
DeviceLogonEvents
| where TimeGenerated between (startDate .. endDate)
| where DeviceName startswith "nh-"
| where AccountName in ("j.morris", "nh-admin")
| summarize count() by AccountName, ActionType, RemoteIP
```

**Internal source resolution (F7)**

*`IPAddresses` is a JSON array and must be expanded before filtering.*

```kusto
let startDate = datetime(2026-03-08);
let endDate   = datetime(2026-03-18);
DeviceNetworkInfo
| where TimeGenerated between (startDate .. endDate)
| where DeviceName startswith "nh-"
| mv-expand parse_json(IPAddresses)
| extend IP = tostring(IPAddresses.IPAddress)
| where IP in ("10.0.8.8", "10.0.8.9", "10.1.0.207", "10.1.0.235", "10.0.8.6")
| distinct DeviceName, IP
```

### Noise elimination

**Volume profile of process activity (F5)**

*Establishes what the estate's baseline looks like so operator activity can be recognised against it.*

```kusto
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-03-09 01:00) .. datetime(2026-03-09 06:00))
| where DeviceName startswith "nh-"
| where AccountName in ("j.morris", "nh-admin")
| summarize Runs=count() by DeviceName, AccountName, FileName
| sort by Runs desc
```

**Frequency discrimination on a candidate behaviour (F4)**

*The general form of the test: if a behaviour recurs daily it is automation; if it appears once it is worth working.*

```kusto
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-03-08) .. datetime(2026-03-18))
| where DeviceName startswith "nh-"
| where ProcessCommandLine has "localgroup"
| project TimeGenerated, DeviceName, AccountName, ProcessCommandLine
| sort by TimeGenerated asc
```

### Discovery and execution

**Estate-wide discovery sweep (F5, F6)**

*Searches the command line rather than the file name, which catches PowerShell cmdlets that a `FileName` filter would miss entirely.*

```kusto
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-03-08) .. datetime(2026-03-18))
| where DeviceName startswith "nh-"
| where ProcessCommandLine has_any ("localgroup","net user","net group","net view",
        "net share","whoami","systeminfo","nltest","dsquery","query user","quser",
        "net accounts","Get-ADUser","Get-ADGroup","Get-LocalGroup","tasklist",
        "ipconfig","arp -a","netstat","hostname","nslookup")
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine
| sort by TimeGenerated asc
```

**Typed commands isolated by parent process (F5, F6, F8, F11)**

*The highest-yield filter in this investigation. Anything typed into a console is a child of the shell, whatever the binary.*

```kusto
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-03-11 12:42) .. datetime(2026-03-11 13:25))
| where DeviceName startswith "nh-wks-bill-01"
| where AccountName =~ "j.morris"
| where InitiatingProcessFileName in~ ("cmd.exe","powershell.exe","conhost.exe")
| project TimeGenerated, FileName, ProcessCommandLine, InitiatingProcessFileName
| sort by TimeGenerated asc
```

**Unfiltered session review (F5)**

*No keyword list at all. Necessary once the shape of the noise is known, because a predicted-keyword search finds only what the analyst already suspected.*

```kusto
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-03-11 12:00) .. datetime(2026-03-11 14:30))
| where DeviceName startswith "nh-wks-bill-01"
| where AccountName =~ "j.morris"
| project TimeGenerated, FileName, ProcessCommandLine, InitiatingProcessFileName
| sort by TimeGenerated asc
```

### Collection and staging

**Documents opened across the shares (F9)**

*Notepad records the full UNC path on the command line, which gives the complete list of documents touched in one query.*

```kusto
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-03-11 12:00) .. datetime(2026-03-11 19:00))
| where ProcessCommandLine contains "NH-FS-01"
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine
| sort by TimeGenerated asc
```

**The staging chain (F10)**

*Searching on the file-name stem rather than a path catches the file in both shares and across the rename.*

```kusto
DeviceFileEvents
| where TimeGenerated between (datetime(2026-03-11 12:45) .. datetime(2026-03-11 19:00))
| where FileName contains "payroll_review" or FileName contains "temp_"
| project TimeGenerated, DeviceName, ActionType, FileName, FolderPath,
          InitiatingProcessFileName, InitiatingProcessAccountName
| sort by TimeGenerated asc
```

**Local staging on the file server (F11)**

*Note the column: in `DeviceFileEvents` the actor is `InitiatingProcessAccountName`, not `AccountName`.*

```kusto
DeviceFileEvents
| where TimeGenerated between (datetime(2026-03-11 13:36) .. datetime(2026-03-12 06:00))
| where DeviceName startswith "nh-fs-01"
| where InitiatingProcessAccountName =~ "j.morris"
| project TimeGenerated, ActionType, FileName, FolderPath, InitiatingProcessFileName
| sort by TimeGenerated asc
```

**Archive and exfiltration-tooling sweep (N5)**

*Returned only Azure guest-agent bundles; the negative is the finding.*

```kusto
DeviceFileEvents
| where TimeGenerated between (datetime(2026-03-11 12:00) .. datetime(2026-03-12 06:00))
| where DeviceName startswith "nh-"
| where FolderPath contains "\\Exceptions\\"
     or FolderPath contains "\\Users\\j.morris\\Documents"
     or FolderPath contains "\\Downloads"
     or FileName endswith ".zip" or FileName endswith ".7z" or FileName endswith ".rar"
| project TimeGenerated, DeviceName, ActionType, FileName, FolderPath,
          InitiatingProcessFileName, InitiatingProcessAccountName
| sort by TimeGenerated asc
```

**Negative test on the red-herring hop (N1)**

*Run against three tables with no command filter, then with a shell-parent filter. Both empty.*

```kusto
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-03-11 13:27) .. datetime(2026-03-11 19:00))
| where DeviceName startswith "nh-wks-it-01"
| where AccountName =~ "j.morris"
| where InitiatingProcessFileName in~ ("cmd.exe","powershell.exe","conhost.exe","explorer.exe")
| project TimeGenerated, FileName, ProcessCommandLine, InitiatingProcessFileName
| sort by TimeGenerated asc
```

---

## Appendix B, Raw evidence extracts

Selected raw extracts, trimmed to the fields that carry the finding. Full result sets are retained unedited in the case evidence store.

### B-1 Orientation burst (F5)

*DeviceProcessEvents, nh-wks-bill-01. Five commands in 147 seconds, all children of `cmd.exe`. The console itself opened seven seconds before the first.*

| **Time (UTC)** | **FileName**   | **ProcessCommandLine** | **Parent** |
| -------------- | -------------- | ---------------------- | ---------- |
| 12:42:05       | conhost.exe    | `conhost.exe 0xffffffff -ForceV1` | cmd.exe |
| 12:42:12.976   | whoami.exe     | `whoami`               | cmd.exe    |
| 12:43:31.930   | HOSTNAME.EXE   | `hostname`             | cmd.exe    |
| 12:43:41.200   | net.exe        | `net use`              | cmd.exe    |
| 12:44:10.185   | net.exe        | `net view`             | cmd.exe    |
| 12:44:39.698   | net.exe        | `net view \\NH-FS-01`  | cmd.exe    |

### B-2 Network mapping phase (F6)

*DeviceProcessEvents, nh-wks-bill-01. Parent changes to `powershell.exe`, marking a separate phase 31 minutes later.*

| **Time (UTC)** | **ProcessCommandLine**        | **Parent**     |
| -------------- | ----------------------------- | -------------- |
| 13:16:00.838   | `"net.exe" view`              | powershell.exe |
| 13:17:35.618   | `"net.exe" view /domain:nimbus` | powershell.exe |
| 13:18:08.272   | `"ARP.EXE" -a`                | powershell.exe |
| 13:18:51.678   | `"nslookup.exe" 10.1.0.233`   | powershell.exe |
| 13:18:59.007   | `"nslookup.exe" 10.1.0.234`   | powershell.exe |
| 13:19:14.049   | `"nslookup.exe" 10.1.0.235`   | powershell.exe |
| 13:19:35.992   | `"nslookup.exe" 10.1.7.255`   | powershell.exe |
| 13:20:04.904   | `"nslookup.exe" 224.0.0.22`   | powershell.exe |
| 13:20:19.691   | `"nslookup.exe" 10.1.0.1`     | powershell.exe |

### B-3 Group enumeration, 9 March (F4)

*DeviceProcessEvents. `net.exe` hands off to `net1.exe` roughly 13 ms later; the pairs are one command each, not two.*

| **Time (UTC)**      | **Host**       | **Account** | **ProcessCommandLine**                  |
| ------------------- | -------------- | ----------- | --------------------------------------- |
| 2026-03-09 04:40:08.384 | nh-wks-clin-01 | nh-admin | `"net.exe" localgroup "Remote Desktop Users"` |
| 2026-03-09 04:40:08.397 | nh-wks-clin-01 | nh-admin | `net1 localgroup "Remote Desktop Users"` |
| 2026-03-09 04:45:03.774 | nh-dc-01       | nh-admin | `"net.exe" localgroup "Remote Desktop Users"` |
| 2026-03-09 04:45:32.146 | nh-wks-clin-01 | nh-admin | `"net.exe" localgroup "Remote Desktop Users"` |

### B-4 Billing workflow access (F9)

*DeviceProcessEvents. Notepad carries the full UNC path, so the process log is the file-access record.*

| **Time (UTC)** | **Folder**       | **File**                                          |
| -------------- | ---------------- | ------------------------------------------------- |
| 12:10:57.543   | `Approved`       | `approved_pending_invoice_INV-664215_20260310.txt` |
| 12:11:56.148   | `Approved`       | `approved_pending_invoice_INV-773221_20260311.txt` |
| 12:12:29.768   | `Reconciliation` | `billing_reconciliation_20260311.txt`             |
| 12:13:11.989   | `AuditTrail`     | `review_audit_20260311.txt`                       |

### B-5 Payroll access under the second account (F9)

*DeviceFileEvents. Share-side events are logged under SYSTEM; the client-side `.lnk` in `Recent` is what attributes them to c.wright.*

| **Time (UTC)** | **Subject**  | **Share-side (nh-fs-01)** | **Client-side attribution (nh-wks-hr-01)** |
| -------------- | ------------ | ------------------------- | ------------------------------------------ |
| 12:54:46       | achen        | FileRenamed, SYSTEM       | `.lnk` created, c.wright                   |
| 12:55:40       | mperez       | FileRenamed, SYSTEM       | `.lnk` created, c.wright                   |
| 12:56:39       | cwright      | FileRenamed, SYSTEM       | `.lnk` created, c.wright                   |
| 12:56:58       | dpatel       | FileRenamed, SYSTEM       | `.lnk` created, c.wright                   |
| 12:57:21       | lrodriguez   | FileRenamed, SYSTEM       | `.lnk` created, c.wright                   |
| 12:57:39       | jmorris      | FileRenamed, SYSTEM       | `.lnk` created, c.wright                   |

Share-side `FileModified` events for the same six files follow at 12:55:07, 12:55:50, 12:58:18, 12:58:26, 12:58:36 and 12:58:42. The 75 ms cluster referenced in F9 is the Notepad process opens at 12:58:09.429–.504 in `DeviceProcessEvents`, a different table. The two should not be conflated.

### B-6 The staging chain (F10)

*DeviceFileEvents, nh-fs-01. Three events across 160 seconds.*

| **Time (UTC)** | **ActionType** | **Path**                                                                            |
| -------------- | -------------- | ------------------------------------------------------------------------------------ |
| 12:59:21.549   | FileRenamed    | `C:\Shares\HR\2026-03\Payroll\temp_payroll_review_jmorris_20260311.txt.txt`           |
| 13:01:47.502   | FileCreated    | `C:\Shares\Billing\2026-03\Exceptions\temp_payroll_review_jmorris_20260311.txt.txt`   |
| 13:02:01.770   | FileRenamed    | `C:\Shares\Billing\2026-03\Exceptions\payroll_exception_reference_20260311.txt.txt`   |

The destination folder already contained a genuine `billing_exceptions_20260311.txt`, modified routinely throughout the day by `ntoskrnl.exe`.

### B-7 Local staging on the file server (F11)

*DeviceFileEvents, nh-fs-01. `explorer.exe` as the initiating process indicates a manual GUI copy inside the RDP session.*

| **Time (UTC)** | **ActionType** | **Path**                                                        | **Initiating process** |
| -------------- | -------------- | ---------------------------------------------------------------- | ---------------------- |
| 13:40:08.857   | FileCreated    | `C:\Users\j.morris\Documents\payroll_review_dpatel_20260311.txt`  | explorer.exe           |
| 13:40:08.857   | FileModified   | same                                                             | explorer.exe           |
| 13:40:13.382   | FileCreated    | `...\Windows\Recent\payroll_review_dpatel_20260311.lnk`            | explorer.exe           |

### B-8 Estate noise signatures ruled out

*Recorded so future hunts in this estate can discard them immediately.*

| **Signature**                                                        | **Source**                              | **Cadence**                       |
| --------------------------------------------------------------------- | --------------------------------------- | --------------------------------- |
| `cmd.exe /q /c del /q "...\OneDrive\Update\OneDriveSetup.exe"`        | OneDrive self-maintenance               | Multiple times daily, every host  |
| `"powershell.exe"` with no arguments                                  | OneDrive / scheduled tasks              | Multiple times daily              |
| `ipconfig /all` + `netstat /a /b /o` pairs under the SYSTEM account   | Inventory or monitoring agent           | Daily, every host                 |
| `VMAgentLogs.zip` written by `collectguestlogs.exe`                   | Azure VM guest agent                    | ~30 minutes, every host           |
| `cscript.exe //B //Nologo "C:\scripts\billing-baseline.vbs"`          | Billing scheduled task                  | Hourly on the minute; Batch logons |
| `pending_claim_CLM-*.csv` writes to `Billing\2026-03\Pending`          | Output of the above task                | Hourly                            |
| `umfd-*`, `dwm-*`, `nh-wks-*$` logon entries                          | Windows session/window manager, machine accounts | Continuous              |
| `LogonAttempted` + `LogonType Unknown` paired with an adjacent success | MDE shadow record                       | Every logon; do not double-count  |

---

## Appendix C, Reference list

- MITRE ATT&CK, <https://attack.mitre.org/>

- Microsoft Defender for Endpoint advanced hunting schema reference, <https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-schema-tables>

- NIST SP 800-61r3, Incident Response Recommendations and Considerations, <https://csrc.nist.gov/pubs/sp/800/61/r3/final>

- SANS PICERL incident-handling process, <https://www.sans.org/>

- RFC 1918, Address Allocation for Private Internets, <https://datatracker.ietf.org/doc/html/rfc1918>

- Windows logon type reference (event 4624), <https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/appendix-l--events-to-monitor>

### Placeholder legend

*The identities, hosts and addresses in this report are those of a training environment and are reproduced as recorded. Where a real engagement would redact, the convention below applies.*

| **Placeholder** | **Refers to**                                                        |
| --------------- | -------------------------------------------------------------------- |
| [ANALYST]       | Reporting analyst, SOC / Cyber Range Operations                      |
| j.morris        | Billing analyst, submissions role; primary compromised account       |
| c.wright        | HR staff; second compromised account                                 |
| d.patel         | Billing analyst; investigation control baseline and a data subject   |
| nh-admin        | Privileged service account; legitimate automation, separately abused |
| a.chen, m.perez, l.rodriguez | Clinic staff; data subjects only                        |
| `nh-*`          | Nimbus Health estate hosts                                           |
| 10.1.0.x / 10.0.8.x | Internal addresses                                               |

---

## Appendix D, Outstanding verification

*Items whose value or claim could not be re-read off a retained query result during the cold verification pass. Each is marked **[unverified]** at its point of use. None changes a conclusion; all change how defensible the citation is.*

| **#** | **Item**                                                        | **Status**                                                                                              | **What closes it**                                                                                          |
| ----- | ---------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------- |
| D1    | Exact timestamp of `"net.exe" share` on nh-fs-01 (F11, timeline) | Command and sequence position confirmed; timestamp recorded as `~13:37` without a retained result           | `DeviceProcessEvents` on nh-fs-01, 13:36–14:30, `ProcessCommandLine has "share"`                              |
| D2    | "No alert fired" (B2.1, §8 rec 8, B2.7)                          | Asserted from the absence of an alert-driven referral; `SecurityAlert` / `SecurityIncident` never queried   | `SecurityAlert` over 08–18 March filtered to the two accounts and the three hosts                             |
| D3    | Attribution of the 14:02–14:03 HR file events (N7)               | Assessed operator-attributable at moderate confidence from write-signature comparison; not confirmed        | Bin those file creations by day across 08–18 March: daily recurrence means generator, single occurrence means operator |
| D4    | Data elements inside the accessed payroll records (B2.6)         | Not inspected; determines whether breach notification is triggered                                          | Not a query. Inspection of the recovered files under Legal/Privacy supervision                                |
| D5    | Outbound transfer to the three operator addresses (B2.1, N5)     | Never queried; exfiltration assessed from staging behaviour alone                                           | `DeviceNetworkEvents` filtered to the three external addresses across the window                               |
| D6    | Resolution of 10.0.8.6 / 10.0.8.8 / 10.0.8.9 (F7, gaps)          | Returned nothing in `DeviceNetworkInfo`; may be outside MDE coverage                                        | Re-run without the `nh-*` filter and without the time bound, then fall back to `RemoteDeviceName`               |
| D7    | Whether other planted files exist (B2.3)                         | One instance confirmed; the technique is cheap to repeat and no sweep was run                               | Sweep `\Shares\` for filenames carrying a doubled extension                                                   |

*Note on identifiers: `NH-INC-2026-0311` is an analyst-assigned case reference for this report. It is not a Sentinel `IncidentNumber` and not an MDE portal incident ID. No query in this report cites it, and none should; it will not resolve in any workspace.*
