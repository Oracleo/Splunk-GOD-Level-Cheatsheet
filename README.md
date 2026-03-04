<div align="center">

```
███████╗██████╗ ██╗     ██╗   ██╗███╗   ██╗██╗  ██╗
██╔════╝██╔══██╗██║     ██║   ██║████╗  ██║██║ ██╔╝
███████╗██████╔╝██║     ██║   ██║██╔██╗ ██║█████╔╝ 
╚════██║██╔═══╝ ██║     ██║   ██║██║╚██╗██║██╔═██╗ 
███████║██║     ███████╗╚██████╔╝██║ ╚████║██║  ██╗
╚══════╝╚═╝     ╚══════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═╝
```

**God-Level SPL Reference for SOC Analysts, Threat Hunters & SIEM Engineers**

[![Live Demo](https://img.shields.io/badge/🔥_LIVE_DEMO-View_Cheatsheet-f97316?style=for-the-badge&labelColor=0c0800)](https://oracleo.github.io/Splunk-GOD-Level-Cheatsheet/Splunk-GOD-Level-Cheatsheet.html)
[![License](https://img.shields.io/badge/LICENSE-MIT-fbbf24?style=for-the-badge&labelColor=0c0800)](LICENSE)
[![PRs Welcome](https://img.shields.io/badge/PRs-WELCOME-22c55e?style=for-the-badge&labelColor=0c0800)](CONTRIBUTING.md)

![Splunk](https://img.shields.io/badge/SPLUNK-SPL-f97316?style=flat-square&labelColor=0c0800)
![SOC](https://img.shields.io/badge/ROLE-SOC_ANALYST-fbbf24?style=flat-square&labelColor=0c0800)
![ThreatHunting](https://img.shields.io/badge/ROLE-THREAT_HUNTER-ef4444?style=flat-square&labelColor=0c0800)
![DFIR](https://img.shields.io/badge/ROLE-DFIR-2dd4bf?style=flat-square&labelColor=0c0800)
![HTML](https://img.shields.io/badge/BUILT_WITH-HTML_·_CSS_·_JS-fbbf24?style=flat-square&labelColor=0c0800)


</div>

---

## What Is This?

A **single-file, fully interactive Splunk SPL cheatsheet** for cybersecurity professionals preparing for SOC analyst, threat hunter, DFIR, and SIEM engineer roles. Covers everything from basic SPL search syntax to production-grade alert engineering and advanced behavioral detections.

> *"Most candidates can write `index=main | stats count by host`. You write multi-stage correlation queries, risk-scored alerts with lookup-driven whitelisting, and behavioral detections using streamstats and eventstats. That's what gets you hired."*

---

## What's Inside

| Tab | Contents |
|-----|----------|
| **Overview** | Master quick-reference — search structure, top commands, stats functions, time modifiers, boolean operators, key sourcetypes |
| **SPL Basics** | search, table, where, sort, dedup, top, rare, head/tail, rename, fields — the foundational 11 |
| **Stats & Aggregation** | stats, timechart, chart, eventstats, streamstats — the analytics core |
| **Eval & Fields** | eval (if/case/math/string), rex, rex mode=sed, spath, convert — data transformation |
| **Lookup & Enrich** | lookup, inputlookup, outputlookup, append, join, union, tstats — enrichment & correlation |
| **Threat Hunting** | 10 ready-to-run hunt queries: brute force, lateral movement, Pass-the-Hash, impossible travel, DNS beaconing, PowerShell, exfiltration |
| **Windows Events** | Complete Event ID reference with Logon Types, Sysmon events, PS logging — with Splunk queries for each |
| **Network & Firewall** | Top talkers, port scan detection, C2 beaconing, blocked spikes, DNS exfil, firewall changes |
| **Alert Engineering** | 6 production-grade alerts with scheduling, thresholds, FP reduction, and deployment notes |
| **Interview** | 8 real interview questions with full SPL answers + the reasoning you explain out loud |

---

## Quick Start

```bash
git clone https://github.com/Oracleo/Splunk-GOD-Level-Cheatsheet.git
cd Splunk-GOD-Level-Cheatsheet
open Splunk-GOD-Level-Cheatsheet.html   # macOS
xdg-open Splunk-GOD-Level-Cheatsheet.html  # Linux
```

Or visit the live demo → **[oracleo.github.io/Splunk-GOD-Level-Cheatsheet](https://oracleo.github.io/Splunk-GOD-Level-Cheatsheet/Splunk-GOD-Level-Cheatsheet.html)**

---

## SPL Commands & Queries Covered


```
SEARCH BASICS            │  AGGREGATION              │  FIELD MANIPULATION
─────────────────────────┼───────────────────────────┼────────────────────────
index= sourcetype=        │  | stats count by         │  | eval if() case()
| search | where          │  | stats dc() values()    │  | eval round() lower()
| table | sort | dedup    │  | timechart span=1h       │  | rex "(?P<name>regex)"
| top | rare | head       │  | eventstats | streamstats│  | spath | convert
| rename | fields         │  | chart over by           │  | rex mode=sed

ENRICHMENT               │  THREAT HUNTING           │  PRODUCTION ALERTS
─────────────────────────┼───────────────────────────┼────────────────────────
| lookup OUTPUT           │  Brute force (4625)       │  Scheduled every 5min
| lookup OUTPUTNEW        │  Lateral movement (4624)  │  Lookup-driven whitelists
| inputlookup             │  Pass-the-Hash NTLM       │  tstats accelerated
| outputlookup            │  Impossible travel        │  FP reduction patterns
| tstats from datamodel=  │  DNS beaconing (dc/stdev) │  Suppress + escalate
| join | union | append   │  PowerShell encoded (4104)│  Risk scoring with eval
```



---

## Threat Hunting Queries Included

```spl
// Brute Force Detection
index=windows EventCode=4625
| stats count as failures by src_ip, user
| where failures > 10 | sort -failures

// Lateral Movement
index=windows EventCode=4624 Logon_Type=3
| stats dc(host) as unique_hosts by user
| where unique_hosts > 5 | sort -unique_hosts

// Compromised Account (Fail → Success)
index=windows (EventCode=4625 OR EventCode=4624)
| stats count(eval(EventCode=4625)) as fails,
        count(eval(EventCode=4624)) as success by user, src_ip
| where fails > 5 AND success > 0

// PowerShell Encoded Commands (Malware Indicator)
index=windows EventCode=4104
| search ScriptBlockText="*-enc*" OR ScriptBlockText="*FromBase64*"

// C2 Beaconing via Network Traffic (Jitter Analysis)
index=firewall | bucket span=1h _time
| stats count by _time, src_ip, dest_ip
| stats stdev(count) as jitter by src_ip, dest_ip
| where jitter < 2 | sort jitter

// ... 5 more inside the cheatsheet
```

---

## 🪟 Critical Windows Event IDs Reference

```
AUTHENTICATION          ACCOUNT MGMT            EXECUTION & PERSISTENCE
────────────────────    ────────────────────    ────────────────────────
4624 Successful logon   4720 Account created    4688 Process created
4625 Failed logon ⚡    4726 Account deleted    4698 Scheduled task ⚡
4648 Explicit creds     4728 Added to group ⚡  7045 New service ⚡
4672 Special privs ⚡   4732 Added local group  Sysmon 1 Process detail
4768 Kerberos TGT       4756 Universal group    Sysmon 3 Net connection
4769 Kerberos ST        4719 Audit policy chg   PS 4104 Script block ⚡
4771 Kerberos fail      4767 Account unlocked   PS 4103 Module logging

LOGON TYPES
────────────────────────────────────────────
Type 2  = Interactive (local console)
Type 3  = Network ← lateral movement indicator
Type 8  = NetworkCleartext ← credentials in plaintext
Type 10 = RemoteInteractive (RDP) ← remote access
```

---

## Features

- **Live Cross-Tab Search** — Filter any SPL command, event ID, or attack technique instantly
- **10 Organized Tabs** — From basics to production alert engineering
- **SPL Log Ticker** — Animated live-query ticker in the header
- **Severity Badges** — CRITICAL / SOC / HUNT / IR / PRO labels
- **Guru Tips & Interview Boxes** — Contextual insights and answer frameworks
- **Responsive** — Works on desktop and mobile
- **Zero Dependencies** — Single HTML file, works fully offline

---

## Who Is This For?

```
✅ SOC Analyst candidates (L1/L2/L3 interviews)
✅ Threat Hunters learning behavioral detection SPL
✅ DFIR analysts conducting log-based investigations
✅ Splunk admins building production alert content
✅ Security engineers writing SIEM detection rules
✅ Students preparing for: Splunk Core Certified User/Power User, CySA+, GCIH, GCIA
✅ CTF players (HackTheBox, TryHackMe — SIEM/forensics challenges)
```

---

## Tech Stack

| Layer | Choice | Why |
|-------|--------|-----|
| Structure | Pure HTML5 | Zero build step, instant open |
| Styling | CSS3 + Custom Properties | Splunk orange/amber brand palette |
| Logic | Vanilla JavaScript | Live cross-tab search |
| Fonts | Bebas Neue + Space Mono + DM Sans | Industrial SIEM dashboard aesthetic |
| Hosting | GitHub Pages | Free, fast, permanent URL |

---

## Repository Structure

```
Splunk-GOD-Level-Cheatsheet/
│
├── Splunk-GOD-Level-Cheatsheet.html   # ← The entire app. One file.
├── README.md                           # ← You are here
└── LICENSE                             # MIT
```

---

## Security Tools Reference Series

> Building a complete god-level reference library:

| Tool | Repo | Focus |
|------|------|-------|
| 🟢 NMAP | [Nmap-GOD-Level-Cheatsheet](https://github.com/Oracleo/Nmap-GOD-Level-Cheatsheet) | Recon, port scanning, NSE scripts |
| 🔵 Wireshark | [Wireshark-GOD-Level-Cheatsheet](https://github.com/Oracleo/Wireshark-GOD-Level-Cheatsheet) | Packet analysis, forensics |
| 🔥 Splunk | Splunk-GOD-Level-Cheatsheet ← **You are here** | SPL, SIEM, threat hunting |

*Coming next: Metasploit · Burp Suite · Volatility · Suricata*

---

## Contributing

Have a better detection query? Know a missing Event ID? PRs welcome.

```bash
git clone https://github.com/Oracleo/Splunk-GOD-Level-Cheatsheet.git
```

Suggest new sections via Issues: Splunk ES correlation searches, ES notable events workflow, Splunk SOAR playbooks, cloud log sources (AWS CloudTrail, Azure AD).

---

## License

MIT — use it, share it, build on it.

---

## Author

<div align="center">

Built by **[Dr. Niladri Biswas](https://www.linkedin.com/in/dr-niladri-biswas/)**

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Dr._Niladri_Biswas-0077b5?style=for-the-badge&logo=linkedin&logoColor=white)](https://www.linkedin.com/in/dr-niladri-biswas/)
[![GitHub](https://img.shields.io/badge/GitHub-Oracleo-181717?style=for-the-badge&logo=github&logoColor=white)](https://github.com/Oracleo)

</div>

---

<div align="center">

**Built for the security community. Hunt threats. Write better SPL. Get hired.**

`splunk` · `spl` · `siem` · `threat-hunting` · `soc` · `dfir` · `cybersecurity` · `blue-team` · `incident-response` · `windows-event-logs` · `alert-engineering` · `interview-prep`

</div>
