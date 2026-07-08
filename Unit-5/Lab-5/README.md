# Lab 5: Splunkin' Around — SIEM Fundamentals & Incident Investigation

A hands-on lab exploring Splunk as a Security Information and Event Management (SIEM) platform. Using Docker and pre-indexed datasets, I practiced building SPL searches, visualizing log data, and investigating a simulated web server breach the way a SOC analyst would.

**Course:** CodePath CYB102 — Unit 5  
**Lab source:** [codepath/opencyber-splunk-lab](https://github.com/codepath/opencyber-splunk-lab) (Parts 0–2)

---

## Overview

A SIEM aggregates logs from firewalls, servers, endpoints, and applications into one searchable platform. Without one, an analyst investigating an incident has to pull logs from dozens of separate systems manually. With one, they can correlate events across the entire environment in a single query.

This lab runs entirely in Docker — no Azure Labs or VM required. All interaction happens through Splunk's web UI at `http://localhost:8000`.

---

## Environment Setup

**Prerequisites:** Docker Desktop (Mac/Windows/Linux)

```bash
docker run --rm -it -p 8000:8000 -v splunk-lab-data:/opt/splunk/var --platform linux/amd64 ghcr.io/codepath/opencyber-splunk-lab:latest
```
```


| Flag | Purpose |
|------|---------|
| `-p 8000:8000` | Exposes Splunk web UI on localhost |
| `-v splunk-lab-data:/opt/splunk/var` | Persists indexed data and dashboards across sessions |
| `--platform linux/amd64` | Required on Apple Silicon (Splunk has no native arm64 build) |
| `--rm -it` | Interactive terminal; container removed on stop, volume data retained |

**Credentials:** `admin` / `codepath`  
**First startup:** ~90 seconds (data indexing); subsequent starts ~30 seconds.

Pre-indexed datasets include video game sales data, Netflix titles, WebServer01 authentication logs, and PathCode Inc. malware investigation logs (used in the Unit 5 Project).

---

## Skills Demonstrated

- SIEM concepts and Splunk terminology: **index**, **sourcetype**, **source**, **host**
- Writing SPL (Search Processing Language) queries with field filters, wildcards, and pipes
- Aggregating data with `stats`, `sort`, `head`, `timechart`, and `table`
- Building visualizations (pie charts, bar charts, line charts)
- Creating dashboards and saved reports for repeatable SOC workflows
- Investigating a simulated brute-force attack against a Linux web server

---

## Part 1: Splunk Fundamentals

### Key SPL Queries

**Basic search — target a dataset by index and host:**
```spl
index=main host="SalesData"
```

**Aggregate and rank — top gaming platforms by title count:**
```spl
index=main host="SalesData" | stats count by Platform | sort -count | head 5
```

**Security-focused search — failed login attempts on WebServer01:**
```spl
index=main host="WebServer01" Message="Failed password for" | stats count by IP | sort -count
```

### Deliverables

| Artifact | Description |
|----------|-------------|
| **Video Game Statistics** dashboard | 3+ panels: top platforms (pie chart), top genres (bar chart), and a custom panel |
| **Top 10 Source IPs with Failed Login Attempts** report | Bar chart of source IPs generating failed auth events on WebServer01 |

### Part 1 Findings

Top failed-login source IPs on WebServer01:

| IP | Failed Login Count |
|----|--------------------|
| 1.3.3.7 | 38 |
| 15.16.17.18 | 9 |
| 7.8.9.10 | 3 |
| 192.168.1.104 | 2 |
| *(7 more IPs, 1 each)* | |

`1.3.3.7` accounts for more failed attempts than all other IPs combined — flagged for deeper investigation in Part 2.

---

## Part 2: Web Server Breach Investigation

### Scenario

PathCode Inc.'s security team flagged unusual activity in `WebServer01` authentication logs. As the on-call SOC analyst, the goal was to characterize the attack, identify the threat actor, and determine whether any logins succeeded.

### Investigation Queries

**Activity timeline — when did the attack spike?**
```spl
index=main host="WebServer01" | timechart count
```

**Event type breakdown:**
```spl
index=main host="WebServer01" | stats count by Message
```

**Top attacking IPs (failed logins only):**
```spl
index=main host="WebServer01" Message="Failed password for" | stats count by IP | sort -count | head 10
```

**Successful logins — did the attacker get in?**
```spl
index=main host="WebServer01" Message="Accepted password for" | table _time IP
```

**Profile the primary suspect:**
```spl
index=main host="WebServer01" IP="1.3.3.7" | stats count by Message
```

### Key Findings

| Metric | Value |
|--------|-------|
| Total events | 98 |
| Failed login attempts | 60 (61% of all activity) |
| Successful logins | 38 |
| Primary attacker IP | `1.3.3.7` (38 failed attempts) |
| Attacker successfully logged in? | **No** — all 38 events from `1.3.3.7` are failed attempts |

**Conclusion:** A concentrated brute-force attack occurred within a narrow time window. The primary suspect (`1.3.3.7`) generated 38 failed password attempts but never achieved a successful login. The brute-force attack was blocked; no compromise from that IP.

### Deliverable

**WebServer01 Breach Investigation** dashboard — three panels:
1. **Activity Timeline** — `timechart` showing the attack spike
2. **Top Attacking IPs** — ranked failed-login sources
3. **Successful Logins** — `table _time IP` showing accepted auth events

---

## Splunk Terminology Reference

| Term | Analogy | Description |
|------|---------|-------------|
| **Index** | Library department | Top-level container grouping related data |
| **Sourcetype** | Book genre | Identifies the kind of data (auth log, web access log, CSV) |
| **Source** | Book author | Where the data came from (file path, script, input) |
| **Host** | Shelf location | Which machine or device generated the event |
| **_time** | Publication date | When the event occurred (Splunk internal field) |

---

## Technical Details

- **SIEM:** Splunk Enterprise 9.0.4 (Free license, pre-configured)
- **Runtime:** Docker container via GitHub Container Registry
- **Interface:** Web browser only (`http://localhost:8000`) — no CLI tools beyond Docker
- **Data persistence:** Named Docker volume `splunk-lab-data`
- **Time range:** All Time (lab data is historical)

---

## Next Steps

Unit 5 **Project** covers Part 3 of the Splunk Lab — the **SIEMsational CTF**, an open-ended challenge across PathCode Inc. malware investigation datasets (web proxy logs, failed logins, file upload hashes).
