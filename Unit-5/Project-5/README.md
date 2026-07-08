# SIEMsational CTF — Malware Investigation with Splunk

A Capture-the-Flag style SOC investigation using Splunk to trace an attacker's login attempts, credential compromise, and malicious file upload across a simulated corporate environment.

**Course:** CodePath CYB102 — Unit 5, Project 5
**Lab source:** [codepath/opencyber-splunk-lab](https://github.com/codepath/opencyber-splunk-lab) (Part 3)

---

## Overview

Unlike a guided lab, this CTF provided no step-by-step instructions — only a dataset and a set of investigative questions. The goal was to form hypotheses and validate them with Splunk SPL (Search Processing Language) queries, mirroring how a SOC analyst works a real incident: starting from a single indicator of compromise (a malware hash) and pivoting outward to reconstruct the full attack chain.

The CTF covered two datasets:

- **Netflix Data** — 10 questions (1 point each)
- **Investigating the Malware** (`index=pathcode`) — 5 questions (2 points each)

This writeup focuses on the malware investigation, which required correlating login attempts, file uploads, and hash data across multiple log sources to identify the attacker, the compromised account, and the malicious payload.

---



## Environment Setup

**Prerequisites:** Docker Desktop (Mac/Windows/Linux)

```bash
docker run --rm -it -p 8000:8000 -v splunk-lab-data:/opt/splunk/var ghcr.io/codepath/opencyber-splunk-lab:latest
```

Dashboards and indexed data persist across sessions via the named volume `splunk-lab-data`.

---



## Skills Demonstrated

- Pivoting an investigation from a single IOC (file hash) to a full attack timeline
- Writing SPL queries with field filters, `where`, and multi-field `table` output
- Correlating events across multiple hosts within the same index (`webserver02`, `failedlogins64`, `uploadedhashes`)
- Identifying compromised credentials by tracing failed vs. successful login attempts
- Distinguishing malicious activity from legitimate activity using shared indicators (timing, IP, file hash)

---



## Investigation: Tracing the Malware Upload



### Dataset

All malware investigation data lives under `index=pathcode`, split across several hosts:


| Host              | Description                           |
| ----------------- | ------------------------------------- |
| `webserver02`     | Web server login/upload access events |
| `failedlogins64`  | Failed login attempt records          |
| `uploadedhashes`  | Hashes of uploaded files              |
| `BluecoatProxy01` | Web proxy traffic logs                |




### Challenge 11 — Who uploaded the malware?

Starting from a known malicious MD5 hash, find the source IP.

```spl
index=pathcode "File Hash"="3AADBF7E527FC1A050E1C97FEA1CBA4D"
```

**Answer:** `192.168.1.10`

### Challenge 12 — What usernames did that IP try, and which one succeeded?

```spl
index=pathcode IP="192.168.1.10"
| table _time host Username Event
| sort _time
```

**Answer:**

- `Admin` — login attempt
- `Pi` — login attempt
- `ABurke` — login **and** successful file upload



### Challenge 13 — What User Agent did the attacker use during the successful upload?

```spl
index=pathcode Event="File Upload*" "Server Response"=200
| table _time host IP Username "User Agent"
```

**Answer:** `Firefox/89.0`

### Challenge 14 — Did any other user upload a file around the same time?

```spl
index=pathcode Event="File Upload*"
| table _time host IP Username "User Agent" "Server Response"
| sort _time
```

**Answer:** `Jmann` uploaded a file from `192.168.1.7` around the same time window.

### Challenge 15 — What were the uploaded files, and which one is malicious?

```spl
index=pathcode host=uploadedhashes
| table _time Username "File Hash" *
```

**Answer:**


| Uploader | File             | Verdict       |
| -------- | ---------------- | ------------- |
| Jmann    | `proposal.pdf`   | Benign        |
| ABurke   | `EvilScript.exe` | **Malicious** |


---



## Key Findings


| Metric                      | Value                                                      |
| --------------------------- | ---------------------------------------------------------- |
| Attacker IP                 | `192.168.1.10`                                             |
| Usernames attempted         | `Admin`, `Pi`, `ABurke`                                    |
| Compromised account         | `ABurke`                                                   |
| Malicious file              | `EvilScript.exe` (MD5: `3AADBF7E527FC1A050E1C97FEA1CBA4D`) |
| Attacker's User Agent       | `Firefox/89.0`                                             |
| Secondary uploader (benign) | `Jmann` from `192.168.1.7` — uploaded `proposal.pdf`       |


**Conclusion:** An attacker at `192.168.1.10` attempted to log in as several accounts before successfully authenticating as `ABurke`. Using that compromised session, they uploaded `EvilScript.exe` via `webserver02`. A second, unrelated, legitimate file upload (`proposal.pdf` by `Jmann` from a different IP) occurred in the same time window, requiring careful field-level correlation (IP, username, hash, and timestamp) to avoid misattributing the malicious upload.

---



## Splunk Terminology Reference


| Term         | Description                                                                                          |
| ------------ | ---------------------------------------------------------------------------------------------------- |
| **Index**    | Top-level container grouping related data (`pathcode`)                                               |
| **Host**     | Which machine/log source generated the event (`webserver02`, `uploadedhashes`, etc.)                 |
| **IOC**      | Indicator of Compromise — the starting thread pulled to unravel an investigation (here, a file hash) |
| **Pivoting** | Using one confirmed data point (IP, hash, username) to search for related events across other logs   |


---



## Technical Details

- **SIEM:** Splunk Enterprise 9.0.4 (Free license, pre-configured)
- **Runtime:** Docker container via GitHub Container Registry

