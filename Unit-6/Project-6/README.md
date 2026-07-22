# Incident Response Follow-Up — Malware Case Review (Catalyst)

Second-analyst review of a closed malware incident: enrich IOCs with external threat intel, challenge the original severity and artifact ratings, and produce a post-incident gap analysis with a concrete detection recommendation.

**Course:** CodePath CYB102 — Unit 6, Project 6  
**Platform:** [Catalyst](https://github.com/SecurityBrewery/catalyst) (incident case management)  
**Source IR:** `[ir_report_malware.md](./ir_report_malware.md)`

---

## Overview

This project places you in the role of a second analyst reviewing Alice Johnson’s handling of `IR-2023-002`. An employee (Bob Anderson / `PC-002`) clicked a social media link, downloaded `download123.doc` from `bad-weather-app.net`, and executed a Remote Access Trojan. Alice isolated the host, removed the malware, and restored the system within about 90 minutes.

The project builds on an existing initial triage report and tasks us with **documenting the case in Catalyst**, **validating and enrichinig the reported IOCs** with VirusTotal / AbuseIPDB (and related intel), and **writing a critical post-incident analysis**: what the IR left out, which control failed, and what specific change would reduce the chance of a repeat.

---



## Skills Demonstrated

- Documenting a malware incident in a case-management platform (Catalyst): title, severity, TLP, description, artifacts, analyst notes
- IOC enrichment across hash, IP, and domain/URL observables
- Cross-checking first-responder claims against VirusTotal, AlienVault OTX, and sandbox/triage reports
- Distinguishing **confirmed malicious** artifacts from **mis-labeled** or **context-only** indicators
- Applying severity and Traffic Light Protocol (TLP) judgments with written justification
- Gap analysis of an incomplete IR record (scope, methodology, and missing host checks)
- Naming a specific detection/prevention control failure (not vague “poor security posture”)
- Writing an actionable recommendation (DNS/web filtering + Office macro policy)

---



## Incident Summary


| Field                           | Value                              |
| ------------------------------- | ---------------------------------- |
| Incident ID                     | `IR-2023-002`                      |
| Type                            | Malware (RAT)                      |
| Date                            | 2023-05-07 ~16:00–17:30 UTC        |
| Affected user                   | Bob Anderson                       |
| Host                            | `PC-002`                           |
| Assigned severity (this review) | **Medium** (Alice had marked High) |
| TLP                             | **AMBER**                          |
| Classification                  | **True Positive**                  |


**Attack path:** Social media link → `bad-weather-app.net` → `download123.doc` → RAT execution → host isolation and restoration.

---



## IOC Investigation


| Artifact                                       | Type       | Verdict    | Key finding                                                                                                                                   |
| ---------------------------------------------- | ---------- | ---------- | --------------------------------------------------------------------------------------------------------------------------------------------- |
| `3AADBF7E527FC1A050E1C97FEA1CBA4D`             | MD5 hash   | Malicious  | Maps to **PoetRAT** (Python RAT) via Word macro dropper ,malware family was not named in original IR                                          |
| `93.184.216.34`                                | IP         | Safe       | Tied to IANA **example.com** infrastructure; VT ~1/91 malicious — contradicts Alice’s High/VirusTotal “malicious” rating                      |
| `hxxp://bad-weather-app[.]net/download123.doc` | Domain/URL | Malicious* | Limited external intel; marked malicious from incident narrative. Alice incorrectly cited AbuseIPDB (IP reputation tool) as the domain source |


Verdict is case-based (download delivered the RAT), not strong public-intel corroboration.

**Differentiator for the submission:** the IP finding adds evidence that **differs from** the original IR and is the strongest example of second-analyst validation catching a false malicious label.

---



## Post-Incident Analysis (Highlights)



### Gap analysis

Alice’s timeline never states whether other hosts were checked for the same hash, domain, or related activity after `PC-002` was isolated. Without that, “contained by 17:30” only covers one workstation; the blast radius of the incident and severity confidence remain underspecified.

### Detection gap

DNS/web filtering did not block `bad-weather-app.net` before the download, and endpoint controls did not stop a macro-enabled Office file from the Internet from executing. That allowed the full click → download → PoetRAT path on `PC-002`.

### Concrete recommendation

Deploy DNS-layer filtering (or a secure web gateway) that blocks newly registered / known-malicious domains by default, and enforce an endpoint policy that blocks macro execution in Office documents from the Internet Zone.

---



## Tools & Environment

- **Catalyst** — incident case creation, artifacts, notes, case closure
- **VirusTotal** — file hash and IP reputation / community context
- **AbuseIPDB** — IP abuse reporting (browser check for the IP artifact)
- **AlienVault OTX / Hatching Triage** — supplemental family and sandbox context (PoetRAT)
- **Docker / local lab VM** — Catalyst stack served at `https://catalyst.localhost`

---



## Files in This Folder


| File                   | Purpose                                    |
| ---------------------- | ------------------------------------------ |
| `ir_report_malware.md` | Original IR from the first analyst (Alice) |
| `README.md`            | This portfolio summary                     |


