# Project 3: Off Limits — FTP Directory Traversal Attack

## Overview
Simulated a directory traversal attack against a locally hosted FTP server to access restricted files without authorization. Analyzed captured network traffic to identify files accessed during an attack.

## Skills Demonstrated
- Bash scripting (process management, variables, background execution)
- Directory traversal attack concepts
- Network packet analysis with Wireshark
- Node.js script execution from the command line

## What I Built
Extended `attack.sh`, a bash script that:
1. Spins up a vulnerable `hftp` Node.js server in the background
2. Waits for the server to initialize
3. Sends an HTTP GET request via `attack.js` to a target file path
4. Kills the server process on completion

## Attack in Action
Used the script to access restricted files outside the public `general/` directory:
- `timmy/reports_original.txt` — revealed real earnings hidden from the public report
- `cosmo/passwords.txt`
- `wanda/catnames.txt`

Discovered that `general/reports.txt` falsely claimed earnings were up 900%, while `timmy/reports_original.txt` revealed earnings were actually **down 1600%**.

## Packet Analysis
Loaded `activity.pcapng` in Wireshark and filtered HTTP GET requests to identify which restricted files were accessed during a recorded attack session.

## Key Takeaway
A misconfigured server with no access controls on directory paths exposes sensitive files to anyone who knows (or guesses) the path — no special exploit needed.
