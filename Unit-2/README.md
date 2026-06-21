# Unit 2: Endpoint Monitoring

## VM Setup
- Custom VM setup
- Using M5 Macbook (ARM chip)
- UTM to emulate x64 architecture, ubuntu-20.04.6-live-server-amd64 
- VM Config:
   - 8GB RAM
   - 4 cores
   - 128GB SSD

## Lab 2: Oops!...I Audit Again
In this lab, I learned about Host Intrusion Detection Systems (HIDS) and the Linux Audit daemon (`auditd`). I set up custom rules to monitor specific files for modifications and wrote bash scripts to search and filter the generated logs.

**Skills Acquired:**
- Installing and configuring `auditd` on an Ubuntu VM.
- Writing `audit.rules` to monitor file modifications using appropriate permissions and keys.
- Searching and filtering `/var/log/audit/audit.log` effectively using the `ausearch` command.

## Project 2: Let's wget This Bread
In this project, I applied the skills learned in the lab to a simulated scenario. I monitored a protected directory with multiple files and attempted to identify unauthorized access. I ran various attack scripts that modified unknown files and used the audit daemon to track down the exact files altered by each script.

**Skills Acquired:**
- Configuring comprehensive `audit.rules` for watching directories and protected files.
- Simulating endpoint attacks via executable scripts.
- Using `ausearch` and analyzing audit logs to map specific scripts back to the files they maliciously altered. 