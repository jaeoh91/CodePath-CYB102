# Project 1 – BEC Phishing Email Investigation

## Overview

This project analyzes four `.pcap` network capture files to identify a Business Email Compromise (BEC) campaign. The threat actor sent phishing/extortion emails to many recipients in an attempt to extort money. The analysis uses Wireshark  to inspect SMTP traffic and Internet Message Format (IMF) email headers across the captures.


# Investigation Flow

## Filters Used
- `smtp` filters for all SMTP traffic (Login, QUIT, data fragments, etc)
- `imf` filters for packets containing Internet Message Format data (the actual email headers + body)

- `smtp.req.command == "DATA"`: Filters for the packet where the sender requests to transmit the actual message content.
- `smtp.req.command == "MAIL"`: Filters for packets containing the sender address (MAIL FROM).
- `smtp.req.command == "RCPT"`: Filters for packets containing recipient addresses (RCPT TO).

- `File -> Export Objects -> IMF` to export emails in .eml format

## A.pcap
- Just one email, from user `galunt`, subject line `Testing testing 1 2 3 (Multiple attachments)`
- Two attachments, `info-16.png` + `packet-tnef-name-string.patch.gz`
-> Benign, just a testing email

## B.pcap
- Just one email, from user `gurpartap@patriots.in`, subject line `gurpartap@patriots.in`
- One attachments, `NEWS.txt`: contains changelog for some software product
-> Benign

## C.pcap
- 24 emails sent by `YourLifeXX@XXXX.com` to various personal yahoo email addresses
- Red Flags:
   - 24 emails sent in rapid succession, from T1.1 ~ T3.1 (within 2 seconds)
   - Emails all originating from similar sender (`YourLife\d{2}@\d{4}\.com`)
   - Emails all originating from src ip `10.6.1.104`
   - Very suspicious subject lines: 
      - `Subject: Read carefully! - dayrit`
      - `Subject: I can destroy everything! - 12345678`
      - `Subject: Your ife about to get ruined! - computercomputer`


## Summary

- **Malicious file:** `C.pcap`
- **Malicious actor's IP:** `10.6.1.104`
- **Attack type:** Automated sextortion/extortion phishing campaign (BEC)
- **Mechanism:** The attacker used an automated script to send 24+ phishing emails in under 3 seconds, cycling through randomly generated spoofed sender addresses (`YourLife*@*.com`) and resolving hundreds of throwaway domains via DNS, all routed through Yahoo's SMTP infrastructure to reach victims.
- **Red flags identified:**
  - Volume anomaly: 24 IMF email objects vs. 1 in all other captures
  - Rapid-fire SMTP connections (all within ~2.5 seconds)
  - Programmatic sender rotation (random numeric domains)
  - Threatening, coercive subject lines consistent with extortion phishing
  - Mass DNS lookups for hundreds of numeric `.com` domains