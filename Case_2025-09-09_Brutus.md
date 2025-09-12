---
challenge: Brutus
date: 2025-09-09
category: DFIR
difficulty: Very Easy
tags:
  - DFIR
  - MITRE
  - sysadmin
  - forensics
  - logs
start: 2025-09-09 15:42
finish: 2025-09-09 16:42
status: Finished
---
# 🕵️ Sherlock Case File – Case_2025-09-09_Brutus

**Opened:** 2025-09-09 15:42  
**Closed:**   2025-09-09 16:42

**Case Reference / ID:**  Brutus

---

## 🎯 Case Objectives
- What are we investigating? 
	- Brute force SSH logs for a Confluence server (Atlassian software)
	- User gained access and committed malicious acts.
- Scope & boundaries (systems, artifacts, timeframe).
	- We get a triple of files:
		- `auth.log`
		- `utmp.py`
		- `wtmp`
	- Basically we're reviewing the logs.
- Known IOCs / leads.
	- Logs immediately show last login as cyberjunkie.
	- SSH failures in excess from 65.2.161.68, until eventual success.

---

## 📂 Evidence Collected
- Source(s): (disk image, pcap, memory dump, logs, etc.)
	- wtmp logs (standard linux login format)
	- server auth logs.
- Acquisition method / chain of custody:  
	- N/A for acquisition.
	- Chain of custody through HTB (lol)
- Integrity check (hashes, verification): 
	- SHA256 hash of the files.
- Storage location:  
	- Zip given to us.

---

## 🔍 Analysis Steps (Chronological)
1. Tool / Method:  
   - Command(s):
	   - `nvim auth.log`
	   - `sudo utmpdump ./wtmp`
	   - `python3 utmp.py ./wtmp -o <file>`
   - Observations:  
	   - The files inspected are common across linux installations and include authentication and user logins.
	   - SSH attempts appear in auth.log.
	   - Use the tools to review the files. Pretty easy and is mainly just associating timestamps, IPs and usernames.
   - Results:  
	   - Able to obtain information and IOCs from the logs, specifically for SSH and local commands.

---

## 🧾 Findings
- Confirmed indicators:  
	- SSH session 37 is associated with IP address 65.2.161.68.
		- Was found using nvim (vi works too), to parse for `/ssh session` or `sshd:auth` (the latter more formal).
		- `sshd` is the linux service for ssh and will spill details of failed attempts. I knew this already but is quite apparent from log spam.
	- Multiple failed attempts before this success on user `root`
		- Noted IP address for failed attempts.
		- Might be useful in noisy environments to `cat x | grep y` or even `sed` to parse verbosity.
	- User commands found on computer, including user creation, getting scripts.
- Suspicious artifacts:  
	- User accessed external link with `wget`, possibly malicious script was downloaded.
	- User account logged in and given auth.log rites.
- Anomalies noted:
	- Password seems weak (broken after something like 20 attempts). Possible that password known beforehand from list?

---

## 🚧 Dead Ends / Pivots
- Lead pursued:
	- Tried to access `wtmp` files from command line.
		- Had to investigate programs online.
		- Didn't realize but python script provided, derp (basically a parsing script)
	- Searched by IP address.
		- Found multiple login attempts associated with IP address.
			- Followed timestamps and collated SSH logins with auth.
			- IP then associated with cyberjunkie account.
		- Found multiple SSH sessions.
			- Had to backtrack and associate these with accounts.

---

## 📊 Timeline Reconstruction
- Key events with timestamps:
	- We'll keep this short as I already did this step, so we'll show HTB question submissions.
	- 2024-03-06 06:32:45
		- User login time, associated with malicious account.
	- 2024-03-06 06:37:24
		- First ssh session in `auth.log`
- Correlation between evidence sources.
	- Direct equivocation with newly created account, IP address and ssh session.
		- Bruteforce Attempt (IP addr from wtmp/auth.log) -> successful login timestamp (in wtmp/auth.log) -> successful ssh auth (in wtmp/auth.log) -> user creation (wtmp shows session, auth.log shows creation) -> sudo commands (multiple in auth.log)
- Gaps / uncertainties in timeline.
	- None I can see, pretty transparent here.

---

## 📝 Reflection & Next Steps
- What worked well in this investigation?  
	- Review and HTB question categories apparently covered most of the data.
	- Remember to record notes as you go, I did this partially.
- What slowed me down?  
	- Doing this review after the fact without direct notes, but indirect info (history, nvim sessions, etc.)
	- Stream of consciousness for notes, refine for review and showing to others through this template.
- Tools or scripts to add to my playbook?  
	- `sudo utmpdump <file>`
	- `sudo utmpdump /var/log/wtmp`
		- Very useful for looking at these auth sessions, running locally I can see my daily logins! Very good.
		- Although this challenge gives you a python script to parse with, having a CLI utility is more useful.
	- `MITRE ATT&CK` is an excellent resource for IOCs and other info for DFIR.
	- Finding logs:
		- On linux systems, `/var/log` and `/var/log | grep "btmp"`
		- `auth.log` -> important example of log! If this file has been tampered with, something might be wrong...
- Outstanding questions.  

---

## 📎 Attachments
- N/A for this solve.