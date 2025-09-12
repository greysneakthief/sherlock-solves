---
challenge: SalineBreeze-1
date: 2025-09-10
category: Threat Intelligence
difficulty: Very Easy
tags:
  - threatintel
  - APT
  - TTP
  - malware
  - MITRE
start: 2025-09-10 17:19
finish: 2025-09-10 21.12
status: Finished
---
# 🕵️ Sherlock Case File – Case_2025-09-10_SalineBreeze-1

**Opened:** 2025-09-10 17:19  
**Closed:**  2025-09-10 21:12

**Case Reference / ID:**  SalineBreeze-1

---

## 🎯 Case Objectives
- What are we investigating?  
	- Your manager has just informed you that, due to recent budget cuts, you'll need to take on additional responsibilities in threat analysis. As a junior threat intelligence analyst at a cybersecurity firm, you're now tasked with investigating a cyber espionage campaign linked to a group known as Salt Typhoon. Apparently, defending against sophisticated Nation-State cyber threats is now a "do more with less" kind of game. Your Task: Conduct comprehensive research on Salt Typhoon, focusing on their tactics, techniques, and procedures. Utilize the MITRE ATT&CK framework to map out their activities and provide actionable insights. Your findings could play a pivotal role in fortifying our defenses against this adversary. Dive deep into the data and show that even with a shoestring budget, you can outsmart the cyber baddies.
- Scope & boundaries (systems, artifacts, timeframe).
	- OSINT Collection bay-beeeeee.
		- Involves a number of Threat Intel websites.
		- No active malware review, thank goodness.
- Known IOCs / leads.
	- Start with MITRE and move from there!

---

## 📂 Evidence Collected
- Source(s): (disk image, pcap, memory dump, logs, etc.)  
	- Open-source repositories such as:
		- https://attack.mitre.org/
	- Accumulated in OSINT:
		- http://picussecurity.com/resource/blog/salt-typhoon-removing-chinese-telecom-equipment
		- https://www.trendmicro.com/en_us/research/23/h/earth-estries-targets-government-tech-for-cyberespionage.html
		- https://www.trendmicro.com/en_us/research/24/k/earth-estries.html
		- https://cybersecsentinel.com/earth-estries-uses-ghostspider-malware-to-infiltrate-high-value-targets/
		- https://securelist.com/ghostemperor-from-proxylogon-to-kernel-mode/104407/
- Acquisition method / chain of custody:  
	- N/A
- Integrity check (hashes, verification):  
	- N/A
- Storage location:  
	- `~/Simulations/Sherlocks/SalineBreeze-1`
		- ^(this file)

---

## 🔍 Analysis Steps (Chronological)
1. Tool / Method:  
   - Command(s):  
	   - Web browser -> https://attack.mitre.org/
	   - Search for "Salt Typhoon"
   - Observations:  
	   - https://attack.mitre.org/groups/G1045/
	   - https://attack.mitre.org/software/S1206/
		   - Custom software written in GO, specifically for Salt Typhoon
   - Result:  
	   - Associated country is China
	   - Tons of techniques listed on page, including Cisco CVEs, Linux system compromise techniques, ACL bypass, FTP/TFTP/SSH tunneling, hiding infrastructure, etc.
2. Tool / Method:  
   - Command(s):  
	   - Web browser -> http://picussecurity.com/resource/blog/salt-typhoon-removing-chinese-telecom-equipment
   - Observations:
	   - Brief overview of techniques used to establish footholds.
	   - Also noted, TP-Link vulnerabilities (corroborates with network infrastructure targets)
   - Result:  
	   - Multiple CVEs and MITRE TTPs listed. Numerous follow below.
3. Tool / Method:  
   - Command(s):  
	   - Web browser -> https://www.trendmicro.com/en_us/research/23/h/earth-estries-targets-government-tech-for-cyberespionage.html
	   - Second search, related -> https://www.trendmicro.com/en_us/research/24/k/earth-estries.html
   - Observations:
	   - Multiple techniques targeting windows infrastructure, especially through DLL sideloading.
	   - Also first mention of TrillClient, used for stealing browser information, operating as a `.cab` file. What is that?
   - Result:  
	   - The info dump you see below
4. Tool / Method:  
   - Command(s):  
	   - Web browser ->  https://cybersecsentinel.com/earth-estries-uses-ghostspider-malware-to-infiltrate-high-value-targets/
   - Observations:
	   - Done for assessment, desired to know .dev domain.
   - Result:  
	   - `telcom[.]grishamarkovgf8936[.]workers[.]dev`
5. Tool / Method:  
   - Command(s):  
	   - Web browser ->  https://securelist.com/ghostemperor-from-proxylogon-to-kernel-mode/104407/
   - Observations:
	   - Looking for information about GhostSpider.
	   - Shows exactly how the malware works.
   - Result:  
	   - An overview of the Demodex rootkit, how it operates, and a list of IOCTL codes used to facilitate/hide it.

---

## 🧾 Findings
- I started off with listing these in great detail, but simply provided the MITRE codes as time went on -- too numerous for quick review.
- Crowdoor/Zingdoor, TrillClient and HemiGate were notable in persistence.
- Specific techniques:
	- JumbledPath -> software specifically written for Salt Typhoon, ID S1206 on MITRE.
		- Sniffer, archive and obfuscation tool.
		- Specific targets:
			- Linux servers 
			- Cisco infrastructure
		- Special considerations:
			- T1070.002 is of specific interest:
				- Indicator Removal: Clear Linux or Mac System Logs
		- Sophisticated tool that can be used to monitor network traffic.
	- Multiple CVEs associated with footholds.
	- Exploiting Public-Facing Applications (MITRE T1190)
		-  CVE-2023-46805, CVE-2024-21887 (Ivanti Connect Secure VPN)
		- CVE-2023-48788 (Fortinet FortiClient EMS)
		- CVE-2022-3236 (Sophos Firewall)
		- CVE-2021-26855, CVE-2021-26857, CVE-2021-26858, CVE-2021-27065 (Microsoft Exchange – ProxyLogon)
	- Utilizes DRM Exploits via cab/bat (MITRE 1059.
		- Remotely executes a series of scripts with RCE.
		- Data staging for exfiltration is organized:
			- Compress with rar.exe into a single archive for maximum compression.
	- Persistence (MITRE T1112, T1543.003)
		- Crowdoor -> registry modification:
			- `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
	   - Zingdoor:
		- HTTP Backdoor written in go.
		  - Anti this: https://blogs.jpcert.or.jp/en/2022/03/anti_upx_unpack.html
		  - Exploits `MsSecEs.exe` (microsoft defender binary)
			- Waits for info from the CC server:
			- Can get sysinfo
			- Get service info
			- Disk management (yikes)
			- Arbitrary command execution (double yikes)
	- TrillClient
		- Operates as a `.cab` file.
		- Extracted through `expand.exe`
		- Two parts, installer and stealer.
		- Keeping it short here, but connects with ID created by installer and retrieves commands from github.
			- Hard-coded in malware as `_hxxps://raw[.]githubusercontent[.]com/trillgb/codebox/main/config.json_`
			- Commands:
				- Does nothing.
				- Starts collection of browser creds.
				- Schedules a task for browser cred steal.	
				- Schedules stealing after specified time.
		- Interestingly, compress with tar, encrypts stolen shit with simple XOR, and sends it over SMTP.
			- All of these alone would make it trivial to see but combo might be harder to detect?
	- HemiGate:
		- Another DLL sideload backdoor.
			- Encrypted file is `taskhask.doc`
			- Config is `taskhask.dat`
			- Detects if proxy is needed, established C&C over port 443.
			- RC4 encrypted config.
			- Comms with server performed using POST with pre-defined header.
		- Multistage execution:
			- First instance is to install start mechanism and initialize second instance. Stops when done.
				- Calls itself `Windrive` or `Windows Drive Security`
			- Second instance has multiple roles:
				- Keylogger pipe from third instance.
				- C&C Oversight for third instance
					- watchdog
					- backdoor command exec if pipe fails
					- if pipe success, passes commands to third instance
					- uninstaller if C&C dictates
			- Third instance
				- keylogger: `\\[.]\pipe\Key[500]`
					- To second instance
				- command module: `\\[.]\pipe\<username>\[<session-id>]`
	- Privesc (MITRE T1068)
		- Cobalt Strike and PsExec installed via external-facing services.
	- Valid Account Exploitation (MITRE T1078)
		- With above TrillClient, creds harvested and accounts, tokens gained.
	- Obfuscating Files (MITRE T1027, T1027.005)
	- Remote Services (MITRE T1021)
	- OS Credential Dumps (MITRE T1003.003)
	- Local System Data (MITRE T1005)
	- C2 Channel Exfil (MITRE T1041)
	- Internal Proxy (MITRE T1090.001)
		- Notable because pretty advanced obfuscation of network traffic as legitimate.
	- Bunch of other features I won't detail here, it's honestly massive but well documented already at the above links.
		- All in all, heavy DLL sideload use (MITRE T1574.002) by **Earth Estries** (active since 2020), associated with Salt Typhoon.
		- Direct linking to whois:
			- Organization: De Wang Mao Yi You Xian Gong Si (De Wang 貿易有限公司)
			- City: Qinyuanshi (清遠市)
			- Not the full story -> the link supplied has more info for a trace.
		- **FamousSparrow** also associated with Salt Typhoon by TTPs.
- Other notable tools:
	- *GhostSpider* via **GhostEmperor**
	- SNAPPYBEE (Deed RAT)
- Okay, imo it looks like Earth Estries is the APT, not Salt Typhoon?...
	- Now that's curious...Estries are a kind of Female Vampire in Judaic folklore.
	- According to Trend Micro, they compromised more than 20 organizations in various technical fields, all over SE Asia, Brazil, South Africa, and the US.
- DEMODEX rootkit infection chain:
	- Server compromise
	- PSEXEC.exe (classic)
	- onedrived.ps1
	- msmp4dec.dll
		- memory implant
			^(this is the lolbin I believe?)
	- DEMODEX rootkit in-memory
	- Connect to C&C
	- (DEMODEX uses flow flattening to obfuscate)
- DEMODEX and GHOSTSPIDER used in conjunction.
	- Origin with hacker **GhostEmperor**?
	- C&C Server for GhostSpider utilizes `index.php` with an initial GET request.
- Attribution chain has a cool diagram: ![EarthEstries-Fig15-2.png](https://github.com/greysneakthief/sherlock-solves/blob/main/EarthEstries-Fig15-2.png)
- C&C Domains:
	- cloudlibraries[.]global[.]ssl[.]fastly[.]net
	- pulseathermakf[.]com
	- palloaltonetworks[.]com
	- telcom[.]grishamarkovgf8936[.]workers[.]dev
		- Important for assessment.
- For our purposes, we reviewed the Demodex rootkit.
	- The powershell dropper utilizes an attacker provided AES key to decrypt the bulk of the code at runtime, after a service is established.
		- There are variants that use a system derived decryption key, interestingly.
	- Various steps happen to install it, including fake file format headers to obfuscate the data sent to C&C server.
		- This matches the goal of disguising the action of the service.
		- Reverse engineered from CobaltStrike?
	- Last stage has the payload injected into winlogon.exe.
		- Various ways this can be abused.
		- Vitally, the core of the malware is able to run a kernel mode driver - ultimate obfuscation of system artefacts (covering one's trail)
	- Once the in-memory implant is established, it contacts the C2 server and engages with the winlogon.exe.
	- Finally we get to what we're looking for: IOCTL dispatcher that facilitate the loading of the rootkit, and thus allowing it to obfuscate its function.
		- **0x220300**: Hides the malware’s service from a list within the services.exe process address space. The service’s name is passed as an argument to the IOCTL, in turn being sought in a system-maintained linked list. The corresponding entry is being unlinked, thus hiding the service from being easily detected.
---

## 🚧 Dead Ends / Pivots
---
- Lead pursued:  
	- Originally dove heavily into technical explanations.
- Why it was abandoned:  
	- While useful for personal enrichment, lengthened the task beyond what I had originally allotted for time.
- What it revealed indirectly:  
	- IOCTL codes for the Demodex malware actually provided some insight into earlier materials. Kaspersky writeup on GhostEmperor was *chef's kiss*.
---
- Lead pursued:  
	- Focus on Salt Typhoon designation drew search terms away from actors like Earth Estries and GhostEmperor.
- Why it was abandoned:  
	- Not completely abandoned, but searches for Earth Estries and GhostEmperor lead to more relevant details on the TTPs used by the TAs.
- What it revealed indirectly:  
	- Chain of connections between these actors.
	- The scale of complexity of DNS and the domain C&C infrastructure used to carry out these attacks.
		- Not unmanageable but would take a certain organizational spirit to collate these directly with some sort of charting.
		- Would be interesting to do an association map of the domains.
---

## 📊 Timeline Reconstruction
- Note; for brevity here, not going to go over individual cases as they are too numerous.
- Key events with timestamps:
	- Active since 2019
	- Kaspersky did blog writeup on GhostEmperor in September 2021
	- Picus Security released a blog post on Dec 20, 2024
	- US Department of Treasury notified of hack Jan 17th, 2025
	- MITRE Report first filed Feb 24, 2025
- Correlation between evidence sources. 
	- Earth Estries, GhostEmperor, GhostSpider, FamousSparrow -> these are all associated with Salt Typhoon.
	- Lots of reused domains, associated domains, specifically within the sinosphere.
- Gaps / uncertainties in timeline.
	- Significant gap between first activity (2019) of Salt Typhoon and official MITRE disclosure of it as a collective entity (2025).
	- Exact connections difficult to process without a much deeper dive.

---

## 📝 Reflection & Next Steps
- What worked well in this investigation?  
	- Real time note-taking here allowed pivoting and searching off of related concepts.
		- This is how Demodex as a rootkit was found before the query even came up from HTB.
	- For larger investigations, a separate obsidian folder might allow for mind mapping and hash searching for quicker association of involved entities, TTPs, files, timelines, etc.
- What slowed me down?
	- Getting too caught up on details for complicated subjects (kernel level malware is not my wheelhouse)
	- Organizing links.
		- Remember to utilize the folder structure we've been utilizing for each engagement! Stream of consciousness notes are effective if you have time for review, plus they allow concretization of concepts.
	- *1 day review* --> should have added these files to specific folders to allow embedded screenshots to be pulled with uploads.
- Tools or scripts to add to my playbook?
	- Good to know that:
		- MITRE
		- TrendMicro
		- Kaspersky
		Are all excellent resources for APT stuff.
	- Good reversing software is going to come in handy in the future as these challenges ramp up to the real.

---
