---
challenge: RomCom
type: sherlock
date: 2025-09-15
category: DFIR
difficulty: Very Easy
tags:
  - mft-analysis
  - DFIR
start:2025-09-15 14:55
finish:
status: in-progress
---

# Sherlock Case File – Case-2025-09-15-RomCom

##### Overview

- **Timestamp:** 2025-09-15 14:58
- **Overview:** 
	- Susan works at the Research Lab in Forela International Hospital. A Microsoft Defender alert was received from her computer, and she also mentioned that while extracting a document from the received file, she received tons of errors, but the document opened just fine. According to the latest threat intel feeds, WinRAR is being exploited in the wild to gain initial access into networks, and WinRAR is one of the Software programs the staff uses. You are a threat intelligence analyst with some background in DFIR. You have been provided a lightweight triage image to kick off the investigation while the SOC team sweeps the environment to find other attack indicators.

##### Researching RomCom

- **Timestamp:** 2025-09-15 14:59
- **Action:**
	- OSINT Collection (web browser)
- **Commands:** 
	- Google with the knowers of all things.
- **Notes:**
	- Investigating RomCom WinRAR group.
	- Found https://www.cvedetails.com/cve/CVE-2025-8088/
		- CVE-2025-8088
	- Also https://www.cvedetails.com/cwe-details/35/Path-Traversal-...-...-.html
	- Appears to be a path traversal exploit.
	- Might help with potential malware analysis.
- **Next Steps:** 
	- Examine image file.

##### Using QEMU to open the storage file

- **Timestamp:** 2025-09-15 15:07
- **Action:**
	- QEMU usage to examine image file.
	- "Connect the .vhdx file to a network block device using qemu-nbd. This allows you to interact with the disk image as if it were a physical disk."
- **Commands:** 
	- `sudo qemu-nbd --connect=/dev/nbd0 2025-09-02T083211_pathology_department_incidentalert.vhdx`
	- Full mount command change:
 ```
 9192  sudo modprobe nbd max_part=16
...
 9199  sudo qemu-nbd -c /dev/nbd0 ./2025-09-02T083211_pathology_department_incidentalert.vhdx 
 9200  lsblk
 9201  sudo fdisk -l /dev/nbd0
 9202  sudo mount /dev/nbd0p1 /mnt
```
- Here's a more robust version of the above, from walkthrough:
	- `sudo mkdir -p /mnt/romcom`
	- `sudo mount -o ro /dev/nbd0p1 /mnt/romcom`
- **Notes:** 
	- Giving the Microsoft Disk Image eXtended file a home
	- Mounting that file system locally for forensics tools
- **Next Steps:** 
	- Getting timeline explorer for a more robust examination.

<1 hour break>

##### Downloading timeline explorer.

- **Timestamp:** 2025-09-15 16:20
- **Overview:** We have the mounted file, now to examine it for timestamps.

##### Getting proper tools

- **Timestamp:** 2025-09-15 16:28
- **Action:** We need to source proper forensics tools. Thankfully, I actually have been recommended by some pros to use Zimmerman's toolset, which looks robust
- **Commands:** Source from https://ericzimmerman.github.io/#!index.md
- **Notes:** It appears the mounted filesystem has MFT files, so we need MFTcmd and Timeline Explorer.
- **Next Steps:** Utilize the tools to parse the garble.

##### Wine failed - moving to Windows machine

- **Timestamp:** 2025-09-15 16:35
- **Overview:** It appears Zimmerman's tools are written for Windows (arghhhh), and wine is missing some fundamentals. Going to use my gaming laptop.


