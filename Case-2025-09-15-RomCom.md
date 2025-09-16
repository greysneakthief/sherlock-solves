---
challenge: RomCom
type: sherlock
date: 2025-09-15
category: DFIR
difficulty: Very Easy
tags:
  - mft-analysis
  - DFIR
start: 2025-09-15 14:55
finish: 2025-09-15 20:04
status: complete
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

##### Establishing Windows Obsidian Git

- **Timestamp:** 2025-09-15 17:37
- **Overview:** Just moving a bunch of shit onto my Windows workstation so I have an environment for tools. If I was more clever I would run a windows VM but their service keys are always a pain in the ass, so running a git instance for sherlock-solves is the best solution.
- Also set up my obsidian environment.

##### Parsing the $MFT file to CSV and Reading

- **Timestamp:** 2025-09-15 17:38
- **Action:**
	- Mounted filesystem (easy on windows)
		- **Personal reminder to investigate linux based DFIR tools**
	- Parsed $MFT file
		- "The **Master File Table (MFT)** is the core database of the NTFS file system, storing a record for every file and directory on the volume."
		- "Each record holds metadata such as names, timestamps, permissions, and sometimes even the file’s data itself, making the MFT vital for both system operation and forensic analysis."
	- Filtered results for `.rar` files.
- **Commands:** 
```
.\MFTECmd.exe -f "D:\C\`$MFT" --csv <outputfile.csv>
.\TimelineExplorer.exe
```
- Various filtering command (screenshots)
- **Notes:** 
	- Found file `Pathology-Department-Research-Records.rar`
	- Found creation date `2025-09-02 08:13:50`
- **Next Steps:**
	- Reconstruct timeline for when file was extracted

##### Parsing $J file

- **Timestamp:** 2025-09-15 17:52
- **Action:** Finding the data stream timeline in USNJournal under $Extend\$J
	- "The USN Journal is like a changelog for the filesystem."
	- "Whenever a file or directory changes, NTFS writes a USN record to `$J`."
- **Commands:** 
```
.\MFTECmd.exe -f "D:\C\`$Extend\`$J" --csv <outputfile.csv
.\TimelineExplorer.exe
```
- **Notes:** 
	- Found timestamp for file open at `2025-09-02 08:14:04`
- **Next Steps:** 
	- Filter results to see what exactly was extracted

##### Filtering results from $MFT exported CSV from earlier

- **Timestamp:** 2025-09-15 18:05
- **Action:** We're filtering results from the MFT file to see what exact file was extracted to inspect if it was malicious.
- **Commands:** 
	- Filter by Parent Path in FileExplorer GUI
	- Search/Find `.docx`
		- No Result
	- Search/Find `.pdf`
		- Found result.
	- **Personal note:** Common file ending list might be useful to parse results.
- **Notes:** Found `Genotyping_Results_B57_Positive.pdf` in `.\Users\susan\Documents`
- **Next Steps:**
	- Maybe a check of the hash on virustotal?
	- If file not malicious, check for any auxiliary files loaded.

-- Dinner break
##### Searching for interesting artifacts

- **Timestamp:** 2025-09-15 19:36
- **Action:** Sorting the timestamps between 08:13 and 08:15 while looking for suspicious files.
- **Commands:** TimelineExplorer
- **Notes:** 
	- Found suspicious `.exe` file.
	- Sanity check for other `.exe` files -> this one fits the timeline.
	- `C:\Users\susan\AppData\Local\ApbxHelper.exe`
	- `.lnk` file created at the same time.
	- Cross-examined that with USNJournal file.
	- `C:\Users\susan\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\Display Settings.lnk`
		- This seems to link to startup programs (probably for persistence)
- **Next Steps:** 
	- Finalize report details, including MITRE ATT&CK designation.
	- Determine when malicious executable was opened.
		- Repeated above procedures, obtained `2025-09-02 08:15:05` -> `.lnk` created by `Genotyping_results_B57_Positive.lnk`

##### MITRE Designation

- **Timestamp:** 2025-09-15 19:49
- **Overview:**
	- Used search to find anything to do with "persistence".
	- Found `T1547`
		- Sub-designation for startup folder exploits at `T1547.001`
	- Probably a better fit is `T1547.009`
		- While link is to startup, it's actually a malicious `.lnk` that does the heavy lifting here.

### Review
#### Post-Analysis
- Malicious file was hidden in a `.rar` document.
- Leveraged LFI to change write directory for extraction of malicious payload.
- Malicious payload disguised by decoy document.
- Decoy links to malicious executable.
- User inadvertently accesses malicious file through link (shortcut), executing program.2025-09-15 20:04


#### Takeaways
- Update version of WinRAR to prevent this exploit.
- Remember that [Zimmerman's Tools](https://ericzimmerman.github.io/#!index.md) for are incredibly useful, but require an instance of windows to run.
- USNJournal file ($J) is useful to review as a forensic trail, unless actively tampered with, along with the $MFT (Master File Table) for NTFS.
- Interesting exploit utilizing a link to disguise access to the malicious file.





