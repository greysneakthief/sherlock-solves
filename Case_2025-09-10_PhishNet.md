# 🕵️ Sherlock Case File – Case_2025-09-10_PhishNet

**Opened:** 2025-09-10 13:54  
**Closed:**   2025-09-10 16:58

**Case Reference / ID:**  PhishNet

---

## 🎯 Case Objectives
- What are we investigating?
	- An accounting team receives an urgent payment request from a known vendor. The email appears legitimate but contains a suspicious link and a .zip attachment hiding malware. Your task is to analyze the email headers, and uncover the attacker's scheme.
- Scope & boundaries (systems, artifacts, timeframe). 
	- Single `.zip` file from HTB
- Known IOCs / leads. 
	- From known sender, apparently includes unopened attachment.

---

## 📂 Evidence Collected
- Source(s): (disk image, pcap, memory dump, logs, etc.)  
	- Single `.zip` file titled `PhishNet.zip`
	- Assuming this is the e-mail zip, in real situation we would not unpack before doing due diligence, which I did anyways.
		- E-mail contains e-mail metadata, message and a zip b64 encoded string.
- Acquisition method / chain of custody:  
	- Taken direct from malicious e-mail.
- Integrity check (hashes, verification):  
	- Hashes listed below.
- Storage location:  
	- Secure folder on alpine podman instance. For more rigorous malware analysis, note to self to set up SELinux VM or equivalent.

---

## 🔍 Analysis Steps (Chronological)
1. Tool / Method:  
   - Command(s):  `file PhishNet.zip`, `sha256sum PhishNet.zip`
   - Observations:  PhishNet.zip: Zip archive data, at least v2.0 to extract, compression method=deflate, check VirusTotal
   - Result:  Initial analysis on VirusTotal with Hash -- nothing, expected files.
2. Tool / Method: 
   - Command(s): `unzip -le PhishNet.zip`, `file email.eml`, `nvim email.eml`
   - Observations:  
	   - Single file, `email.eml`, [[SMTP]] mail, ASCII text, with [[CRLF]] line terminators.
	   - Had to check CRLF terminators. SMTP is simple mail transfer protocol.
		   - Carriage Return Line Feed terminators.
		   - Could actually be used to inject into a header, parser may return unintended shit.
	- E-mail contains potentially malicious link, checked with virustotal and pulled a blank.
	- E-mail contains base64 encoded attachment.
		- Brief sanity check for determining if `base64` utility is safe to run on unknown encodings -> recommendations say to never (obviously) pipe output to other commands: `UEsDBBQAAAAIABh/WloXPY4qcxITALvMGQAYAAAAaW52b2ljZV9kb2N1bWVudC5wZGYuYmF0zL3ZzuzIsR18LQN+h62DPujWX0e7`
	- Originating IP obtained: `[45.67.89.10]` from Outlook 16.0
   - Result: 
	   - Obtained a base64 encoded string from the e-mail. Content headers show that it's a zip file encoded thus for SMTP (--boundary123-- --> is this important?). 
	   - Also obtained IP addresses.
		   - 203.0.113.25
		   - 198.51.100.45
		   - 198.51.100.75
		   - 45.67.89.10 (Approved sender)
		   - The above IPs are internal 'example' IPs, i.e., because this is a simulation, these are likely used.
3. Tool / Method:  
   - Command(s): `base64 -d suspiciousfile.b64 > suspiciousfile.zip`, `file suspiciousfile.zip`
   - Observations:
	   - Suspicious zip unlock would be dangerous, so spun up alpine linux podman to deal with files.
		   - Turns out this is probably not secure, after research - use a VM for kernel isolation.
   - Result: 
	   - Decoded malicious zip base64 encoded for e-mail transfer.
	   - First, we're going to look at the e-mails, and return to zip.
4. Tool / Method:  
   - Command(s): `nvim email.eml`
   - Observations: 
	   - We're looking at various cues from the e-mail:
		   - Reply-to is `support@business-finance.com`
		   - Not the original sender.
		   - `<href>` link sends to `secure.business-finance.com`
		   - There is a download link there.
		   - `SPF=pass` - the origin is permitted to send the mail.
		   - `DKIM` and `DMARC` also pass.
   - Result: 
	   - Nothing suspicious in the origin, except how clean it was for originating from an existing client.
5. Tool / Method:  
   - Command(s): `base64 -d suspiciousfile.b64 > suspiciousfile.zip`,`sha256sum suspiciousfile.zip`
   - Observations: 
	   - **NOTE: DO THIS IN SANDBOX**
	   - Checked `suspiciousfile.zip` sha256 hash on virustotal.
	   - Looks clean, unzipping.
	   - Obtained `invoice_document.pdf.bat`
   - Result: 
	   - There was a windows .bat file in the attachment.
	   - Probably malicious.
---

## 🧾 Findings
- Confirmed indicators:
	- Suspicious `.bat` file recovered from base64 encoded attachment.
- Suspicious artifacts:  
	- `invoice_document.pdf.bat`
	- `<p><a href="https://secure.business-finance.com/invoice/details/view/INV2025-0987/payment">Download Invoice</a></p>`
- Anomalies noted:
	- All security measures for the e-mail origin appear legitimate after checking SPF, DKIM and DMARC.
		- Why did a legitimate client address send an e-mail with a suspicious attachment?

---

## 🚧 Dead Ends / Pivots
- Lead pursued:  
	-  Originally looked into suspicious origins for domains, but turned out to be legitimate external sender.
- Why it was abandoned:  
	-  Domains legitimate and not obfuscated by text. Could possibly be from a client, not enough info to determine that from assessment. Initial statement said "from known vendor" so did not investigate further
- What it revealed indirectly:  
	-  Possible compromise of mail-server at business-finance. Also revealed a domain hosted in Bulgaria. Also, secure.business-finance sub-domain is suspicious.

---

## 📊 Timeline Reconstruction
- Key events:
	- E-mail sent from IP `45.67.89.10` originating at `business-finance`.
	- `mail.business-finance.com` approves internal request from `finance@business-finance.com` with `spf`,`dkim` and `dmarc`
		- `Message-ID: <20250226101500.ABC123@business-finance.com>`
	- There's a download link to unknown invoice:
		- ` <p><a href="https://secure.business-finance.com/invoice/details/view/INV2025-0987/payment">Download Invoice</a></p>`
			- Note, did not follow link, checked domain on virus-total, no hits.
			- Would investigate in sandbox with reverse proxy if time permitted.
	- Base64 included attachment (typical for SMTP)
	- E-mail says follow for urgent payment, encouraging either link or attachment to be unlocked.
	- **Sandbox for following steps**
	- Attachment extracted, and reveals a `.bat` file with unknown content. Checked on virustotal, but `.bat` file is empty anyways (probably because this is a test.)
- Correlation between evidence sources:
	- Typical for phishing, attachment is a windows `.bat` file, which may execute if extracted on windows.
- Gaps / uncertainties in timeline:
	- Uncertain if origin/mailserver was compromised.
	- Uncertain whether domains are real (some are legitimated with `nslookup`)

---

## 📝 Reflection & Next Steps
- What worked well in this investigation?
	- Pivoting after certain level of detail was attained about origin.
	- Ensuring understanding of each section of a less known format (I have little experience with SMTP)
- What slowed me down?
	- Lack of ordered approach to digesting e-mail
		- In future, line by line approach might be good (see outstanding questions with script automation)
- Tools or scripts to add to my playbook?
	- Made script for podman instance of alpine, with necessary inspection tools.
	- Realized that podman instances as such should be ran on separate vm for kernel isolation (from research).
- Outstanding questions.
	- How to check further if mail service on domain was compromised?
	- How to check/execute `.bat` files in safe environment, esp on linux machines?
	- What other tools would be good for digesting e-mails? Perhaps write a script to automate checking of `SPF/DKIM/DMARC` sections of e-mail?

---

## 📎 Attachments
- Hashes:
	- `7d5621c46502fe5badf62137bb9340898e712fd3915d220022f9db046defd4d5 PhishNet.zip`
	- `7d5621c46502fe5badf62137bb9340898e712fd3915d220022f9db046defd4d5 suspiciousfile.zip`
	- 
- Screenshots / logs: 
	- e-mail follows:
```
Return-Path: <finance@business-finance.com>
Reply-To: <support@business-finance.com>
X-Mailer: Microsoft Outlook 16.0
X-Originating-IP: [45.67.89.10]
X-Priority: 1 (Highest)
X-MSMail-Priority: High
Received-SPF: Pass (protection.outlook.com: domain of business-finance.com designates 45.67.89.10 as permitted sender)
ARC-Seal: i=1; a=rsa-sha256; d=business-finance.com; s=arc-2025; t=1677416100; cv=pass;
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=business-finance.com; s=arc-2025;
X-AntiSpam: Passed
X-Organization: Business Finance Ltd.
X-Envelope-From: finance@business-finance.com
List-Unsubscribe: <mailto:unsubscribe@business-finance.com>
X-Sender-IP: 45.67.89.10
Received: from mail.business-finance.com ([203.0.113.25])
	by mail.target.com (Postfix) with ESMTP id ABC123;
	Mon, 26 Feb 2025 10:15:00 +0000 (UTC)
Received: from relay.business-finance.com ([198.51.100.45])
	by mail.business-finance.com with ESMTP id DEF456;
	Mon, 26 Feb 2025 10:10:00 +0000 (UTC)
Received: from finance@business-finance.com ([198.51.100.75])
	by relay.business-finance.com with ESMTP id GHI789;
	Mon, 26 Feb 2025 10:05:00 +0000 (UTC)
Authentication-Results: spf=pass (domain business-finance.com designates 45.67.89.10 as permitted sender)
	 smtp.mailfrom=business-finance.com;
	 dkim=pass header.d=business-finance.com;
	 dmarc=pass action=none header.from=business-finance.com;
Message-ID: <20250226101500.ABC123@business-finance.com>
Date: Mon, 26 Feb 2025 10:15:00 +0000 (UTC)
From: "Finance Dept" <finance@business-finance.com>
To: "Accounting Dept" <accounts@globalaccounting.com>
Subject: Urgent: Invoice Payment Required - Overdue Notice
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="boundary123"

--boundary123
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<html>
<head>
  <title>Invoice Overdue</title>
</head>
<body>
  <p>Dear Accounting Team,</p>
<p>This is a final notice regarding the outstanding invoice #INV-2025-0012. Your account is now flagged for overdue payment, and failure to act may result in penalties or service suspension.</p>
<p>Details of the invoice:</p>
<ul>
  <li><b>Invoice Number:</b> INV-2025-0012</li>
  <li><b>Amount Due:</b> $4,750.00</li>
  <li><b>Due Date:</b> February 28, 2025</li>
</ul>
  <p>Our records indicate that invoice #INV-2025-0012 is overdue for payment. Please process the payment immediately to avoid late fees.</p>
  <p>For your convenience, you can download the full invoice and payment instructions from the link below:</p>
  <p><a href="https://secure.business-finance.com/invoice/details/view/INV2025-0987/payment">Download Invoice</a></p>
  <p>Alternatively, the invoice is also attached as a .zip file.</p>
  <p>If you have already made the payment, kindly ignore this notice.</p>
  <p>Best regards,<br>Finance Department<br>Business Finance Ltd.</p>
</body><p>For assistance, please contact our support team at <a href='mailto:support@business-finance.com'>support@business-finance.com</a> or call our helpline at +1-800-555-0199.</p>
<p>Thank you for your prompt attention to this matter.</p>

</html>

--boundary123
Content-Type: application/zip; name="Invoice_2025_Payment.zip"
Content-Disposition: attachment; filename="Invoice_2025_Payment.zip"
Content-Transfer-Encoding: base64

UEsDBBQAAAAIABh/WloXPY4qcxITALvMGQAYAAAAaW52b2ljZV9kb2N1bWVudC5wZGYuYmF0zL3ZzuzIsR18LQN+h62DPujWX0e7

--boundary123--
```