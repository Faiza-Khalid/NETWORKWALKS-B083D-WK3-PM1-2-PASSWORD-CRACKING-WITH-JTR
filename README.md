# Password Cracking with John the Ripper and Hash Calculator

A visual, educational walkthrough of password-recovery testing against password-protected PDF files using **John the Ripper (Jumbo)** and the **Network Walks Hash Calculator / Password Cracker** workflow.

> **Purpose:** cybersecurity learning and authorized password-recovery practice only. Use these techniques exclusively on files, hashes, and systems that you own or have explicit permission to test. Never use this repository to access someone else’s data.

## What this repository demonstrates

- Downloading the Windows build of John the Ripper Jumbo.
- Extracting and preparing John the Ripper on Windows.
- Converting a password-protected PDF into a crackable hash representation.
- Running a dictionary-based password audit with John the Ripper.
- Reviewing a recovered password and using it to open the protected PDF.
- Performing the same educational exercise with a web-based hash calculator/password-cracker workflow.
- Understanding why a limited wordlist can fail and why wordlist quality matters.

This is a **screenshot-based lab record**; it does not contain an application or executable source code.

## Tools and resources

- [John the Ripper](https://www.openwall.com/john/) — password-auditing and recovery tool. Download the current release appropriate for your operating system from the official Openwall website.
- [Network Walks Hash Calculator](https://networkwalks.com/hash-calculator/) — used in the screenshots to generate or extract hashes.
- [Network Walks Password Cracker](https://networkwalks.com/password-cracker/) — used in the screenshots for the dictionary-based demonstration.

The screenshots were captured on Windows. User interfaces, download versions, supported formats, and website behaviour may change over time; prefer the official documentation and current releases.

## Lab workflow

### 1. Download and prepare John the Ripper

1. Visit the official John the Ripper download page.
2. Download the Windows **Jumbo** archive that matches your system.
3. Extract the archive to a working directory.
4. Locate the John executable and confirm that the extracted folder contains the expected `run` directory and supporting files.

Screenshots: [01](01-Downloading-Of-JTR.png), [02](02-JTR-Setup-Files.png), [03](03-JTR-Setup-Files-Extraction.png), [04](04-Extraction-Of-John-Jumbo.png), [05](05-Setting-up-John-exe-File-In-JTR.png)

### 2. Create a hash input from the protected PDF

1. Work with a sample PDF created for the lab or a file you are authorized to recover.
2. Use a trusted, permitted PDF-hash extraction method to produce the appropriate hash text.
3. Save the extracted value in a text file, such as `hash.txt`, following the format required by the tool you are using.
4. Do not upload confidential documents or hashes to a third-party service without authorization and an appropriate data-handling review.

Screenshots: [06](06-Downloading-LockedFile-In-System.png), [07](07-Making-Hashtxt-File.png), [08](08-Making-Hashtxt-File2.png), [09](09-Making-Hashtxt-File3.png), [10](10-Loading-Lockedpdf-In-JTR.png)

### 3. Run the John the Ripper audit

Use the current John the Ripper documentation for the exact command and format for your file type and release. In general, the workflow is:

```text
john [options] hash.txt
john --show hash.txt
```

The first command performs the authorized password audit using the configured attack mode/wordlist. The second displays recovered results, when available. Options and supported formats vary, so validate them with the local `john --help` output and the official documentation rather than copying commands blindly.

The screenshots record a successful recovery and the subsequent use of the recovered password to open the sample PDF: [11](11-JTR-Decrypted-Hashtxt.png), [12](12-Collect-Cracked-Password.png), [13](13-Password-Cracked-By-JTR.png).

### 4. Compare with the Hash Calculator workflow

The second part of the lab uses the Network Walks web tools to:

1. Open the Hash Calculator.
2. Upload/select the authorized sample PDF or provide the permitted input required by the tool.
3. Extract the PDF hash.
4. Pass the hash to the Password Cracker workflow.
5. Run the supplied dictionary and review the result.

Screenshots: [14](14-MH2.png), [15](15-MH2-2.png), [16](16-MH3.png), [17](17-MH3-2.png), [18](18-Password-Cracking-By-HashCalculator.png).

### 5. Learn from a failed dictionary attempt

The lab also shows a failed attempt caused by a limited wordlist, followed by an updated wordlist and a successful retry. This illustrates an important security lesson: dictionary attacks depend heavily on the quality and relevance of the candidate list. A password that is not present in the list will not be recovered by that run, regardless of how long the tool executes.

Screenshots: [19](19-Failure-Due-To-LimitedWordlist.png), [20](20-Update-Wordlist.png), [21](21-Another-Attempt-After-Wordlist-Updation.png), [22](22-Password-Cracked-By-HashCalculator.png), [23](23-HC2.png), [24](24-HC2-2.png), [25](25-HC3.png), [26](26-HC3-2.png).

## Security and privacy notes

- Obtain written authorization before testing any password or hash.
- Use synthetic lab files whenever possible.
- Never commit passwords, private hashes, personal documents, or confidential screenshots to a public repository.
- Treat recovered passwords as sensitive secrets; do not reuse or share them.
- For defense, use long unique passphrases, password managers, MFA where available, and strong encryption.
- For password-protected PDFs, remember that password strength and the PDF encryption implementation both affect resistance to offline guessing.
- If a password is lost, use the owner’s approved recovery process before attempting technical recovery.

## Repository contents

| File group | Contents |
|---|---|
| `01`–`13` | John the Ripper download, setup, hash preparation, and recovery walkthrough |
| `14`–`18` | Hash Calculator workflow |
| `19`–`26` | Wordlist limitation, update, retry, and recovery results |
| `README.md` | Lab overview and safe-use documentation |
| `LINKEDIN_POST.md` | Ready-to-publish project summary |

## Learning outcomes

After reviewing this walkthrough, you should be able to explain the difference between a password-protected file and its crackable hash representation, describe how dictionary-based auditing works, identify the effect of wordlist coverage, and discuss responsible password-recovery practices.

## License and attribution

No software license is asserted for the original screenshots in this repository. John the Ripper and the linked Network Walks services are separate projects with their own terms, licenses, and acceptable-use policies. Review those terms before using them.

</details>

---

## 👤 Author & Credits

**Pentester:** **Faiza Khalid** — Cybersecurity Professional, **B083D-Networkwalks**

**Evidence Host:** `DESKTOP-D4AVS8U` / Windows user **Faiza Khalid** 

**Program:** Networkwalks Cybersecurity & Ethical Hacking Internship — **Week 3: Password Cracking By JTR And HashCalculator**

**Evidence Window:** **27 September 2026** —

---

## 📄 License

This report and all supporting screenshots/logs are provided for **educational and research purposes only**. You may reuse the **report structure** for your own authorized labs, but you **must not target systems without explicit written permission**. Redact sensitive tokens (e.g., full `google-site-verification`) if you fork publicly.

---

<p align="center">
  <em>— End of Report —</em><br>
  <sub>Networkwalks • Week 3 • PM1 / PM2 • Password Cracking By JTR And HashCalculator • 27 Sep 2026</sub>
</p>
