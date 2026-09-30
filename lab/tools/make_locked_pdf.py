#!/usr/bin/env python3
"""Create the sample password-protected PDF used in the Week 3 lab.

The PDF is a synthetic lab artefact (no real data). It is encrypted with the
Standard Security Handler, revision 4 / AES-128, which is the classic scheme
John the Ripper's `pdf` format (and the Networkwalks Hash Calculator)
understand how to attack.

  * user password  = monday1   (the password students must recover)
  * owner password = OwnerKey#NW-Lab-2026 (strong, only used to lock the file)
"""
import sys

import pikepdf

# A minimal one-page PDF written by hand (no third-party generator needed).
PAGE = b"""%PDF-1.7
1 0 obj
<< /Type /Catalog /Pages 2 0 R >>
endobj
2 0 obj
<< /Type /Pages /Kids [3 0 R] /Count 1 >>
endobj
3 0 obj
<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792]
   /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>
endobj
4 0 obj
<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>
endobj
5 0 obj
<< /Length 330 >>
stream
BT /F1 20 Tf 72 700 Td (Networkwalks Academy - Week 3 Password Cracking Lab) Tj ET
BT /F1 12 Tf 72 660 Td (Synthetic sample document created for the JTR / Hash) Tj ET
BT /F1 12 Tf 72 644 Td (Calculator exercise. This file contains no real data.) Tj ET
BT /F1 12 Tf 72 612 Td (If you can read this page you unlocked the PDF.) Tj ET
endstream
endobj
trailer << /Root 1 0 R /Size 6 >>
"""

def main(out_path: str) -> None:
    import tempfile, os
    with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as tmp:
        tmp.write(PAGE)
        tmp_path = tmp.name

    pdf = pikepdf.open(tmp_path)
    with pdf.open_metadata() as meta:
        meta["dc:title"] = "Networkwalks Week 3 Lab - Locked Sample"
        meta["dc:creator"] = ["B083D Lab"]

    pdf.save(
        out_path,
        encryption=pikepdf.Encryption(
            user="monday1",
            owner="OwnerKey#NW-Lab-2026",
            R=4,          # Standard Security Handler revision 4
            aes=True,     # AES-128 (V=4); key derivation is Algorithm 3.2
        ),
    )
    os.unlink(tmp_path)
    print(f"[+] wrote locked PDF -> {out_path}")

if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "locked.pdf")
