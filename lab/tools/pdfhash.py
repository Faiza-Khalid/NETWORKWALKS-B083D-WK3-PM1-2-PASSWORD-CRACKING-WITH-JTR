#!/usr/bin/env python3
"""pdfhash.py - Hash Calculator + Password Cracker (dictionary attack) for PDFs.

This is a faithful local re-implementation of the workflow used by the
Networkwalks "Hash Calculator" and "Password Cracker" web tools:

  extract  - parse a password-protected PDF **without knowing the password**
             and emit its crackable hash in John the Ripper's classic
             `$pdf$V*R*bits*P*encMeta*idLen*id*Ulen*U*Olen*O` format.
             (The web Hash Calculator does exactly this, in the browser.)
  crack    - hash every word in a wordlist and match it against the PDF
             password hash, "the same idea John the Ripper uses".
  verify   - confirm a recovered password actually opens the PDF.

Supported: Standard Security Handler revisions 2/3/4 (RC4 / AES-128) and
revision 5/6 (AES-256).  Key derivation follows PDF 1.7 Algorithms 3.2,
3.3, 3.2a and 3.2b - the same code paths John the Ripper's `pdf` format
implements.

Usage:
  pdfhash.py extract locked.pdf > hash.txt
  pdfhash.py crack hash.txt --wordlist wordlist.txt
  pdfhash.py verify locked.pdf 'monday1'

Requires: pycryptodome (Crypto.Cipher.ARC4 / AES) - the MD5/SHA parts use
Python's hashlib.  pikepdf is only needed for `verify`.
"""
from __future__ import annotations

import argparse
import hashlib
import re
import sys
import time

from Crypto.Cipher import AES, ARC4

# The 32-byte PDF padding string applied to passwords shorter than 32 bytes
# (PDF 1.7 spec, "password padding string").
PDF_PADDING = bytes(
    [0x28, 0xBF, 0x4E, 0x5E, 0x4E, 0x75, 0x8A, 0x41, 0x64, 0x00, 0x4E, 0x56,
     0xFF, 0xFA, 0x01, 0x08, 0x2E, 0x2E, 0x00, 0xB6, 0xD0, 0x68, 0x3E, 0x80,
     0x2F, 0x0C, 0xA9, 0xFE, 0x64, 0x53, 0x69, 0x7A]
)


# --------------------------------------------------------------------------
# Raw PDF parsing (no password needed - the /Encrypt dictionary and /ID are
# stored in plain text inside the file)
# --------------------------------------------------------------------------
def _find_string(data: bytes, key: bytes):
    """Return the value of /O, /U (etc.) as bytes, handling both
    hex strings <...> and literal strings (...) with octal escapes."""
    m = re.search(re.escape(key) + rb"\s*(<([0-9A-Fa-f\s]*)>|\()", data)
    if not m:
        return None
    if m.group(2) is not None:  # hex string
        return bytes.fromhex(re.sub(rb"\s", b"", m.group(2)).decode())
    # literal string: scan to the matching close paren
    start = m.end()          # just past '('
    depth, out, i = 1, bytearray(), start
    while i < len(data) and depth:
        c = data[i]
        if c == 0x5C:                      # backslash escape
            nxt = data[i + 1:i + 2]
            if nxt.isdigit():
                oct_digits = data[i + 1:i + 4]
                out.append(int(oct_digits, 8) & 0xFF)
                i += 1 + len(oct_digits)
                continue
            mapping = {0x6E: 10, 0x72: 13, 0x74: 9, 0x62: 8, 0x66: 12}
            out.append(mapping.get(nxt[0], nxt[0]))
            i += 2
            continue
        if c == 0x28:
            depth += 1
        elif c == 0x29:
            depth -= 1
            if depth == 0:
                return bytes(out)
        out.append(c)
        i += 1
    return None


def _find_int(data: bytes, key: bytes, default=None):
    m = re.search(re.escape(key) + rb"\s+(-?\d+)", data)
    return int(m.group(1)) if m else default


class PdfCryptInfo:
    def __init__(self, V, R, bits, P, enc_meta, id_, U, O, UE=None, OE=None):
        self.V, self.R, self.bits = V, R, bits
        self.P, self.enc_meta, self.id = P, enc_meta, id_
        self.U, self.O, self.UE, self.OE = U, O, UE, OE

    # ---- classic $pdf$ line used by John the Ripper ---------------------
    def to_pdf_hash(self) -> str:
        if self.R >= 5:
            # hashcat-style long form keeps U/O (48 bytes) and adds UE/OE
            parts = ["$pdf$5", str(self.R), str(self.bits), str(self.P),
                     "1" if self.enc_meta else "0",
                     str(len(self.id)), self.id.hex(),
                     str(len(self.U)), self.U.hex(),
                     str(len(self.O)), self.O.hex(),
                     str(len(self.UE or b"")), (self.UE or b"").hex(),
                     str(len(self.OE or b"")), (self.OE or b"").hex()]
            return "*".join(parts)
        return "$pdf$" + "*".join([
            str(self.V), str(self.R), str(self.bits), str(self.P),
            "1" if self.enc_meta else "0",
            str(len(self.id)), self.id.hex(),
            str(len(self.U)), self.U.hex(),
            str(len(self.O)), self.O.hex(),
        ])

    @staticmethod
    def from_pdf_hash(h: str) -> "PdfCryptInfo":
        if not h.startswith("$pdf$"):
            raise ValueError("not a $pdf$ hash")
        body = h[len("$pdf$"):]
        f = body.split("*")
        if f[0] == "5":      # long (AES-256) form produced above
            V = 5
            R, bits, P, enc = int(f[1]), int(f[2]), int(f[3]), f[4] == "1"
            idlen, id_ = int(f[5]), bytes.fromhex(f[6])
            ulen, U = int(f[7]), bytes.fromhex(f[8])
            olen, O = int(f[9]), bytes.fromhex(f[10])
            uelen, UE = int(f[11]), bytes.fromhex(f[12]) if f[12] else b""
            oelen, OE = int(f[13]), bytes.fromhex(f[14]) if f[14] else b""
            return PdfCryptInfo(V, R, bits, P, enc, id_, U, O, UE, OE)
        V, R, bits, P = int(f[0]), int(f[1]), int(f[2]), int(f[3])
        enc = f[4] == "1"
        idlen, id_ = int(f[5]), bytes.fromhex(f[6])
        ulen, U = int(f[7]), bytes.fromhex(f[8])
        olen, O = int(f[9]), bytes.fromhex(f[10])
        return PdfCryptInfo(V, R, bits, P, enc, id_, U, O)


def extract_info(pdf_path: str) -> PdfCryptInfo:
    """Parse /Encrypt and /ID out of a locked PDF (no password required)."""
    data = open(pdf_path, "rb").read()

    # locate the /Encrypt dictionary object (it may be inline or an indirect ref)
    enc_ref = re.search(rb"/Encrypt\s+(\d+)\s+(\d+)\s+R", data)
    if enc_ref:
        obj_num = enc_ref.group(1)
        m = re.search(re.escape(obj_num) + rb"\s+\d+\s+obj(.{0,4000}?)endobj",
                      data, re.S)
        enc_data = m.group(1) if m else data
    else:
        enc_off = data.find(b"/Encrypt <<")
        enc_data = data[enc_off + 8:] if enc_off >= 0 else data

    V = _find_int(enc_data, b"/V", 1)
    R = _find_int(enc_data, b"/R", 2)
    # The top-level /Length (in bits) is what we want; for V=4 the key length
    # may instead live inside the /CF << /StdCF << ... >> >> sub-dictionary,
    # given in bytes - so drop nested /CF dicts before looking.
    outer = re.sub(rb"/CF\s*<<.*?>>", b"", enc_data, flags=re.S)
    bits = _find_int(outer, b"/Length")
    if bits is None:
        cf = re.search(rb"/StdCF\s*<<(.*?)>>", enc_data, re.S)
        cf_len = _find_int(cf.group(1), b"/Length", 5) if cf else 5
        bits = cf_len * 8
    P = _find_int(enc_data, b"/P", -4)
    enc_meta = True
    if re.search(rb"/EncryptMetadata\s+false", enc_data, re.I):
        enc_meta = False
    U = _find_string(enc_data, b"/U")
    O = _find_string(enc_data, b"/O")
    UE = _find_string(enc_data, b"/UE")
    OE = _find_string(enc_data, b"/OE")
    if U is None or O is None:
        raise ValueError("could not find /U and /O in the Encrypt dictionary")

    # /ID lives in the trailer
    idm = re.search(rb"/ID\s*\[?\s*<([0-9A-Fa-f\s]*)>", data)
    id_ = bytes.fromhex(re.sub(rb"\s", b"", idm.group(1)).decode()) if idm else b""
    return PdfCryptInfo(V, R, bits, P, enc_meta, id_, U, O, UE, OE)


# --------------------------------------------------------------------------
# Key derivation + validation (PDF 1.7 Algorithms 3.2, 3.3, 3.2a, 3.2b)
# --------------------------------------------------------------------------
def pad_password(pw: bytes) -> bytes:
    pw = pw[:32]
    return pw + PDF_PADDING[:32 - len(pw)]


def compute_key_r2_r4(info: PdfCryptInfo, pw: bytes) -> bytes:
    """Algorithm 3.2 - encryption key from a user password (R2-R4)."""
    md5 = hashlib.md5()
    md5.update(pad_password(pw))
    md5.update(info.O)
    md5.update((info.P & 0xFFFFFFFF).to_bytes(4, "little"))
    md5.update(info.id)
    if info.R >= 4 and not info.enc_meta:
        md5.update(b"\xff\xff\xff\xff")
    digest = md5.digest()
    n = info.bits // 8
    if info.R >= 3:
        for _ in range(50):
            digest = hashlib.md5(digest[:n]).digest()
    return digest[:n]


def compute_U_r2_r4(info: PdfCryptInfo, key: bytes) -> bytes:
    """Algorithm 3.4 (R2) / 3.5 (R3/R4) - the /U value a correct password
    must reproduce."""
    if info.R == 2:
        return ARC4.new(key).encrypt(PDF_PADDING)
    # R3/R4: seed is MD5(padding + fileID), RC4 with the key, then 19 more
    # passes with the key XOR round number.
    digest = hashlib.md5(PDF_PADDING + info.id).digest()
    x = ARC4.new(key).encrypt(digest)
    for i in range(1, 20):
        x = ARC4.new(bytes(b ^ i for b in key)).encrypt(x)
    return x[:16]                     # only first 16 bytes are compared


def hash96_r6(pw: bytes, salt: bytes, udata: bytes | None) -> bytes:
    """Algorithm 3.2b - hardened iterated hash for R6 (AES-256).

    Faithful port of John the Ripper's pdf_compute_hardened_hash_r6():
      * at least 64 rounds (extended while i < last_byte + 32),
      * each round encrypts (password + block) x64 with AES-128-CBC
        (key = block[0:16], iv = block[16:32]),
      * the next block is SHA-256/384/512 of the ciphertext, chosen by
        (sum of the first 16 ciphertext bytes) mod 3.
    """
    block = hashlib.sha256(pw + salt + (udata or b"")).digest()
    data = b""
    i = 0
    while i < 64 or i < data[-1] + 32:
        data = (pw + block) * 64
        cipher = AES.new(block[:16], AES.MODE_CBC, block[16:32])
        data = cipher.encrypt(data)
        block_size = 32 + (sum(data[:16]) % 3) * 16
        if block_size == 32:
            block = hashlib.sha256(data).digest()
        elif block_size == 48:
            block = hashlib.sha384(data).digest()
        else:
            block = hashlib.sha512(data).digest()
        i += 1
    return block[:32]


def check_password(info: PdfCryptInfo, pw: bytes) -> bool:
    """Return True when `pw` is the correct **user** password."""
    if info.R <= 4:
        key = compute_key_r2_r4(info, pw)
        if info.R == 2:
            return compute_U_r2_r4(info, key) == info.U
        return compute_U_r2_r4(info, key) == info.U[:16]
    if info.R == 5:
        # Algorithm 3.2a: SHA256(pw + U[32:40]) must equal U[0:32]
        return hashlib.sha256(pw[:127] + info.U[32:40]).digest() == info.U[:32]
    if info.R == 6:
        return hash96_r6(pw[:127], info.U[32:40], None) == info.U[:32]
    raise ValueError(f"unsupported revision R={info.R}")


# --------------------------------------------------------------------------
# Commands
# --------------------------------------------------------------------------
def cmd_extract(args):
    info = extract_info(args.pdf)
    line = info.to_pdf_hash()
    if args.with_filename:
        line = f"{args.pdf}:{line}"
    print(line)
    return 0


def cmd_crack(args):
    hashes = []
    for line in open(args.hashfile):
        line = line.strip()
        if not line:
            continue
        if ":" in line and line.split(":", 1)[1].startswith("$pdf$"):
            line = line.split(":", 1)[1]
        hashes.append(PdfCryptInfo.from_pdf_hash(line))
    info = hashes[0]

    words = [w.rstrip("\r\n") for w in open(args.wordlist, "r",
                                            errors="ignore")]
    words = [w for w in words if w]
    total = len(words)
    t0 = time.time()
    found = None
    print(f"[*] PDF hash   : {info.to_pdf_hash()[:72]}...")
    print(f"[*] Cipher     : V={info.V} R={info.R} {info.bits}-bit "
          f"(PDF standard security handler)")
    print(f"[*] Wordlist   : {args.wordlist} ({total} words)")
    print("[*] Dictionary attack started ...")
    for n, w in enumerate(words, 1):
        if n % 250 == 0 or n == total:
            el = time.time() - t0
            print(f"    tried {n}/{total}  ({n/el:,.0f} pw/s)", file=sys.stderr)
        if check_password(info, w.encode("utf-8", "surrogateescape")):
            found = w
            break
    el = time.time() - t0
    if found is not None:
        print(f"[+] CRACKED after {n}/{total} words in {el:.2f}s "
              f"({n/el:,.0f} pw/s)")
        print(f"[+] Password   : {found}")
        return 0
    print(f"[-] FAILED: password not in this wordlist "
          f"({total} words tried in {el:.2f}s)")
    return 1


def cmd_verify(args):
    try:
        import pikepdf
    except ImportError:
        print("verify needs pikepdf", file=sys.stderr)
        return 2
    try:
        pdf = pikepdf.open(args.pdf, password=args.password)
    except pikepdf.PasswordError:
        print(f"[-] '{args.password}' does NOT open {args.pdf}")
        return 1
    print(f"[+] '{args.password}' opens {args.pdf} "
          f"({len(pdf.pages)} page(s)) - password confirmed")
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("extract", help="extract the $pdf$ hash from a locked PDF")
    p.add_argument("pdf")
    p.add_argument("--with-filename", action="store_true")
    p.set_defaults(func=cmd_extract)

    p = sub.add_parser("crack", help="dictionary attack against a $pdf$ hash")
    p.add_argument("hashfile")
    p.add_argument("--wordlist", required=True)
    p.set_defaults(func=cmd_crack)

    p = sub.add_parser("verify", help="check a password opens the PDF")
    p.add_argument("pdf")
    p.add_argument("password")
    p.set_defaults(func=cmd_verify)

    args = ap.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
