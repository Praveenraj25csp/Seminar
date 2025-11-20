#!/usr/bin/env python3
"""
pdf_to_cert_hash.py

Given a certificate PDF path, this script:
 - extracts the visual text from the first page (best-effort)
 - normalizes it and computes visual_text_hash (sha256)
 - heuristically extracts fields (issuer_id, name, id/roll, program, issuer, issued_date, certificate_id)
 - builds canonical JSON in fixed order
 - prints canonical JSON and SHA-256 hex digest to stdout
 - optionally writes cert.json next to the PDF

Usage:
    python pdf_to_cert_hash.py /path/to/Certificate.pdf [--write-json] [--out <path>]
"""

import argparse
import json
import hashlib
import unicodedata
import re
import os
from pypdf import PdfReader
import datetime

# ---------- Helpers ----------
def normalize_str(s: str) -> str:
    if s is None:
        return ""
    s = str(s)
    s = unicodedata.normalize("NFC", s)
    # collapse whitespace
    s = " ".join(s.split())
    return s.strip()

def extract_first_page_text(pdf_path: str) -> str:
    reader = PdfReader(pdf_path)
    # prefer first page
    if len(reader.pages) == 0:
        return ""
    text = reader.pages[0].extract_text() or ""
    # if first page empty, fall back to concatenating pages
    if not text.strip():
        parts = []
        for p in reader.pages:
            t = p.extract_text() or ""
            if t.strip():
                parts.append(t)
        text = "\n".join(parts)
    return text

def compute_sha256_hex(data_bytes: bytes) -> str:
    return hashlib.sha256(data_bytes).hexdigest()

def normalize_page_for_hash(page_text: str) -> str:
    # rules: NFC, collapse whitespace to single spaces, strip
    return normalize_str(page_text)

# ---------- Field extraction heuristics ----------
def parse_fields_from_text(page_text: str, pdf_path: str=None):
    """
    Best-effort parse common fields from page_text.
    Returns dict with keys: name, id, program, issuer, issued_date (YYYY-MM-DD or ""), certificate_id
    and diagnostics explaining what was found.
    """
    diag = {}
    text = page_text
    # normalize line breaks for easier regex
    lines = [l.strip() for l in text.splitlines() if l.strip()]
    lower = "\n".join(lines).lower()

    # Helper to search regex across the normalized lines
    def search(pattern, flags=0):
        m = re.search(pattern, text, flags)
        return m.group(1).strip() if m else None

    # 1) certificate_id
    cert_id = search(r"Certificate\s*ID[:\s]*([A-Za-z0-9\-_/]+)", re.I)
    if not cert_id:
        cert_id = search(r"Certificate[:\s]*([A-Za-z0-9\-_/]+)", re.I)
    if not cert_id:
        # maybe footer "Certificate ID: ..." or "Cert ID"
        cert_id = search(r"Cert(?:ificate)?\s*ID[:\s]*([A-Za-z0-9\-_/]+)", re.I)
    if cert_id:
        diag['certificate_id_found_by'] = 'regex'
    else:
        diag['certificate_id_found_by'] = None

    # 2) issued_date - look for yyyy-mm-dd or dd-mm-yyyy or Month dd, yyyy
    issued_date = None
    m = re.search(r"Issued\s*date[:\s]*([0-9]{4}-[0-9]{2}-[0-9]{2})", text, re.I)
    if m:
        issued_date = m.group(1)
        diag['issued_date_by'] = 'YYYY-MM-DD'
    else:
        m = re.search(r"Issued\s*date[:\s]*([0-9]{2}[/-][0-9]{2}[/-][0-9]{4})", text, re.I)
        if m:
            # try to parse dd-mm-yyyy or mm-dd-yyyy; assume dd-mm-yyyy (common)
            raw = m.group(1).replace("/", "-")
            parts = raw.split("-")
            if len(parts) == 3:
                d, mth, y = parts[0], parts[1], parts[2]
                try:
                    dt = datetime.date(int(y), int(mth), int(d))
                    issued_date = dt.isoformat()
                    diag['issued_date_by'] = 'dd-mm-yyyy guessed'
                except Exception:
                    issued_date = ""
        else:
            # try Month name forms e.g. October 7, 2025
            m = re.search(r"Issued\s*date[:\s]*([A-Za-z]{3,9}\s+\d{1,2},?\s+\d{4})", text, re.I)
            if m:
                try:
                    parsed = datetime.datetime.strptime(m.group(1), "%B %d, %Y")
                    issued_date = parsed.date().isoformat()
                    diag['issued_date_by'] = 'MonthName parsed'
                except Exception:
                    issued_date = None

    if not issued_date:
        # fallback: try to find any yyyy pattern in the page near 'Issued' or 'Date'
        m = re.search(r"([0-9]{4}-[0-9]{2}-[0-9]{2})", text)
        if m:
            issued_date = m.group(1)
            diag['issued_date_by'] = 'first ISO date on page'
    if not issued_date:
        issued_date = ""

    # 3) roll/id
    roll = search(r"Roll(?:\s*Number)?[:\s]*([A-Za-z0-9\-_/]+)", re.I)
    if not roll:
        roll = search(r"ID[:\s]*([A-Za-z0-9\-_/]+)", re.I)
    if roll:
        diag['roll_by'] = 'regex'
    else:
        diag['roll_by'] = None

    # 4) issuer (human-readable)
    issuer = search(r"Issuer[:\s]*(.+?)(?:\n|$)", re.I)
    if not issuer:
        # sometimes footer "Issued by XYZ"
        issuer = search(r"Issued\s+by[:\s]*(.+?)(?:\n|$)", re.I)
    if issuer:
        diag['issuer_by'] = 'regex'
    else:
        diag['issuer_by'] = None

    # 5) program
    # look for "completed the (.*)" or "has successfully completed the (.*)."
    prog = None
    m = re.search(r"has successfully completed the\s+(.+?)(?:\s+(?:Specialization|Program|Course))?(?:[.\n]|$)", text, re.I)
    if not m:
        m = re.search(r"completed the\s+(?:\s+(?:Specialization|Program|Course))?(?:[.\n]|$)", text, re.I)
    if m:
        prog = m.group(1).strip()
        diag['program_by'] = 'regex completed the'
    else:
        diag['program_by'] = None

    # 6) name extraction — tricky: look for lines like "This is to certify that <NAME>"
    name = None
    m = re.search(r"This (?:is to )?certify that\s+(.+?)(?:\n|,| has | who )", text, re.I)
    if m:
        candidate = m.group(1).strip()
        # if candidate contains multiple words and not too long, take it
        if 2 <= len(candidate.split()) <= 6 and len(candidate) < 120:
            name = candidate
            diag['name_by'] = 'certify that regex'
    if not name:
        # fallback: look for the largest line (most characters) that is not a title
        if lines:
            # ignore lines that are titles
            candidates = [l for l in lines if len(l) > 2 and 'certificate' not in l.lower() and 'issuer' not in l.lower()]
            if candidates:
                # often name is a medium-length centered line; pick a line of length between 5 and 60 with words
                candidates = sorted(candidates, key=lambda s: abs(36 - len(s)))  # favor lines ~36 chars (heuristic)
                name = candidates[0]
                diag['name_by'] = 'heuristic pick'
    if not name:
        name = ""

    # 7) certificate_id fallback: if not found earlier, build from date+roll if available
    if not cert_id:
        if issued_date:
            compact = issued_date.replace("-", "")
            if roll:
                cert_id = f"{compact}{roll}"
                diag['certificate_id_by'] = 'built_from_date_roll'
            else:
                cert_id = compact
                diag['certificate_id_by'] = 'built_from_date'
        else:
            cert_id = ""
            diag['certificate_id_by'] = None

    # Normalize all fields
    parsed = {
        "name": normalize_str(name),
        "id": normalize_str(roll) if roll else "",
        "program": normalize_str(prog) if prog else "",
        "issuer": normalize_str(issuer) if issuer else "",
        "issued_date": normalize_str(issued_date) if issued_date else "",
        "certificate_id": normalize_str(cert_id) if cert_id else "",
        "diagnostics": diag
    }
    return parsed

# ---------- Build canonical dict & compute hash ----------
def build_canonical_dict_from_pdf(pdf_path: str, issuer_id_guess: str = None):
    # 1) extract text
    page_text_raw = extract_first_page_text(pdf_path)
    visual_norm = normalize_page_for_hash(page_text_raw)
    visual_hash = compute_sha256_hex(visual_norm.encode("utf-8"))

    # 2) parse fields heuristically
    parsed = parse_fields_from_text(page_text_raw, pdf_path=pdf_path)

    # 3) issuer_id: prefer guess param, else look for in parsed text or fallback to empty
    issuer_id = issuer_id_guess or ""
    # try to find issuer_id label in metadata or text: look for a token-like id pattern "xxx-university-2025"
    m = re.search(r"([A-Za-z0-9_\-]+-university-[0-9]{4})", page_text_raw, re.I)
    if not issuer_id and m:
        issuer_id = m.group(1).strip()
    # if still empty, try "Issued by <NAME>" normalized
    if not issuer_id and parsed.get("issuer"):
        # create simple slug from issuer name
        slug = re.sub(r"[^A-Za-z0-9]+", "-", parsed["issuer"].lower()).strip("-")
        issuer_id = slug + "-" + datetime.date.today().strftime("%Y")
    issuer_id = normalize_str(issuer_id)

    # 4) certificate_id come from parsed
    certificate_id = parsed.get("certificate_id", "")

    # 5) Build canonical dict in deterministic order
    canonical = {
        "schema": "v1",
        "issuer_id": issuer_id,
        "certificate_id": certificate_id,
        "fields": {
            "name": parsed.get("name", ""),
            "id": parsed.get("id", ""),
            "program": parsed.get("program", ""),
            "issuer": parsed.get("issuer", ""),
            "issued_date": parsed.get("issued_date", ""),
        },
        "visual_text_hash": {
            "algo": "sha256",
            "value": visual_hash
        }
    }

    # Compact JSON bytes
    canonical_bytes = json.dumps(canonical, ensure_ascii=False, separators=(",", ":"),).encode("utf-8")
    payload_hash_hex = compute_sha256_hex(canonical_bytes)

    result = {
        "page_text_raw": page_text_raw,
        "page_text_normalized": visual_norm,
        "visual_text_hash": visual_hash,
        "parsed_fields": parsed,
        "canonical_dict": canonical,
        "canonical_bytes": canonical_bytes,
        "payload_hash_hex": payload_hash_hex
    }
    return result

# ---------- CLI ----------
def main():
    p = argparse.ArgumentParser(description="Extract canonical payload and SHA-256 from a certificate PDF")
    p.add_argument("pdf", help="Path to certificate PDF")
    p.add_argument("--issuer-id", help="Optional issuer_id override (e.g. xyz-university-2025)", default=None)
    p.add_argument("--write-json", action="store_true", help="Write canonical cert.json next to the PDF")
    p.add_argument("--out", help="Write cert.json to this path (overrides --write-json destination)", default=None)
    args = p.parse_args()

    pdf_path = args.pdf
    if not os.path.exists(pdf_path):
        print("ERROR: PDF not found:", pdf_path)
        raise SystemExit(2)

    res = build_canonical_dict_from_pdf(pdf_path, issuer_id_guess=args.issuer_id)

    # Pretty-print summary
    print("=== Parsed fields (best-effort) ===")
    for k,v in res["parsed_fields"].items():
        if k == "diagnostics":
            continue
        print(f"{k}: {v}")
    print("diagnostics:", json.dumps(res["parsed_fields"].get("diagnostics", {}), indent=2))
    print()
    print("visual_text_hash (sha256):", res["visual_text_hash"])
    print("payload_hash (sha256)  :", res["payload_hash_hex"])
    print()
    print("Canonical JSON (compact):")
    print(res["canonical_bytes"].decode("utf-8"))
    print()

    # Optionally write canonical cert.json
    if args.write_json:
        if args.out:
            out_path = args.out
        else:
            out_path = os.path.splitext(pdf_path)[0] + "_cert.json"
        with open(out_path, "wb") as f:
            f.write(res["canonical_bytes"])
        print("Wrote canonical cert.json to:", out_path)

if __name__ == "__main__":
    main()
