import argparse
import os
import datetime
import json
import hashlib
import unicodedata
import tempfile
import base64
import qrcode
from fpdf import FPDF
from PIL import Image
from pypdf import PdfReader, PdfWriter
import oqs

def normalize_str(s: str) -> str:
    if s is None:
        return ""
    s = str(s)
    s = unicodedata.normalize("NFC", s)
    s = " ".join(s.split())
    return s.strip()

def compute_sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()

def build_canonical_cert(schema, issuer_id, certificate_id, fields, visual_hash_algo, visual_hash_value):
    canonical = {
        "schema": normalize_str(schema),
        "issuer_id": normalize_str(issuer_id),
        "certificate_id": normalize_str(certificate_id),
        "fields": {
            "name": normalize_str(fields.get("name","")),
            "id": normalize_str(fields.get("id","")),
            "program": normalize_str(fields.get("program","")),
            "issuer": normalize_str(fields.get("issuer","")),
            "issued_date": normalize_str(fields.get("issued_date","")),
        },
        "visual_text_hash": {
            "algo": normalize_str(visual_hash_algo),
            "value": normalize_str(visual_hash_value),
        }
    }
    b = json.dumps(canonical, ensure_ascii=False, separators=(",", ":"),).encode("utf-8")
    return canonical, b

def extract_first_page_text(pdf_path: str) -> str:
    reader = PdfReader(pdf_path)
    if len(reader.pages) == 0:
        return ""
    text = reader.pages[0].extract_text() or ""
    if not text.strip():
        parts = []
        for p in reader.pages:
            t = p.extract_text() or ""
            if t.strip():
                parts.append(t)
        text = "\n".join(parts)
    return text

ASSETS_DIR = r"f:/One Point/MTech/VS Code/Python/Seminar/Assets"
LOGO_PATH = os.path.join(ASSETS_DIR, "Northcap Logo.png")
SIGNATURE_PATH = os.path.join(ASSETS_DIR, "Signature.png")
OFFICIAL_PATH = os.path.join(ASSETS_DIR, "Official.jpg")

for name, path in [("logo", LOGO_PATH), ("signature", SIGNATURE_PATH), ("official", OFFICIAL_PATH)]:
    if not os.path.exists(path):
        print(f"[Warning] Asset missing: {name} -> {path}")

def create_visual_pdf(out_path: str, recipient_name: str, program: str, issuer: str, issued_date: str, roll_number: str, logo_path: str=None, signature_path: str=None, official_path: str=None, qr_data: str=None):
    pdf = FPDF(orientation="L", unit="mm", format="A4")
    pdf.set_auto_page_break(False)
    pdf.add_page()
    page_w = pdf.w; page_h = pdf.h
    margin = 12
    inner_margin = 20

    pdf.set_line_width(2)
    pdf.set_draw_color(40, 40, 40)
    pdf.rect(margin/2, margin/2, page_w - margin, page_h - margin)

    pdf.set_line_width(1)
    pdf.set_draw_color(150, 150, 150)
    pdf.rect(inner_margin, inner_margin, page_w - inner_margin * 2, page_h - inner_margin * 2)

    if logo_path and os.path.exists(logo_path):
        pdf.image(logo_path, x=inner_margin + 10, y=inner_margin + 10, h=24)

    pdf.set_xy(35, inner_margin + 15)
    pdf.set_font("Arial", "B", 28)
    pdf.set_text_color(10, 10, 10)
    pdf.cell(0, 12, "COURSE COMPLETION CERTIFICATE", ln=True, align="C")

    pdf.set_line_width(1)
    pdf.set_draw_color(200, 100, 20)
    pdf.line(page_w * 0.10, inner_margin + 40, page_w * 0.90, inner_margin + 40)

    pdf.ln(20)
    pdf.set_font("Arial", size=12)
    pdf.set_text_color(60)
    pdf.cell(0, 2, "This is to certify that", ln=True, align="C")

    pdf.ln(4)
    pdf.set_font("Arial", "B", 36)
    pdf.set_text_color(20)
    pdf.cell(0, 12, recipient_name, ln=True, align="C")

    pdf.ln(4)
    pdf.set_font("Arial", size=14)
    pdf.set_text_color(40)
    pdf.cell(0, 8, f"with Roll Number {roll_number} has successfully completed the {program}.", ln=True, align="C")

    pdf.ln(10)
    col_w = (page_w - inner_margin*2) / 2
    x_left = inner_margin + 8
    y_row = pdf.get_y()

    pdf.set_xy(x_left, y_row)
    pdf.set_font("Arial", "B", 12)
    pdf.cell(col_w - 16, 6, f"Issuer: {issuer}", ln=False, align="L")

    pdf.set_xy(x_left + col_w + 20, y_row)
    pdf.set_font("Arial", "B", 12)
    pdf.cell(col_w - 16, 6, f"Issued date: {issued_date}", ln=True, align="L")

    pdf.ln(10)
    pdf.set_font("Arial", size=10)
    pdf.set_text_color(90)
    acc_text = "Awarded in recognition of successful completion of the program requirements and demonstrated competence."
    pdf.set_x(25)
    pdf.multi_cell(page_w - inner_margin*2, 5, acc_text, align="C")

    sig_x = page_w * 0.6
    sig_y = page_h - inner_margin - 40
    sig_w = 70
    sig_h = 30
    pdf.set_draw_color(80)
    pdf.set_line_width(0.4)
    dash_x = sig_x + 10
    dash_end = sig_x + sig_w + 10
    while dash_x < dash_end:
        pdf.line(dash_x, sig_y + sig_h - 6, dash_x + 6, sig_y + sig_h - 6)
        dash_x += 8
    pdf.set_xy(sig_x + 10, sig_y + sig_h - 4)
    pdf.set_font("Arial", size=10)
    pdf.set_text_color(30)
    pdf.cell(sig_w, 5, "Authorized Signature", align="C")

    if signature_path and os.path.exists(signature_path):
        try:
            with Image.open(signature_path) as img:
                rotated = img.rotate(-90, expand=True)
                with tempfile.NamedTemporaryFile(delete=False, suffix=".png") as tmp:
                    tmp_name = tmp.name
                    rotated.save(tmp_name, format="PNG")
                try:
                    pdf.image(tmp_name, x=sig_x + 16, y=sig_y - 3, w=sig_w - 12)
                finally:
                    try: os.remove(tmp_name)
                    except: pass
        except Exception as e:
            print("[Warning] signature image:", e)

    if official_path and os.path.exists(official_path):
        pdf.image(official_path, x=inner_margin + 5, y=page_h - inner_margin - 45, h=40, w=40)

    qr_data = qr_data or f"verify:{certificate_id_from_date_roll(issued_date, roll_number)}"
    if qr_data:
        qr_tmp = None
        try:
            qr_tmp = generate_qr_tempfile(qr_data)
            try:
                pdf.image(qr_tmp, x=inner_margin + 50, y=page_h - inner_margin - 35, w=28, h=28)
            except Exception as e:
                print("[Warning] could not place QR image into PDF:", e)
        finally:
            if qr_tmp:
                try:
                    os.remove(qr_tmp)
                except Exception:
                    pass

    pdf.output(out_path)
    return out_path

def certificate_id_from_date_roll(issued_date_str, roll):
    compact = issued_date_str.replace("-", "")
    return f"{compact}{roll}"

def generate_qr_tempfile(qr_data, size_mm=28, box_size=6):
    qr = qrcode.QRCode(version=2, error_correction=qrcode.constants.ERROR_CORRECT_M, box_size=box_size, border=2)
    qr.add_data(qr_data)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white").convert("RGB")
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".png")
    tmp_name = tmp.name
    tmp.close()
    img.save(tmp_name, format="PNG")
    return tmp_name

def main():
    p = argparse.ArgumentParser(description="Generate, sign and embed canonical certificate into PDF")
    p.add_argument("--roll", required=True, help="Student roll number")
    p.add_argument("--recipient-name", default="Praveenraj Jothi", help="Recipient name (hard-coded default)")
    p.add_argument("--program", default="MTech in Cybersecurity", help="Program name (hard-coded default)")
    p.add_argument("--issuer", default="The Northcap University", help="Issuer display name")
    p.add_argument("--issuer-id", required=True, help="Issuer ID used for portal & metadata (eg xyz-university-2025)")
    p.add_argument("--secret-key", required=True, help="Path to issuer secret key file (.sk or .key)")
    p.add_argument("--pub-key", required=True, help="Path to issuer public key file (.pub)")
    p.add_argument("--pdf", default=None, help="Optional: existing visual PDF to sign (if omitted the script generates one)")
    p.add_argument("--out-dir", default=None, help="Optional out dir (default: same folder as pdf)")
    p.add_argument("--alg", default="Dilithium2", help="Signature algorithm (default Dilithium2)")
    args = p.parse_args()

    roll = args.roll
    recipient_name = args.recipient_name
    program = args.program
    issuer = args.issuer
    issuer_id = args.issuer_id
    secret_key_path = args.secret_key
    pub_key_path = args.pub_key
    alg = args.alg

    IST = datetime.timezone(datetime.timedelta(hours=5, minutes=30))
    issued_date_dt = datetime.datetime.now(IST)
    issued_date = issued_date_dt.date().isoformat()
    certificate_id = f"{issued_date.replace('-','')}{roll}"

    if args.pdf:
        visual_pdf = args.pdf
        if not os.path.exists(visual_pdf):
            raise SystemExit("Provided PDF not found: " + visual_pdf)
    else:
        out_folder = os.path.join(os.getcwd(), "Out")
        os.makedirs(out_folder, exist_ok=True)
        visual_pdf = os.path.join(out_folder, f"Certificate_{certificate_id}.pdf")
        create_visual_pdf(visual_pdf, recipient_name, program, issuer, issued_date, roll, logo_path=LOGO_PATH, signature_path=SIGNATURE_PATH, official_path=OFFICIAL_PATH)

    page_text = extract_first_page_text(visual_pdf)
    visual_norm = normalize_str(page_text)
    visual_hash = compute_sha256_hex(visual_norm.encode("utf-8"))

    fields = {
        "name": recipient_name,
        "id": roll,
        "program": program,
        "issuer": issuer,
        "issued_date": issued_date
    }

    canonical_dict, canonical_bytes = build_canonical_cert("v1", issuer_id, certificate_id, fields, "sha256", visual_hash)

    cert_json_path = os.path.splitext(visual_pdf)[0] + "_cert.json"
    with open(cert_json_path, "wb") as f:
        f.write(canonical_bytes)

    if not os.path.exists(secret_key_path):
        raise SystemExit("Secret key file not found: " + secret_key_path)
    with open(secret_key_path, "rb") as f:
        sk = f.read()

    with oqs.Signature(alg, secret_key=sk) as signer:
        signature = signer.sign(canonical_bytes)

    if not os.path.exists(pub_key_path):
        raise SystemExit("Public key file not found: " + pub_key_path)
    with open(pub_key_path, "rb") as f:
        pub_bytes = f.read()
    issuer_fp = compute_sha256_hex(pub_bytes)

    reader = PdfReader(visual_pdf)
    writer = PdfWriter()
    for p in reader.pages:
        writer.add_page(p)

    metadata = {
        "/IssuerID": issuer_id,
        "/IssuerKeyFingerprint": issuer_fp,
        "/SigAlg": alg
    }
    payload_b64 = base64.b64encode(canonical_bytes).decode("ascii")
    sig_b64 = base64.b64encode(signature).decode("ascii")

    metadata.update({
        "/CertPayloadB64": payload_b64,
        "/CertSigB64": sig_b64,
    })
    writer.add_metadata(metadata)

    writer.add_attachment("cert_payload.json", canonical_bytes)
    writer.add_attachment("cert_signature.bin", signature)

    signed_pdf = os.path.splitext(visual_pdf)[0] + "_signed.pdf"
    with open(signed_pdf, "wb") as f:
        writer.write(f)

    print("Signed PDF written:", signed_pdf)
    print("Canonical JSON written:", cert_json_path)
    print("visual_text_hash (sha256):", visual_hash)
    print("payload_hash (sha256):", compute_sha256_hex(canonical_bytes))
    print("IssuerID:", issuer_id)
    print("Issuer public key fingerprint (sha256):", issuer_fp)
    print("Signature length (bytes):", len(signature))

if __name__ == "__main__":
    main()
