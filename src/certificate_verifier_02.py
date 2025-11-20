#!/usr/bin/env python3
import json
import sys
import re
import hashlib
import unicodedata
from pathlib import Path
from pypdf import PdfReader
import oqs
import base64

CONFIG = {
    "embedded_payload_name": "cert_payload.json",
    "embedded_signature_name": "cert_signature.bin",
    "meta_alg": "SigAlg",
    "meta_sig_b64": "CertSigB64",
    "meta_payload_b64": "CertPayloadB64",
    "meta_policy_oid": "PolicyOID",
    "meta_issuer_id": "IssuerID",
    "meta_issued_at": "IssuedAt",
    "meta_revocation_snapshot_b64": "RevocationSnapshotB64",
    "meta_key_fingerprint": "IssuerKeyFingerprint",
    "allowed_alg_labels": ["Dilithium2", "Dilithium3", "Dilithium5"],
    "oqs_name_by_label": {
        "Dilithium2": "Dilithium2",
        "Dilithium3": "Dilithium3",
        "Dilithium5": "Dilithium5",
    },
}

def load_public_key_bytes(path: Path) -> bytes:
    data = path.read_bytes()
    try:
        text = data.decode("utf-8", errors="ignore")
        m_std = re.search(r"-----BEGIN\s+PUBLIC KEY-----\s*(.*?)\s*-----END\s+PUBLIC KEY-----", text, flags=re.S)
        if m_std:
            b64 = re.sub(r"\s+", "", m_std.group(1))
            return base64.b64decode(b64)
        m_oqs = re.search(r"-----BEGIN\s+OQS-PUBKEY\b[^\-]*-----\s*(.*?)\s*-----END\s+OQS-PUBKEY\b[^\-]*-----", text, flags=re.S)
        if m_oqs:
            b64 = re.sub(r"\s+", "", m_oqs.group(1))
            return base64.b64decode(b64)
    except Exception:
        pass
    return data

def extract_embedded_files(reader: PdfReader):
    out = {}
    try:
        names = reader.trailer["/Root"].get("/Names")
        if not names:
            return out
        ef_tree = names.get("/EmbeddedFiles")
        if not ef_tree:
            return out
        kids = ef_tree.get("/Names")
        if not kids:
            return out
        for i in range(0, len(kids), 2):
            name = kids[i]
            filespec = kids[i + 1]
            fname = str(name)
            ef_dict = filespec.get("/EF")
            if ef_dict and ef_dict.get("/F"):
                file_stream = ef_dict.get("/F").get_object()
                out[fname] = file_stream.get_data()
    except Exception:
        pass
    return out

def get_pdf_metadata(reader: PdfReader):
    meta = {}
    try:
        info = reader.metadata or {}
        for k, v in info.items():
            key = k.strip("/").strip()
            if isinstance(v, str):
                meta[key] = v
    except Exception:
        pass
    return meta

def load_payload_and_sig_from_pdf(pdf_path: Path):
    reader = PdfReader(str(pdf_path))
    embedded = extract_embedded_files(reader)
    payload = embedded.get(CONFIG["embedded_payload_name"])
    signature = embedded.get(CONFIG["embedded_signature_name"])
    meta = get_pdf_metadata(reader)
    if payload and signature:
        alg_label = meta.get(CONFIG["meta_alg"], "")
        aux = {
            "PolicyOID": meta.get(CONFIG["meta_policy_oid"]),
            "IssuerID": meta.get(CONFIG["meta_issuer_id"]),
            "IssuedAt": meta.get(CONFIG["meta_issued_at"]),
            "RevocationSnapshotB64": meta.get(CONFIG["meta_revocation_snapshot_b64"]),
            CONFIG["meta_key_fingerprint"]: meta.get(CONFIG["meta_key_fingerprint"]),
        }
        return payload, signature, alg_label, aux
    payload_b64 = meta.get(CONFIG["meta_payload_b64"])
    sig_b64 = meta.get(CONFIG["meta_sig_b64"])
    alg_label = meta.get(CONFIG["meta_alg"], "")
    if not payload_b64 or not sig_b64:
        raise ValueError("Missing embedded files and metadata; need cert_payload.json & cert_signature.bin or CertPayloadB64 & CertSigB64")
    payload = base64.b64decode(payload_b64)
    signature = base64.b64decode(sig_b64)
    aux = {
        "PolicyOID": meta.get(CONFIG["meta_policy_oid"]),
        "IssuerID": meta.get(CONFIG["meta_issuer_id"]),
        "IssuedAt": meta.get(CONFIG["meta_issued_at"]),
        "RevocationSnapshotB64": meta.get(CONFIG["meta_revocation_snapshot_b64"]),
        CONFIG["meta_key_fingerprint"]: meta.get(CONFIG["meta_key_fingerprint"]),
    }
    return payload, signature, alg_label, aux

def verify_signature(pubkey: bytes, message: bytes, signature: bytes, alg_label: str) -> bool:
    if alg_label not in CONFIG["allowed_alg_labels"]:
        raise ValueError(f"Unsupported algorithm label: {alg_label!r}")
    oqs_name = CONFIG["oqs_name_by_label"][alg_label]
    try:
        with oqs.Signature(oqs_name) as sig:
            return sig.verify(message, signature, pubkey)
    except Exception as e:
        raise RuntimeError(f"OQS verification error: {e}")

def extract_visual_text_hash_from_pdf(pdf_path: Path) -> str:
    reader = PdfReader(str(pdf_path))
    texts = []
    if len(reader.pages) == 0:
        combined = ""
    else:
        first = (reader.pages[0].extract_text() or "").strip()
        if first:
            combined = first
        else:
            for p in reader.pages:
                t = p.extract_text() or ""
                if t.strip():
                    texts.append(t)
            combined = "\n".join(texts)
    norm = unicodedata.normalize("NFC", combined)
    norm = " ".join(norm.split())
    return hashlib.sha256(norm.encode("utf-8")).hexdigest()

def load_config(path: Path):
    if not path.exists():
        raise SystemExit(f"Missing config: {path}")
    return json.loads(path.read_text(encoding="utf-8"))

def main():
    cfg = load_config(Path("../inputs/certificate_verifier_input.json"))
    pdf_path = Path(cfg["pdf"]).resolve()
    pubkey_path = Path(cfg["pubkey"]).resolve()
    expect_alg = cfg.get("expect_alg")
    print_payload = bool(cfg.get("print_payload", False))
    try:
        payload_bytes, signature_bytes, alg_label, aux = load_payload_and_sig_from_pdf(pdf_path)
        try:
            payload_obj = json.loads(payload_bytes.decode("utf-8"))
        except Exception:
            raise ValueError("Payload JSON is not valid UTF-8 JSON")
        vth = payload_obj.get("visual_text_hash")
        if not isinstance(vth, dict) or "value" not in vth:
            raise ValueError("Payload missing visual_text_hash.value")
        new_visual_hash = extract_visual_text_hash_from_pdf(pdf_path)
        old_visual_hash = vth["value"]
        if new_visual_hash != old_visual_hash:
            print("VERDICT: INVALID")
            print("Reason: Visual text does not match visual_text_hash inside payload.")
            print("Expected visual_text_hash:", old_visual_hash)
            print("Computed visual_text_hash:", new_visual_hash)
            sys.exit(6)
        if not alg_label:
            alg_label = expect_alg or ""
        if not alg_label:
            print("VERDICT: INVALID")
            print("Reason: Missing algorithm label (SigAlg).")
            sys.exit(4)
        pubkey = load_public_key_bytes(pubkey_path)
        meta_fp = aux.get(CONFIG["meta_key_fingerprint"])
        if meta_fp:
            computed_fp = hashlib.sha256(pubkey).hexdigest()
            if computed_fp != meta_fp:
                print("VERDICT: INVALID")
                print("Reason: Issuer public key fingerprint mismatch.")
                print("Metadata fingerprint:", meta_fp)
                print("Computed pubkey fingerprint:", computed_fp)
                sys.exit(7)
        print("=== DEBUG ===")
        print("Algo:", alg_label)
        print("Pubkey len:", len(pubkey))
        print("Pubkey sha256:", hashlib.sha256(pubkey).hexdigest())
        print("Payload sha256:", hashlib.sha256(payload_bytes).hexdigest())
        print("Payload length:", len(payload_bytes))
        print("Signature length (raw):", len(signature_bytes))
        ok = verify_signature(pubkey, payload_bytes, signature_bytes, alg_label)
        if not ok:
            print("VERDICT: INVALID")
            print("Reason: Signature verification failed.")
            sys.exit(5)
        print("VERDICT: VALID")
        print(f"Algorithm: {alg_label}")
        if aux.get("IssuerID"): print(f"IssuerID: {aux['IssuerID']}")
        if aux.get("IssuedAt"): print(f"IssuedAt: {aux['IssuedAt']}")
        if print_payload:
            print("\n-- Payload (from PDF, pretty) --")
            print(json.dumps(payload_obj, indent=2, ensure_ascii=False))
    except SystemExit:
        raise
    except Exception as e:
        print("VERDICT: ERROR")
        print("Reason:", str(e))
        sys.exit(10)

if __name__ == "__main__":
    main()
