#!/usr/bin/env python3
import argparse, base64, json, sys, re, hashlib, unicodedata
from typing import Dict, Tuple
from pypdf import PdfReader
import oqs

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

def load_public_key_bytes(path: str) -> bytes:
    with open(path, "rb") as f:
        data = f.read()
    # try to detect and decode several PEM styles
    try:
        text = data.decode("utf-8", errors="ignore")
        # standard PEM
        m_std = re.search(r"-----BEGIN\s+PUBLIC KEY-----\s*(.*?)\s*-----END\s+PUBLIC KEY-----", text, flags=re.S)
        if m_std:
            b64 = re.sub(r"\s+", "", m_std.group(1))
            return base64.b64decode(b64)
        # custom OQS PEM like: -----BEGIN OQS-PUBKEY Dilithium2 IssuerID-----
        m_oqs = re.search(r"-----BEGIN\s+OQS-PUBKEY\b[^\-]*-----\s*(.*?)\s*-----END\s+OQS-PUBKEY\b[^\-]*-----", text, flags=re.S)
        if m_oqs:
            b64 = re.sub(r"\s+", "", m_oqs.group(1))
            return base64.b64decode(b64)
    except Exception:
        pass
    # fallback: assume raw binary
    return data

def extract_embedded_files(reader: PdfReader) -> Dict[str, bytes]:
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

def get_pdf_metadata(reader: PdfReader) -> Dict[str, str]:
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

def load_payload_and_sig_from_pdf(pdf_path: str) -> Tuple[bytes, bytes, str, Dict[str, str]]:
    reader = PdfReader(pdf_path)

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
        # wrap OQS exceptions with useful info
        raise RuntimeError(f"OQS verification error: {e}")

def extract_visual_text_hash_from_pdf(pdf_path: str) -> str:
    reader = PdfReader(pdf_path)
    # try page 0 first, if empty, concatenate all pages (mirrors maker)
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
    # normalization: NFC + collapse whitespace (must match maker)
    norm = unicodedata.normalize("NFC", combined)
    norm = " ".join(norm.split())
    return hashlib.sha256(norm.encode("utf-8")).hexdigest()

def main():
    ap = argparse.ArgumentParser(description="Verify a PQC-signed certificate PDF (Dilithium).")
    ap.add_argument("--pdf", required=True)
    ap.add_argument("--pubkey", required=True)
    ap.add_argument("--expect-alg", default=None, help="Optionally enforce an algorithm label (e.g., Dilithium2)")
    ap.add_argument("--print-payload", action="store_true")
    args = ap.parse_args()

    try:
        payload_bytes, signature_bytes, alg_label, aux = load_payload_and_sig_from_pdf(args.pdf)
        message_bytes = payload_bytes

        # parse payload early and validate visual_text_hash exists
        try:
            payload_obj = json.loads(payload_bytes.decode("utf-8"))
        except Exception:
            raise ValueError("Payload JSON is not valid UTF-8 JSON")

        vth = payload_obj.get("visual_text_hash")
        if not isinstance(vth, dict) or "value" not in vth:
            raise ValueError("Payload missing visual_text_hash.value")

        # Extract NEW visual hash from the actual PDF
        new_visual_hash = extract_visual_text_hash_from_pdf(args.pdf)
        old_visual_hash = vth["value"]

        if new_visual_hash != old_visual_hash:
            print("VERDICT: INVALID")
            print("Reason: Visual text does not match visual_text_hash inside payload.")
            print("Expected visual_text_hash:", old_visual_hash)
            print("Computed visual_text_hash:", new_visual_hash)
            sys.exit(6)

        if not alg_label:
            alg_label = args.expect_alg or ""

        if not alg_label:
            print("VERDICT: INVALID")
            print("Reason: Missing algorithm label (SigAlg). Pass --expect-alg Dilithium2 if needed.")
            sys.exit(4)

        pubkey = load_public_key_bytes(args.pubkey)

        # optional: compare pubkey fingerprint with embedded metadata
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
        print("Payload sha256:", hashlib.sha256(message_bytes).hexdigest())
        print("Payload length:", len(message_bytes))
        print("Signature length (raw):", len(signature_bytes))

        ok = verify_signature(pubkey, message_bytes, signature_bytes, alg_label)
        if not ok:
            print("VERDICT: INVALID")
            print("Reason: Signature verification failed.")
            sys.exit(5)

        print("VERDICT: VALID")
        print(f"Algorithm: {alg_label}")
        if aux.get("IssuerID"): print(f"IssuerID: {aux['IssuerID']}")
        if aux.get("IssuedAt"): print(f"IssuedAt: {aux['IssuedAt']}")

        if args.print_payload:
            try:
                print("\n-- Payload (from PDF, pretty) --")
                print(json.dumps(payload_obj, indent=2, ensure_ascii=False))
            except Exception:
                pass

    except SystemExit:
        raise
    except Exception as e:
        print("VERDICT: ERROR")
        print("Reason:", str(e))
        sys.exit(10)

if __name__ == "__main__":
    main()
