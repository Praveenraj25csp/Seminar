import json
import hashlib
import base64
import oqs
from pathlib import Path

def write_pem_pubkey(pub_bytes, outpath, issuer_id, alg):
    b64 = base64.b64encode(pub_bytes).decode("ascii")
    with open(outpath, "w", encoding="utf-8") as f:
        f.write(f"-----BEGIN OQS-PUBKEY {alg} {issuer_id}-----\n")
        for i in range(0, len(b64), 64):
            f.write(b64[i:i+64] + "\n")
        f.write(f"-----END OQS-PUBKEY {alg} {issuer_id}-----\n")

def generate_keys(out_dir, issuer_id, alg):
    out_dir.mkdir(parents=True, exist_ok=True)
    pubpath_bin = out_dir / f"{issuer_id}.pub"
    secret_path = out_dir / f"{issuer_id}.sk"
    pem_path = out_dir / f"{issuer_id}.pub.pem"
    with oqs.Signature(alg) as sig:
        pk = sig.generate_keypair()
        sk = sig.export_secret_key()
    pubpath_bin.write_bytes(pk)
    secret_path.write_bytes(sk)
    write_pem_pubkey(pk, pem_path, issuer_id, alg)
    fp = hashlib.sha256(pk).hexdigest()
    print("Wrote:", pubpath_bin)
    print("Wrote:", secret_path)
    print("Wrote:", pem_path)
    print("IssuerID:", issuer_id)
    print("Public key fingerprint (sha256):", fp)

def main():
    cfg_path = Path("../inputs/key_generation_input.json")
    with open(cfg_path, "r") as f:
        cfg = json.load(f)
    out_dir = Path(cfg["out_dir"])
    issuer_id = cfg["issuer_id"]
    alg = cfg.get("alg", "Dilithium2")
    generate_keys(out_dir, issuer_id, alg)

if __name__ == "__main__":
    main()
