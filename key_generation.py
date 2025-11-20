import os, argparse, hashlib, base64
import oqs

def write_pem_pubkey(pub_bytes: bytes, outpath: str, issuer_id: str, alg: str):
    b64 = base64.b64encode(pub_bytes).decode('ascii')
    with open(outpath, "w", encoding="utf-8") as f:
        f.write(f"-----BEGIN OQS-PUBKEY {alg} {issuer_id}-----\n")
        for i in range(0, len(b64), 64):
            f.write(b64[i:i+64] + "\n")
        f.write(f"-----END OQS-PUBKEY {alg} {issuer_id}-----\n")

def generate_keys(out_dir: str, issuer_id: str, alg: str = "Dilithium2"):
    os.makedirs(out_dir, exist_ok=True)
    pubpath_bin = os.path.join(out_dir, f"{issuer_id}.pub")
    secret_path = os.path.join(out_dir, f"{issuer_id}.sk")
    pem_path = os.path.join(out_dir, f"{issuer_id}.pub.pem")

    with oqs.Signature(alg) as sig:
        pk = sig.generate_keypair()
        sk = sig.export_secret_key()

    with open(pubpath_bin, "wb") as f:
        f.write(pk)
    with open(secret_path, "wb") as f:
        f.write(sk)
    write_pem_pubkey(pk, pem_path, issuer_id, alg)

    fp = hashlib.sha256(pk).hexdigest()
    print("Wrote:", pubpath_bin)
    print("Wrote:", secret_path)
    print("Wrote:", pem_path)
    print("IssuerID:", issuer_id)
    print("Public key fingerprint (sha256):", fp)
    return pubpath_bin, secret_path, pem_path, fp

if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--out-dir", default=r"F:\One Point\MTech\VS Code\Python\Seminar\Out\issuer_portal_keys")
    p.add_argument("--issuer-id", required=True, help="eg. xyz-university-2025")
    p.add_argument("--alg", default="Dilithium2")
    args = p.parse_args()
    generate_keys(args.out_dir, args.issuer_id, args.alg)
