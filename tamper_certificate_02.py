import argparse, json, base64, hashlib, sys, re
from PyPDF2 import PdfReader, PdfWriter
from PyPDF2.generic import (
    IndirectObject, ArrayObject, NameObject, NumberObject, DictionaryObject
)

PAYLOAD_NAME      = "cert_payload.json"
SIG_NAME          = "cert_signature.bin"
K_META_PAYLOAD    = "/CertPayloadB64"
K_META_SIG        = "/CertSigB64"

def _deref(obj):
    return obj.get_object() if isinstance(obj, IndirectObject) else obj

def _get_docinfo_map(reader: PdfReader):
    info = reader.metadata or {}
    return {k: (str(v) if v is not None else "") for k, v in info.items()}

def _update_stream_bytes(stream_obj, new_bytes: bytes):

    try:
        f_key = NameObject("/Filter")
        dp_key = NameObject("/DecodeParms")
        if f_key in stream_obj:
            del stream_obj[f_key]
        if dp_key in stream_obj:
            del stream_obj[dp_key]
    except Exception:
        pass
    stream_obj._data = new_bytes
    stream_obj[NameObject("/Length")] = NumberObject(len(new_bytes))

def _import_names_tree(reader: PdfReader, writer: PdfWriter):
    root_r = _deref(reader.trailer["/Root"])
    names_r = _deref(root_r.get("/Names"))
    if not isinstance(names_r, (DictionaryObject,)):
        return None
    names_ref = writer._add_object(names_r)
    writer._root_object.update({NameObject("/Names"): names_ref})
    return _deref(names_ref)

def _find_embedded_in_writer(writer: PdfWriter):
    out = {}
    root_w = _deref(writer._root_object)
    names = _deref(root_w.get("/Names"))
    if not names:
        return out
    embedded = _deref(names.get("/EmbeddedFiles"))
    if not embedded:
        return out
    arr = _deref(embedded.get("/Names"))
    if not isinstance(arr, ArrayObject):
        return out
    for i in range(0, len(arr), 2):
        name = str(arr[i])
        fs   = _deref(arr[i+1])
        ef   = _deref(fs.get("/EF"))
        if ef and ef.get("/F"):
            stream = _deref(ef.get("/F"))
            out[name] = {"filespec": fs, "stream": stream}
    return out

def _esc_lit(s: str) -> bytes:
    return s.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)").encode("latin-1")

def _utf16_hex(s: str) -> bytes:
    return ("<" + s.encode("utf-16-be").hex().upper() + ">").encode("ascii")

def _replace_literal_variants(data: bytes, old_text: str, new_text: str):
    replaced = 0
    variants = [
        (old_text.encode("latin-1"), new_text.encode("latin-1")),
        (b"(" + _esc_lit(old_text) + b")", b"(" + _esc_lit(new_text) + b")"),
        (_utf16_hex(old_text), _utf16_hex(new_text)),
    ]
    new_data = data
    for old_b, new_b in variants:
        if old_b in new_data:
            new_data = new_data.replace(old_b, new_b)
            replaced += 1
    return new_data, replaced

RE_TJ = re.compile(rb"\[\s*(?P<body>(?:\((?:\\.|[^()])*\)|-?\d+(?:\.\d+)?|\s+)+?)\s*\]\s*TJ")
RE_TJ_STR = re.compile(rb"\((?:\\.|[^()])*\)")

def _unescape_pdf_lit(b: bytes) -> str:
    assert b.startswith(b"(") and b.endswith(b")")
    inner = b[1:-1]
    out = bytearray()
    i = 0
    while i < len(inner):
        ch = inner[i]
        if ch == 0x5C:
            i += 1
            if i >= len(inner): break
            esc = inner[i]
            if esc in (0x5C, 0x28, 0x29):
                out.append(esc); i += 1
            elif esc in b"01234567":
                j = i; octal = bytes([esc]); j += 1
                for _ in range(2):
                    if j < len(inner) and inner[j] in b"01234567":
                        octal += bytes([inner[j]]); j += 1
                    else: break
                out.append(int(octal, 8)); i = j
            else:
                out.append(esc); i += 1
        else:
            out.append(ch); i += 1
    try: return out.decode("latin-1")
    except Exception: return out.decode("utf-8", errors="replace")

def _make_pdf_lit(s: str) -> bytes:
    return b"(" + _esc_lit(s) + b")"

def _replace_in_TJ_arrays(data: bytes, old_text: str, new_text: str):
    out = bytearray(); last = 0; hits = 0
    for m in RE_TJ.finditer(data):
        out += data[last:m.start()]
        body = m.group("body")
        seg_texts = [ _unescape_pdf_lit(sm.group(0)) for sm in RE_TJ_STR.finditer(body) ]
        if not seg_texts:
            out += data[m.start():m.end()]; last = m.end(); continue
        joined = "".join(seg_texts)
        if old_text in joined:
            repl = joined.replace(old_text, new_text)
            out += b"[" + _make_pdf_lit(repl) + b"] TJ"
            hits += 1
        else:
            out += data[m.start():m.end()]
        last = m.end()
    out += data[last:]
    return bytes(out), hits

def tamper(pdf_in: str, pdf_out: str, key: str, new_value: str):
    r = PdfReader(pdf_in)
    w = PdfWriter()
    w.append_pages_from_reader(r)

    names_w = _import_names_tree(r, w)
    ef_w = _find_embedded_in_writer(w)
    info_r = _get_docinfo_map(r)

    payload_bytes = None
    if PAYLOAD_NAME in ef_w:
        payload_bytes = ef_w[PAYLOAD_NAME]["stream"].get_data()
    elif K_META_PAYLOAD in info_r:
        try: payload_bytes = base64.b64decode(info_r[K_META_PAYLOAD])
        except Exception: payload_bytes = None

    if payload_bytes is None:
        print("ERROR: could not locate embedded payload to modify.", file=sys.stderr)
        sys.exit(2)

    try:
        payload_obj = json.loads(payload_bytes.decode("utf-8"))
    except Exception as e:
        print("ERROR: payload JSON decode failed:", e, file=sys.stderr)
        sys.exit(2)

    def _read_key(obj, k):
        if isinstance(obj, dict):
            if k in obj: return obj[k]
            if "fields" in obj and isinstance(obj["fields"], dict) and k in obj["fields"]:
                return obj["fields"][k]
        return None

    old_value = _read_key(payload_obj, key)
    if isinstance(payload_obj, dict) and (key in payload_obj or "fields" not in payload_obj):
        payload_obj[key] = new_value
    else:
        payload_obj.setdefault("fields", {})
        if not isinstance(payload_obj["fields"], dict):
            payload_obj["fields"] = {}
        payload_obj["fields"][key] = new_value

    new_payload_bytes = json.dumps(payload_obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

    if PAYLOAD_NAME in ef_w:
        _update_stream_bytes(ef_w[PAYLOAD_NAME]["stream"], new_payload_bytes)
    meta_out = dict(info_r)
    meta_out[K_META_PAYLOAD] = base64.b64encode(new_payload_bytes).decode("ascii")
    w.add_metadata(meta_out)

    streams_modified = 0
    matches = 0
    if isinstance(old_value, str) and old_value and old_value != new_value:
        for page in w.pages:
            contents = page.get("/Contents")
            if not contents: continue
            content_objs = [contents] if not isinstance(contents, ArrayObject) else contents
            for obj in content_objs:
                stream = _deref(obj)
                try:
                    data = stream.get_data()
                except Exception:
                    continue
                nd, h1 = _replace_literal_variants(data, old_value, new_value)
                nd, h2 = _replace_in_TJ_arrays(nd, old_value, new_value)
                if (h1 + h2) > 0 and nd != data:
                    _update_stream_bytes(stream, nd)
                    streams_modified += 1
                    matches += (h1 + h2)
        print(f"[visual] replaced '{old_value}' -> '{new_value}' | streams:{streams_modified}, hits:{matches}")
    else:
        print("[visual] skipped: old value for key not found in payload (or unchanged).")

    with open(pdf_out, "wb") as f:
        w.write(f)

    print("Tampered payload SHA256:", hashlib.sha256(new_payload_bytes).hexdigest(), "len:", len(new_payload_bytes))
    print("Saved:", pdf_out)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pdf", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--payload-change", required=True, help='key=value (e.g., name=Praveenraj Johti)')
    args = ap.parse_args()

    if "=" not in args.payload_change:
        print("payload-change must be key=value", file=sys.stderr); sys.exit(2)
    k, v = args.payload_change.split("=", 1)

    tamper(args.pdf, args.out, k, v)

if __name__ == "__main__":
    main()
