"""An access log checked by a second implementation, apart from seclume's own
AccessLogVerifier: the hash chain with hashlib, the checkpoint signatures with
the openssl command line.

usage: verify_access_log.py <log.jsonl> <public-key.der>

Exit 0 when the log holds, 1 when it does not - each problem on its own line.
"""
import hashlib
import json
import os
import subprocess
import sys
import tempfile

DOMAIN = b"seclume-access-log-1"
ZERO = "0" * 64


def problems(log_path, key_path):
    found = []
    with open(log_path, "rb") as f:
        data = f.read()
    if not data.endswith(b"\n"):
        found.append("torn: no line break at the end")
    with open(key_path, "rb") as f:
        key_der = f.read()
    fingerprint = hashlib.sha256(key_der).hexdigest()
    with tempfile.TemporaryDirectory() as tmp:
        pem = os.path.join(tmp, "key.pem")
        subprocess.run(["openssl", "pkey", "-pubin", "-inform", "DER", "-in", key_path,
                        "-out", pem], check=True, capture_output=True)
        prev, expected = ZERO, None
        for number, raw in enumerate(data.split(b"\n")[:-1], 1):
            line = raw.decode("ascii")
            entry = json.loads(line)
            seq = entry["seq"]
            if expected is None:
                expected = seq
                if seq != 1:
                    prev = entry["prev"]
            if seq != expected:
                found.append(f"line {number}: seq {seq}, expected {expected}")
            expected = seq + 1
            cut = line.rindex(',"hash":"')
            if hashlib.sha256((line[:cut] + "}").encode("ascii")).hexdigest() != entry["hash"]:
                found.append(f"line {number}: hash does not match")
            if entry["prev"] != prev:
                found.append(f"line {number}: prev is not the hash before it")
            if entry["event"] == "checkpoint":
                if entry["head"] != prev:
                    found.append(f"line {number}: head is not the entry before it")
                if entry["key"] != fingerprint:
                    found.append(f"line {number}: signed by another key")
                message = DOMAIN + seq.to_bytes(8, "big") + bytes.fromhex(entry["head"])
                msg, sig = os.path.join(tmp, "msg"), os.path.join(tmp, "sig")
                with open(msg, "wb") as m:
                    m.write(message)
                with open(sig, "wb") as s:
                    s.write(bytes.fromhex(entry["signature"]))
                if entry["algorithm"] == "Ed25519":
                    command = ["openssl", "pkeyutl", "-verify", "-pubin", "-inkey", pem,
                               "-rawin", "-in", msg, "-sigfile", sig]
                else:
                    command = ["openssl", "dgst", "-sha256", "-verify", pem, "-signature", sig, msg]
                if subprocess.run(command, capture_output=True).returncode != 0:
                    found.append(f"line {number}: the signature does not hold")
            prev = entry["hash"]
    return found


def main(argv):
    if len(argv) != 3:
        print(__doc__)
        return 2
    found = problems(argv[1], argv[2])
    for problem in found:
        print(problem)
    print("holds" if not found else f"{len(found)} problem(s)")
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
