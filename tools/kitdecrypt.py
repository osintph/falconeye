#!/usr/bin/env python3
"""Decrypt Paper Rabbit kit blobs. Both hardcoded AES-128-CBC contexts."""
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import base64, sys

CTX = {
    "storage":   (b"NLFRWBHXVQJTCPYK", b"DMAGSZEIOPQUNTVC"),
    "transport": (b"ZQMWLSPXJRDHKTNV", b"YFBCUENAGPQLXJWR"),
}

def dec(b64, key, iv):
    ct = base64.b64decode(b64 + "=" * (-len(b64) % 4))
    d = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    pt = d.update(ct) + d.finalize()
    return pt[:-pt[-1]] if 1 <= pt[-1] <= 16 else pt

def main():
    if len(sys.argv) > 1:
        vals = sys.argv[1:]
    else:
        vals = [l.strip() for l in sys.stdin if l.strip()]
    for v in vals:
        print("=" * 60)
        print("input:", v[:60] + ("..." if len(v) > 60 else ""))
        for name, (k, iv) in CTX.items():
            try:
                out = dec(v, k, iv).decode("utf-8")
                print("[%-9s] %s" % (name, out))
            except Exception as e:
                print("[%-9s] no (%s)" % (name, type(e).__name__))

if __name__ == "__main__":
    main()
