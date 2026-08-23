import re, base64, json, sys
CUS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/="
STD = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
T = str.maketrans(CUS, STD)
def dec(x):
    t = x.translate(T); t += "=" * (-len(t) % 4)
    try: return base64.b64decode(t).decode('utf-8')
    except Exception: return None
path = sys.argv[1]
s = open(path).read()
cands = list(re.finditer(r'\[\s*(?:"(?:[^"\\]|\\.)*"\s*,\s*){20,}"(?:[^"\\]|\\.)*"\s*\]', s))
if not cands:
    print("no string table in", path); sys.exit(0)
arr = json.loads(max(cands, key=lambda m: len(m.group(0))).group(0))
out = [dec(a) for a in arr]
name = path + ".strtab.txt"
with open(name, 'w') as f:
    for i, v in enumerate(out):
        f.write("%4d\t%s\n" % (i, (v or "<undecoded>").replace("\n", "\\n")))
print(path, "entries:", len(arr), "->", name)
pats = {
 'hosts': r'https?://|[a-z0-9-]+\.(com|net|org|club|top|cyou|icu|vip|xyz|shop|online|site)\b',
 'paths': r'^/[a-z0-9]|/api|/submit|/order|/pay|/collect|\.php|\.json',
 'payment': r'card|cvv|expir|otp|pin|gcash|maya|bpi|bdo|unionbank|visa|master',
 'net': r'axios|XMLHttpRequest|POST|Content-Type|Authorization|token|websocket|wss?://',
}
for label, p in pats.items():
    r = re.compile(p, re.I)
    print("\n== " + label)
    for i, v in enumerate(out):
        if v and r.search(v) and not v.startswith('data:'):
            print("%4d  %s" % (i, v[:180].replace("\n", "\\n")))
