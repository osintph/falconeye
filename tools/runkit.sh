#!/usr/bin/env bash
# runkit.sh <host> <path>   e.g. ./runkit.sh jtexpress.mwkqbr.club /com/
# Fetch a kit's assets read-only and analyze. No JS execution.
set -uo pipefail
HOST="${1:?host}"; P="${2:-/}"
UA='Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1'
OUT="kit_${HOST//[^A-Za-z0-9]/_}_$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$OUT/assets" && cd "$OUT"

echo "[*] index"
curl -sk -A "$UA" -D headers.txt -o index.html "https://${HOST}${P}"
grep -iE '^(set-cookie|server|cf-ray|content-type):' headers.txt

echo "[*] assets"
grep -oE '(href|src)="[^"]+\.(js|css)"' index.html | sed -E 's/.*="//; s/"$//' | sort -u | tee assetlist.txt
while read -r a; do
  f=$(basename "$a")
  curl -sk -A "$UA" -H "Referer: https://${HOST}${P}" -o "assets/$f" "https://${HOST}${P}${a#./}"
done < assetlist.txt
sha256sum assets/* | tee hashes.txt

echo "[*] socket probe"
for s in /socket.io/ "${P}socket.io/" /ws/socket.io/; do
  printf '%-28s %s\n' "$s" "$(curl -s -o /dev/null -w '%{http_code}' -m 10 "https://${HOST}${s}?EIO=4&transport=polling")"
done
for c in /console "${P}console" /admin; do
  printf '%-28s %s\n' "$c" "$(curl -s -o /dev/null -w '%{http_code}' -m 10 "https://${HOST}${c}")"
done

echo "[*] rdap"
curl -sL "https://rdap.org/domain/$(echo "$HOST" | rev | cut -d. -f1,2 | rev)" -o rdap.json
python3 -c "import json;d=json.load(open('rdap.json'));print(json.dumps({'events':d.get('events'),'ns':[n['ldhName'] for n in d.get('nameservers',[])]},indent=2))" 2>/dev/null || head -c 200 rdap.json

echo "[*] analyze"
python3 ../kitanalyze.py --json report.json --strtab strtab --resolved resolved assets/*.js | tee analysis.txt
echo "[*] done -> $OUT"
