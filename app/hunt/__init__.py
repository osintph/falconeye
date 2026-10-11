"""Phishing Domain Hunt (v3.38.0).

Public and ungated: it hunts attacker infrastructure impersonating a brand, so it
is not behind the ASM ownership gate. Discovery from certificate transparency
(crt.sh keyword search), permutations (dnstwist), urlscan keyword search, and an
optional newly-registered-domain feed. Each candidate gets DNS, RDAP, ASN, a cert
freshness check and exactly one HTTP GET through safe_fetch. No port scans, no
crawling. Results are one-time and delivered as a PDF. No em dashes in this
package.
"""
