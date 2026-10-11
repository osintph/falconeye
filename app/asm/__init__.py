"""Attack Surface Management (v3.37.0).

ASM maps the internet-facing surface of a domain the requester has proven they
control, or any domain in operator mode for an authorized engagement. The rule
that governs everything here: no ASM output of any kind (discovery, findings,
exports, MCP) is returned for an unverified or blocked domain outside operator
mode.

Submodules:
  blocklist   free-mail providers, PSL private parents, and public suffixes
  cdn         published CDN/edge ranges, excluded from the port scan
  signing     itsdangerous serializers for grants, management links, sessions
  store       all ASM SQLite tables and their helpers
  verify      the ownership gate (DNS TXT and role-address email)
  operator    the master-key bypass (key + TOTP, short-lived session)
  discovery   passive discovery (CT logs, passive DNS, Wayback, RIPEstat)
  probe       light active probe (DNS, HTTP/TLS, tech fingerprint, mail posture)
  portscan    pure-Python asyncio TCP connect scan
  findings    takeover, cert, header, posture and exposure findings
  fingerprints  vendored subdomain-takeover fingerprint data
  jobs        the background scan runner (bounded concurrency plus a queue)
  report      summary and export shaping
  monitor     scheduled snapshots, diffs and retention

No em dashes anywhere in this package (a test enforces it).
"""
