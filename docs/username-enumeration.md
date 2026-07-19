# Username Enumeration

FalconEye v3.8.0 adds a Username tab: given a handle, it checks where that
username has a profile across ~950 platforms and returns the hits as leads for
human verification.

## Overview

Every other FalconEye tab operates on infrastructure (domains, IPs, headers).
Username Enumeration operates on identity. A scammer's Telegram handle may also
appear on a GitHub account whose commit history carries a real name; a BEC
actor's forum handle may match a decade-old profile elsewhere.

**What a hit means:** the username has a profile at that platform.
**What a hit does NOT mean:** that the same person owns every matching profile.
Common handles collide. Treat every hit as a lead to verify, never as proof of
identity — and never use this tab for stalking or harassment.

## Data sources

Two projects, both MIT-licensed, both **vendored** as static JSON under
`app/data/` — FalconEye does not depend on either project's runtime code, it
reads the data and runs its own checker.

- **WhatsMyName** (WebBreacher) — ~700 sites, strong forum / dev / niche coverage.
- **Sherlock** (sherlock-project) — ~480 sites, overlaps on majors, adds some
  regional and newer platforms.

The two lists are merged and deduplicated by host. Refresh cadence is at
operator discretion; see "Data refresh procedure" below.

## Confidence tiers

- **high** — the site was found in **both** WhatsMyName and Sherlock. The
  cross-validation makes a false positive less likely.
- **medium** — the site came from a single engine.

Confidence is about *engine agreement on the detection method*, not about whether
the profile truly belongs to your subject. A high-confidence hit can still be a
coincidental handle collision. Verify.

## False positive expectations

Expect **5-10% false positives**. Two common causes:

1. Platforms that return HTTP 200 (and a generic page) for *any* username.
2. Bot-detection pages served in place of a real profile.

Mitigate by clicking through the profile link and confirming the page is a real
account for that handle. The scan surfaces leads; you do the verification.

## Rate limits

A single scan makes 280-950 outbound HTTP requests, so scans are a genuine load
event on the VPS, not a soft policy. Limits (enforced before any request is
made):

| Scope | Limit |
|---|---|
| Per client IP | 3 scans/hour, 20 scans/day |
| Global | 100 scans/day |

Scopes: **Quick** checks the ~280 highest-priority sites (majors + mid-tier
developer/gaming/forum) in ~20s; **Full** checks all sites. The whole scan runs
under one wall-clock budget so it can never exceed the web-server worker timeout
— a Full scan that runs long returns partial results with a warning naming how
many sites were not reached.

## Ethical use

This tool is for authorized OSINT, security research, and investigative
journalism. Using it to stalk, harass, dox, or surveil an individual is an abuse
of it. A username match is not consent and not proof. Verify leads, respect
privacy, and follow the law in your jurisdiction.

## Data refresh procedure

The vendored files drift as upstream adds/removes sites. To refresh:

```bash
cd /opt/falconeye/app_src
/opt/falconeye/venv/bin/python scripts/refresh_username_data.py
```

The script fetches both upstreams, validates the shape and a minimum site count,
and only overwrites a vendored file if validation passes — a bad fetch leaves the
existing file untouched. It prints the new counts. After a refresh, restart the
service so the new data loads:

```bash
sudo systemctl restart falconeye
```

Suggested cadence: every 4-6 weeks, or before a release. If Sherlock's upstream
path moves and its fetch fails, the tab keeps working on WhatsMyName data alone.
