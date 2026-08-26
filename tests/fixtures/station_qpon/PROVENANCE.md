# station.qpon evidence capture

Captured 2026-08-26, roughly 06:03 UTC, from a Philippine residential
connection. Nothing is scrubbed. These are the response bodies exactly as
served.

This is the case that produced the target-host bug: the deep kit report was
given `https://station.qpon/`, followed the cloaking redirect, and produced a
full case report describing `www.petron.com` instead.

## What the target does

The host serves two different things depending on what the request looks like.

| file | request profile | status | final URL | bytes |
|------|-----------------|--------|-----------|-------|
| `body_bare.html` / `headers_bare.txt` | curl default UA | 302 then 200 | `https://www.petron.com/` | 234607 |
| `body_browser.html` / `headers_browser.txt` | mobile Safari UA | 200 | `https://station.qpon/` | 4314 |
| `entry_index-5ac4d3e6761.js` | mobile Safari UA | 200 | `https://station.qpon/p/1a26/index-5ac4d3e6761.js` | 588713 |

The 302 is served by `GoFrame HTTP Server` behind `via: 1.1 Caddy` with
`location: https://www.petron.com`. `body_bare.html` is therefore not the
target at all, it is Petron's real WordPress homepage behind Sucuri, fetched
because the redirect was followed.

`body_browser.html` is the actual kit: a Vite 5.8.6 SPA shell carrying
`<title>Home - Petron</title>` and randomized class names (`skin-t4c88`,
`frame-1w0u1f`, `token-kxrj`).

## Cloaking discriminators, tested

- User-Agent alone decides. A browser-like UA, mobile or desktop, reaches the
  kit. A curl UA is bounced.
- `Referer` and `Accept-Language` make no difference on their own.
- Source IP is a second, independent discriminator. From the production VPS
  (an OVH datacenter address) the request is bounced to petron.com regardless
  of User-Agent, including with the scanner's own iPhone `KIT_UA`. The 234603
  byte body recorded in the original bad report is that bounce.

The practical consequence: the dual-profile fetch recovers the kit from
residential egress but not from the VPS, so in production the out-of-scope
report path is what renders.

## sha256

```
0af0ce6e279c9c4b0258ea69a7a86767278f38f3161a1175599287cb4fa05e4d  body_bare.html
9e7797286eb31c54fa1ba4d243f1baa1e4a61d906f9e7f12395c58da752aa015  body_browser.html
7d4658eacb3efa530ce95910c36a1cfc4976cee46e9b73d0fe9347e7c85b193f  entry_index-5ac4d3e6761.js
```

## Registration

RDAP on 2026-08-26 returned registration `2026-08-26 04:24 UTC` via
NameMart Pte. Ltd., nameservers `ns1.domainnamens.com` and
`ns2.domainnamens.com`. The domain was hours old when this was captured, and
the kit's own `last-modified` was `04:14:20` the same morning.

## What is committed, and what is not

`body_bare.html` and `entry_index-5ac4d3e6761.js` are **not** committed. See the
`.gitignore` in this directory.

- The entry bundle is live phishing kit source. `docs/kit-analysis.md` already
  documents that convention for `tests/scanner/test_real_bundles.py`, and this
  follows it.
- The bare-profile body is the impersonated brand's own homepage, fetched only
  because the kit redirected there. Keeping it locally is evidence. Republishing
  an uninvolved company's site in a public repo, in the very release that exists
  to stop treating them as part of this case, is not.

Both are preserved on the operator's machine. `tests/scanner/test_kit_scope.py`
uses `body_bare.html` when it is present and a small synthetic Petron-branded
stand-in when it is not, so the tests assert the same thing either way and never
silently skip.

The committed files are the kit's own 4KB shell, the response headers for every
capture, and this record.
