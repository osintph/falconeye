# Deep kit analysis

The Phishing Scanner tab's opt-in "Deep kit report" path. Given one URL it runs
the whole workflow end to end: fetch the live page, detect a client-rendered SPA
shell, pull the JS bundles, deobfuscate and tear down the kit chunk, probe the
operator relay path, pull RDAP, CT and urlscan, score against a kit signature,
and render one consolidated case report.

This is defensive tooling. It analyses phishing kits in order to detect, attribute
and file takedowns against them. It never executes kit code, never opens a socket
to a live operator panel, and never sends a frame.

## The one rule the engine exists to enforce

> Never grep the raw source of an obfuscated file and treat a miss as a finding.

Every identifier in a string-obfuscated bundle can sit behind a decoder call, so
`AES` or `localStorage` can be absent from the plaintext while being all over the
program. `kit_analyzer` therefore decodes the string table **first**, resolves
decoder call sites back into the source, normalizes bracket access
(`c["enc"]["Utf8"]["parse"]`) into dot access, and only then searches. That is
why the report has a separate "Not found" section: those misses are only
meaningful because resolution ran first.

## Modules

| Module | Responsibility |
|---|---|
| `app/scanner/kit_analyzer.py` | The engine. Kit-agnostic: string-table decode, decoder-call resolution, bracket-to-dot normalization, and the extractors. Knows nothing about any specific kit. |
| `app/scanner/rabbithunt_sig.py` | Signature records plus the transparent weighted scorer (`score_bundle`, `score_host`, `probe_socket`). |
| `app/scanner/kit_acquire.py` | Read-only acquisition. Every outbound request goes through `app/utils/safe_fetch`. |
| `app/scanner/kit_report.py` | Assembles the case report and runs the guarded enrichment. |

Endpoint: `POST /api/scanner/kit-report`, 4/minute per IP plus 10 per IP per
24 hours. It is far heavier than `/scan` (many outbound fetches plus a full
teardown), hence the daily budget on top of the burst limit.

## Adding a second kit

**Adding a kit means adding a signature record, never editing the analyzer.** If
you find yourself changing `kit_analyzer.py` to support a new kit, that logic
almost certainly belongs in the signature instead.

Add a record to `SIGNATURES` in `rabbithunt_sig.py`. A record is pure data:

- `crypto_pairs` — `{role, key, iv, mode, padding}`. Roles are what let the report
  label a recovered pair; without a signature the engine still finds the key
  material, it just cannot name the role.
- `storage_keys` — plaintext key names, so an MD5-hashed key in a live browser can
  be cracked back.
- `socket` — `{path, channels, transports}`.
- `hash_routes` — client-side routes. Never write a detection rule against these
  as URL paths; they are fragment routes and will match nothing server-side.
- `cjk_glossary` — developer debug strings and their English glosses. The engine
  extracts CJK strings generically; the glosses are per-kit data.
- `content_tokens` — `{name: (regex, weight)}`, the scored content signals.
- `aes_literals`, `session_cookie`, `operator_path`.

Scoring is deliberately transparent: every signal is returned with its weight and
whether it hit **or missed**, and the verdict is a percentage of achievable
points. Do not hide misses; a miss on a check that could have fired is evidence.
Verdict tiers: `>=70` STRONG MATCH, `40-69` PARTIAL, `20-39` WEAK, else NO MATCH.

## Writing extractors: the failure mode to avoid

Every extraction bug found so far has been the same class: **the extractor matched
a direct or unminified syntactic shape that a real bundler does not emit.** A
synthesized fixture written in the obvious shape passes while the real kit fails.

Real examples, all fixed:

- Channels registered through a kit's own dispatch wrapper
  (`function reg(n,m){...map.set(n,m)}`) rather than `socket.on(...)`.
- `socket.present` reporting false because the socket.io library markers live in
  a *different* chunk than the code configuring the socket.
- Key material bound to a variable before being parsed
  (`const k="...", x=enc.Utf8.parse(k)`) rather than parsed from a literal.
- A hash-router gate keyed on `createWebHashHistory`, which minification deletes.
  What survives is the router's `/^[^#]+#/` regex literal, because a regex literal
  cannot be renamed.

So: **test new extractors against a real bundle, not only the fixture**, and when
you fix one, make the fixture representative of the real shape so it cannot
regress silently. `tests/scanner/kit_fixtures.py` carries comments marking which
shapes are deliberately awkward and must not be "simplified".

## Tests

- `tests/scanner/test_kit_analyzer.py`, `test_rabbithunt_sig.py`,
  `test_kit_report.py` run everywhere, against a synthesized obfuscated fixture.
- `tests/scanner/test_real_bundles.py` scores **real** kit bundles and asserts
  their sha256 first, so a swapped or truncated file fails loudly. Those bundles
  are live phishing kit source and are deliberately **not** committed. Point the
  tests at a local copy:

  ```
  export FALCONEYE_KIT_BUNDLES=/path/to/bundles
  pytest tests/scanner/test_real_bundles.py
  ```

  Without them the 9 tests skip, so CI stays green.

## CLI tools

`tools/` holds the standalone reference scripts the tab's engine was ported from.
They are not imported by the app.

| Tool | Use |
|---|---|
| `tools/kitanalyze.py` | Full deobfuscator with `--json`, `--strtab`, `--resolved`, `--crack`. |
| `tools/runkit.sh` | Reference acquisition sequence. Uses raw `curl`; the web path uses `safe_fetch` instead. |
| `tools/decode_kit.py` | Minimal string-table decoder. |
| `tools/kitdecrypt.py` | Decrypts captured kit blobs. Needs `cryptography`, which is **not** an app dependency. |

`kitdecrypt.py` is **CLI only and stays that way.** Decrypting captured exfil
needs operator judgement about what traffic is lawful and safe to touch. The
report states the keys it recovered; it does not offer a decrypt-a-blob box.
Revisit only as a separate, deliberate decision.

## Safety properties worth preserving

- Every outbound request goes through `safe_fetch`. A target the SSRF guard
  refuses is refused outright: nothing else touches it, no probe, no bundle fetch,
  no registry or urlscan lookup.
- The relay probe reads HTTP status codes only. It does not open a socket. An
  earlier reference implementation opened a raw TLS socket for a WebSocket
  upgrade handshake; that was deliberately **not** carried over, because it
  bypasses the SSRF guard.
- Every value rendered in the tab is escaped. Kit source, decoded strings,
  response headers, RDAP and CT fields are all attacker-controlled.
- Neither raw bundle text nor raw page HTML reaches the LLM. The optional Haiku
  summary receives an allowlisted structural view of the report only.
- Bundle analysis is cached by bundle sha256. Host enrichment and the live probe
  are deliberately **not** cached with it, because the same kit turns up on new
  hosts and serving one host's live results for another would be worse than a
  cache miss.
- Input caps live in `app/config.py` (`KIT_MAX_BUNDLE_BYTES`,
  `KIT_MAX_RESOLVE_BYTES`, `KIT_MAX_ASSETS`). Note `safe_fetch` buffers a whole
  response before returning it, so those caps stop an oversized bundle reaching
  the analyzer but do not stop it being downloaded.

## Known imprecision

The channel list can include a non-socket event bus. On the reference kit it
reports `config, operation, validate`, where `validate` is a Vue form-validation
handler registered with `.on("validate", ...)`. Separating the two would require
knowing which object is the socket, which is not generically decidable, and it
does not affect scoring because the signature check is a subset test.
