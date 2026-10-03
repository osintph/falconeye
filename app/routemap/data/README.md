# Route Map data files

Two bundled tables. Neither is queried over the network at runtime: the point of
both is that FalconEye can answer "where is this" without telling anyone else
what it is asking about.

## `cities.tsv`

GeoNames `cities15000` (every populated place above 15,000 people), trimmed to
seven columns and sorted by population descending. 34,152 rows.

Used for the origin picker's city search and as the one source of city
coordinates in the feature, including for `site_codes.tsv`.

**Licence: Creative Commons Attribution 4.0.** From
<https://download.geonames.org/export/dump/readme.txt>, checked 2026-10-03:
"This work is licensed under a Creative Commons Attribution 4.0 License, see
https://creativecommons.org/licenses/by/4.0/". Attribution is carried in the
file header, in the origin picker, in the page footer's data-source strip and
in the repository README. If you remove it from one of those, the other three
still satisfy the licence; do not remove it from all of them.

Columns: `name`, `asciiname`, `cc`, `admin1`, `lat`, `lon`, `population`.
`asciiname` is empty when it equals `name`; `admin1` is empty unless the
country uses an alphabetic subdivision code (so US and CA have one, PH does
not).

To refresh it, download `cities15000.zip` from the URL above and re-run the
trimming step documented in the CHANGELOG entry for v3.35.0.

## `site_codes.tsv`

The site code a carrier embeds in its own router hostnames, mapped to the city
that carrier says the site is in. This is the `site-code` geolocation source.

**Generated.** Do not hand-edit it. Run:

```bash
python3 tools/build_site_codes.py --dry-run   # show what would change
python3 tools/build_site_codes.py             # rewrite the table
```

Columns: `carrier`, `code`, `city`, `cc`, `lat`, `lon`, `source_ref`. The
`source_ref` ties each row to a source named in the file's own header.

### Why this table is narrow on purpose

A three-letter string in a hostname is not evidence. `lax` appears inside
"relaxed"; customer hostnames are full of city-ish fragments that mean nothing.
So the rule is never "this hostname contains a code", it is "this carrier, in
its own backbone namespace, names this site this way":

- A pattern applies only under that carrier's backbone zones, listed in
  `CARRIERS` in `app/routemap/sitecodes.py`.
- Customer-facing zones are excluded there. A customer interconnect is named
  after the customer, not the site: `plusline-ic-323934.ip.twelve99-cust.net`
  is Plus.line's interconnect, and reading `plusline` as a site code would be
  wrong.
- A code the carrier uses for two different cities is dropped at build time
  rather than guessed at. Arelion's `ewr` covers both New York City and
  Piscataway facilities, so there is no `ewr` row.
- A city the bundled GeoNames table cannot resolve is dropped and reported, not
  approximated. Arelion's Bettembourg PoP has no row for that reason.

A site-code location is still only a claim. It goes through the same RTT
physics bound as every other source in `app/routemap/geo.py`: if the hostname
says Hong Kong and the round trip cannot reach Hong Kong, the hop is not placed
in Hong Kong.

### Adding a carrier

1. Find the carrier's **own published** router list: a looking glass that names
   its nodes, an operator network page, PeeringDB facility data, or equivalent.
   A list you inferred from traceroutes you have seen is not a source. If you
   cannot point at a published mapping, the carrier does not go in the table.
2. Add an entry to `CARRIERS` in `tools/build_site_codes.py` with a `fetch()`
   returning `{router_name: "City (facility)"}`, a `code_of()` that turns a
   router name into its site code, and `source_ref` / `source_url` /
   `source_kind` describing where it came from.
3. Add the matching entry to `CARRIERS` in `app/routemap/sitecodes.py`, naming
   the backbone `suffixes` and any customer `exclude` zones.
4. Run the generator. Resolve or accept every line it prints under
   "NOT INCLUDED" before trusting the result.
5. Add a test case to `tests/unit/test_routemap_sitecodes.py`: at least one
   hostname that must resolve and one that must not.

Current sources:

| `source_ref` | Carrier | Source |
|---|---|---|
| `arelion-lg` | Arelion (AS1299, Twelve99) | Operator looking glass router list, <https://lg.twelve99.net/> |
