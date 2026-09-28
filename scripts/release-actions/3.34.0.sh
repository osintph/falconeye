# v3.34.0: Censys left the reputation consensus, so the verdict is computed over
# four sources instead of five. Rows cached before the upgrade carry the old
# shape ("4 of 5 reputation sources responded", sources_total = 5) and would be
# served for the rest of their six hour TTL.
#
# Idempotent: a DELETE that matches nothing on a second run.
fe_say "flushing IP cache rows computed over five reputation sources"
fe_sqlite "DELETE FROM ip_intel_cache WHERE json_extract(response_json, '\$.reputation.verdict.sources_total') = 5;"
