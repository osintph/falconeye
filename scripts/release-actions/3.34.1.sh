# v3.34.1: the verdict gained an `infrastructure` block and OTX pulses stopped
# being a verdict on their own. Rows cached before the upgrade have neither, so
# a public resolver keeps rendering as MALICIOUS until its row expires.
#
# json_type() returns NULL only when the path is absent, which is what
# distinguishes an old row from a new row whose value is a JSON null.
fe_say "flushing IP cache rows computed under the old verdict rule"
fe_sqlite "DELETE FROM ip_intel_cache WHERE json_type(response_json, '\$.reputation.verdict.infrastructure') IS NULL;"
