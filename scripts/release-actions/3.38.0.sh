# v3.38.0: Attack Surface and Phishing Hunt became one-time assessments. Result
# content (hosts, findings, snapshots) is no longer stored; the engine stopped
# writing those tables and results now live only in a short-lived cache plus the
# PDF. Purge any rows left by earlier versions, and null the stored summaries.
# Monitoring was removed from the public product, so purge snapshot rows too.
#
# Idempotent: each DELETE matches nothing on a second run, and the tables were
# created by the v3.37.0 ASM release so they are always present here.
fe_say "purging stored ASM result content for the one-time model (hosts, findings, snapshots)"
fe_sqlite "DELETE FROM asm_hosts;"
fe_sqlite "DELETE FROM asm_findings;"
fe_sqlite "DELETE FROM asm_snapshots;"
fe_sqlite "UPDATE asm_scans SET summary_json = NULL WHERE summary_json IS NOT NULL;"
