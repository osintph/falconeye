"""Ground-truth evaluation set.

Recorded, offline fixtures for every domain we have reasoned about, each with its
expected outcome (a verdict, or "irrelevant" when relevance drops it) and campaign
membership. This test runs the full relevance, clustering and scoring pipeline over
the set and FAILS on any change in outcome or campaign membership, printing a diff.
Every Hunt change must keep it green; expected labels change only with the owner's
approval, recorded in the release notes.

It also prints precision and recall (positive class: Likely Phishing). Run with
-s to see the numbers on success.
"""
import json
import pathlib

from app.hunt import cluster, score, themes

_DATA = pathlib.Path(__file__).parent / "groundtruth" / "records.json"

_DEFAULT = {
    "resolves": True, "fetched": False, "has_mx": False, "reg_age_days": None,
    "reg_date": None, "registrar": None, "ns": [], "asn": None, "ip": None,
    "favicon_hash": None, "title": "", "page_class": "", "has_cred_form": False,
    "has_payment_form": False, "parked": False, "themes": [], "ct_first_seen_age": None,
    "urlscan": None, "cloudflare": False, "brand_markers": 0, "legit_title_sim": 0,
    "known_bad": False,
}


def _load():
    return json.loads(_DATA.read_text())["entries"]


def _record(entry):
    rec = dict(_DEFAULT)
    rec.update(entry.get("rec") or {})
    rec["domain"] = entry["domain"]
    rec["families"] = themes.families_of(entry["keyword"], rec.get("themes") or [])
    rec["cheap"] = themes.cheap_tld(entry["domain"])  # as the engine sets it
    return rec


def _run_pipeline(entries):
    """Returns {domain: (verdict_or_'irrelevant', in_campaign)} over the whole set,
    running relevance, then clustering and scoring per hunt group."""
    out = {}
    scored_entries = []
    for e in entries:
        if e["outcome"] == "irrelevant":
            rel = themes.classify(e["domain"], e["keyword"])["relevant"]
            out[e["domain"]] = ("irrelevant" if not rel else "RELEVANT", False)
        else:
            scored_entries.append(e)
    # Cluster and score per (group) so each hunt is evaluated on its own.
    by_group = {}
    for e in scored_entries:
        by_group.setdefault(e["group"], []).append(e)
    for group, items in by_group.items():
        recs = {e["domain"]: _record(e) for e in items}
        keyword = items[0]["keyword"]
        legit = items[0]["legit"]
        campaigns, _related, dom_to_cid = cluster.build(list(recs.values()))
        for e in items:
            rec = recs[e["domain"]]
            rec["campaign_member"] = rec["domain"] in dom_to_cid
            rec["campaign_id"] = dom_to_cid.get(rec["domain"])
            scored = score.score_candidate(rec, keyword, legit)
            out[e["domain"]] = (scored["verdict"], bool(rec["domain"] in dom_to_cid))
    return out


def test_groundtruth_set_is_unchanged(capsys):
    entries = _load()
    got = _run_pipeline(entries)
    diffs = []
    for e in entries:
        exp_verdict = e["outcome"]
        exp_campaign = bool(e.get("campaign", False))
        got_verdict, got_campaign = got[e["domain"]]
        if got_verdict != exp_verdict or (exp_verdict != "irrelevant" and got_campaign != exp_campaign):
            diffs.append((e["domain"], exp_verdict, exp_campaign, got_verdict, got_campaign))

    # Precision and recall, positive class = Likely Phishing (ignore irrelevant).
    tp = fp = fn = tn = 0
    for e in entries:
        if e["outcome"] == "irrelevant":
            continue
        exp_pos = e["outcome"] == "likely phishing"
        got_pos = got[e["domain"]][0] == "likely phishing"
        tp += exp_pos and got_pos
        fp += (not exp_pos) and got_pos
        fn += exp_pos and (not got_pos)
        tn += (not exp_pos) and (not got_pos)
    precision = tp / (tp + fp) if (tp + fp) else 1.0
    recall = tp / (tp + fn) if (tp + fn) else 1.0
    print(f"\nground-truth: {len(entries)} domains, "
          f"{sum(1 for e in entries if e['outcome'] != 'irrelevant')} scored, "
          f"{sum(1 for e in entries if e['outcome'] == 'irrelevant')} relevance-dropped")
    print(f"Likely Phishing: TP={tp} FP={fp} FN={fn} TN={tn} "
          f"precision={precision:.3f} recall={recall:.3f}")

    if diffs:
        lines = ["", "GROUND-TRUTH DIFF (domain: expected -> got):"]
        for dom, ev, ec, gv, gc in diffs:
            lines.append(f"  {dom:34} expected {ev!r} campaign={ec}  GOT {gv!r} campaign={gc}")
        with capsys.disabled():
            print("\n".join(lines))
        raise AssertionError(f"{len(diffs)} ground-truth outcome(s) changed; see diff above")
