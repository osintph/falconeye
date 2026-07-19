"""
Post-process the raw CheckResult list into the API response shape:
filter to hits, group by category, tag confidence, and roll up stats.

Confidence: a hit present in BOTH engines (sources == wmn+sherlock) is "high";
a single-engine hit is "medium". This is the cross-validation signal that
motivated shipping dual-engine.
"""


def _confidence(sources: list) -> str:
    return "high" if ("wmn" in sources and "sherlock" in sources) else "medium"


def build_result(results: list, username: str, scope: str,
                 checked_count: int, unchecked_count: int,
                 duration_ms: int, extra_warnings: list | None = None) -> dict:
    hits = [r for r in results if r.hit]

    by_category: dict = {}
    dual_source_count = 0
    for r in hits:
        sources = list(r.site.sources)
        if "wmn" in sources and "sherlock" in sources:
            dual_source_count += 1
        by_category.setdefault(r.site.category, []).append({
            "site": r.site.name,
            "url": r.profile_url,
            "confidence": _confidence(sources),
            "sources": sources,
        })

    categories = []
    for name, items in by_category.items():
        # dual-source first, then alphabetical
        items.sort(key=lambda h: (0 if len(h["sources"]) > 1 else 1, h["site"].lower()))
        categories.append({"name": name, "hits": items, "count": len(items)})
    categories.sort(key=lambda c: (-c["count"], c["name"]))

    warnings = list(extra_warnings or [])
    warnings.append(
        "A hit means a profile exists at that platform, not that the same person "
        "owns all of them. Expect 5-10% false positives; verify each lead manually."
    )
    if unchecked_count:
        warnings.append(
            f"{unchecked_count} sites were not checked before the time budget was "
            f"reached. Re-run or use Quick Scan for faster, priority-ranked results."
        )

    return {
        "username": username,
        "scope": scope,
        "checked_count": checked_count,
        "hit_count": len(hits),
        "dual_source_count": dual_source_count,
        "duration_ms": duration_ms,
        "categories": categories,
        "warnings": warnings,
    }
