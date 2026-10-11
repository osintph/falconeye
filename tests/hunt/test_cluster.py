"""Campaign clustering: candidates sharing a brand theme term form one campaign."""
from app.hunt import cluster


def _c(domain, themes, reg="2026-09-01", registrar="NameSilo", asn="AS000 Host"):
    return {"domain": domain, "themes": themes, "reg_date": reg,
            "registrar": registrar, "asn": asn}


def test_ncap_set_forms_one_campaign():
    cands = [
        _c("mmda-ltoncap.net", ["lto", "ncap"]),
        _c("mmdaltoncaps.com", ["lto", "ncap"]),
        _c("mmdancap-ncr.icu", ["ncap", "ncr"]),
        _c("ncapmmdar.com", ["ncap"]),
        _c("mmda-ncaplto.club", ["ncap", "lto"]),
        _c("unrelatedmember.com", ["member"]),  # a lone different theme, no cluster
    ]
    campaigns, dom_to_cid = cluster.build(cands)
    assert len(campaigns) == 1  # the NCAP cluster; the lone member theme does not cluster
    camp = campaigns[0]
    assert camp["count"] == 5
    assert "ncap" in camp["theme"] and "lto" in camp["theme"]
    for d in ("mmda-ltoncap.net", "ncapmmdar.com", "mmda-ncaplto.club"):
        assert dom_to_cid[d] == camp["id"]
    assert "unrelatedmember.com" not in dom_to_cid


def test_two_below_threshold_is_not_a_campaign():
    cands = [_c("mmda-lto.com", ["lto"]), _c("mmda-ltofine.com", ["lto", "fine"])]
    campaigns, dom_to_cid = cluster.build(cands)
    assert campaigns == [] and dom_to_cid == {}


def test_campaign_reports_window_and_tlds():
    cands = [_c("mmdancap1.icu", ["ncap"], reg="2026-08-10"),
             _c("mmdancap2.sbs", ["ncap"], reg="2026-09-20"),
             _c("mmdancap3.work", ["ncap"], reg="2026-10-01")]
    campaigns, _ = cluster.build(cands)
    assert len(campaigns) == 1
    c = campaigns[0]
    assert c["window"]["first"] == "2026-08-10" and c["window"]["last"] == "2026-10-01"
    assert set(c["tlds"]) == {"icu", "sbs", "work"}
