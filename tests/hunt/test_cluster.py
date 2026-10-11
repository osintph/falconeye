"""Campaign clustering: a theme group is a campaign only when corroborated (a
tight registration window plus a shared registrar, nameserver, ASN or cheap TLD)."""
from app.hunt import cluster


def _c(domain, themes, age=20, reg="2026-09-01", registrar="NameSilo", asn="AS1 Host",
       ns=None, cheap=True):
    return {"domain": domain, "themes": themes, "reg_age_days": age, "reg_date": reg,
            "registrar": registrar, "asn": asn, "ns": ns or ["ns1.host.net"], "cheap": cheap}


def test_corroborated_ncap_set_is_a_campaign():
    cands = [
        _c("mmda-ltoncap.icu", ["lto", "ncap"], age=20),
        _c("mmdaltoncaps.sbs", ["lto", "ncap"], age=30),
        _c("mmdancap-ncr.work", ["ncap", "ncr"], age=25),
        _c("ncapmmdar.club", ["ncap"], age=35),
        _c("mmda-ncaplto.xyz", ["ncap", "lto"], age=40),
    ]
    campaigns, related, dom_to_cid = cluster.build(cands)
    assert len(campaigns) == 1 and not related
    assert campaigns[0]["count"] == 5
    assert dom_to_cid["mmda-ltoncap.icu"] == campaigns[0]["id"]
    assert campaigns[0]["corroboration"]  # window + shared attribute listed


def test_wide_window_is_related_not_a_campaign():
    # Same theme, but registrations span many months: not a campaign, no boost.
    cands = [
        _c("philhealthportal.com", ["portal"], age=10, reg="2026-10-01"),
        _c("philhealthmembersportal.com", ["member", "portal"], age=200, reg="2026-03-01"),
        _c("philhealthregistration.com", ["portal", "registration"], age=340, reg="2025-11-07"),
    ]
    campaigns, related, dom_to_cid = cluster.build(cands)
    assert campaigns == [] and dom_to_cid == {}
    assert len(related) == 1 and related[0]["count"] == 3


def test_tight_window_but_no_shared_attribute_is_related():
    # Within the window, but no shared registrar/NS/ASN and not cheap TLDs.
    cands = [
        _c("mmda-ncap1.com", ["ncap"], age=10, registrar="R1", asn="AS10", ns=["a.com"], cheap=False),
        _c("mmda-ncap2.com", ["ncap"], age=20, registrar="R2", asn="AS20", ns=["b.com"], cheap=False),
        _c("mmda-ncap3.com", ["ncap"], age=30, registrar="R3", asn="AS30", ns=["c.com"], cheap=False),
    ]
    campaigns, related, dom_to_cid = cluster.build(cands)
    assert campaigns == [] and len(related) == 1


def test_below_threshold_is_neither():
    campaigns, related, dom_to_cid = cluster.build(
        [_c("mmda-ncap.icu", ["ncap"]), _c("mmda-lto.icu", ["lto"])])
    assert campaigns == [] and related == [] and dom_to_cid == {}


def test_infra_merge_pulls_in_a_shared_infra_domain():
    # nocpmmda.luxe has no theme term, but shares the campaign registrar, NS and
    # ASN inside the window, so it joins the NCAP campaign.
    members = [
        _c("mmda-ltoncap.icu", ["lto", "ncap"], age=20, registrar="NameMart",
           asn="AS132203", ns=["ns1.domainnamens.com"]),
        _c("mmdaltoncaps.sbs", ["lto", "ncap"], age=30, registrar="NameMart",
           asn="AS132203", ns=["ns1.domainnamens.com"]),
        _c("mmdancap-ncr.work", ["ncap", "ncr"], age=25, registrar="NameMart",
           asn="AS132203", ns=["ns1.domainnamens.com"]),
    ]
    loner = _c("nocpmmda.luxe", [], age=48, registrar="NameMart", asn="AS132203",
               ns=["ns1.domainnamens.com"])
    campaigns, related, dom_to_cid = cluster.build(members + [loner])
    assert len(campaigns) == 1
    assert "nocpmmda.luxe" in dom_to_cid
    assert loner.get("campaign_join", "").endswith("(infra match)")
