"""Campaign clustering: a theme group is a campaign only when corroborated (a
tight registration window plus a shared registrar, nameserver, ASN or cheap TLD).
Clustering keys on the lure family, not the single term."""
from app.hunt import cluster, themes


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


def test_cdn_asn_alone_does_not_corroborate():
    # A shared Cloudflare ASN is not distinctive: different registrars and NS, not
    # cheap TLDs, only the CDN in common means no campaign.
    cands = [
        _c("mmda-ncap1.com", ["ncap"], age=10, registrar="R1", asn="AS13335",
           ns=["a.com"], cheap=False),
        _c("mmda-ncap2.org", ["ncap"], age=20, registrar="R2", asn="13335",
           ns=["b.com"], cheap=False),
        _c("mmda-ncap3.net", ["ncap"], age=30, registrar="R3", asn="13335",
           ns=["c.com"], cheap=False),
    ]
    campaigns, related, _ = cluster.build(cands)
    assert campaigns == [] and len(related) == 1


def test_shared_infra_does_not_recruit_a_themeless_member():
    # Campaign membership requires a lure-family match. A themeless brand lookalike
    # on the SAME operator nameserver as the campaign is NOT recruited by that
    # shared infrastructure; it is scored on its own.
    members = [
        _c("mmda-ltoncap.icu", ["lto", "ncap"], age=20, registrar="NameMart",
           asn="AS9999 Op", ns=["ns1.operatordns.net"]),
        _c("mmdaltoncaps.sbs", ["lto", "ncap"], age=30, registrar="NameMart",
           asn="AS9999 Op", ns=["ns1.operatordns.net"]),
        _c("mmdancap-ncr.work", ["ncap", "ncr"], age=25, registrar="NameMart",
           asn="AS9999 Op", ns=["ns1.operatordns.net"]),
    ]
    themeless = _c("mmda-tracker.luxe", [], age=48, registrar="NameMart", asn="AS9999 Op",
                   ns=["ns1.operatordns.net"])
    campaigns, related, dom_to_cid = cluster.build(members + [themeless])
    assert len(campaigns) == 1
    assert "mmda-tracker.luxe" not in dom_to_cid  # shared infra alone never recruits it


def test_themed_variant_member_joins_via_family():
    # A domain whose theme is only a maintained variant (nocp ~ ncap) still joins
    # the campaign, because it IS a lure-family match (not an infra recruit).
    members = [
        _mk("mmda-ltoncap.icu", ["lto", "ncap"], age=20, registrar="NameMart Pte. Ltd.",
            ns=["ns1.operatordns.net"], asn="AS9999 Op"),
        _mk("mmdaltoncaps.sbs", ["lto", "ncap"], age=30, registrar="NameMart Pte. Ltd.",
            ns=["ns1.operatordns.net"], asn="AS9999 Op"),
        _mk("nocpmmda.luxe", ["ncap"], age=25, registrar="NameMart Pte. Ltd.",
            ns=["ns1.operatordns.net"], asn="AS9999 Op"),
    ]
    campaigns, related, dom_to_cid = cluster.build(members)
    assert len(campaigns) == 1
    assert dom_to_cid.get("nocpmmda.luxe") == campaigns[0]["id"]


def test_generic_infra_does_not_pull_in_a_themeless_domain():
    # NameSilo/NameMart (large registrar), domainnamens.com (registrar default NS)
    # and Tencent ASN 132203 (large cloud) are shared by millions of unrelated
    # domains, so a themeless lookalike sharing only these is NOT merged. The themed
    # set still corroborates on window plus cheap-TLD family.
    members = [
        _c("mmda-ltoncap.icu", ["lto", "ncap"], age=20, registrar="NameSilo, LLC",
           asn="AS132203", ns=["ns1.domainnamens.com"]),
        _c("mmdaltoncaps.sbs", ["lto", "ncap"], age=30, registrar="NameSilo, LLC",
           asn="AS132203", ns=["ns2.domainnamens.com"]),
        _c("mmdancap-ncr.work", ["ncap", "ncr"], age=25, registrar="NameSilo, LLC",
           asn="AS132203", ns=["ns1.domainnamens.com"]),
    ]
    loner = _c("mmda.in", [], age=40, registrar="NameSilo, LLC", asn="AS13335",
               ns=["ava.ns.cloudflare.com"], cheap=False)
    campaigns, related, dom_to_cid = cluster.build(members + [loner])
    assert len(campaigns) == 1
    assert "mmda.in" not in dom_to_cid
    assert "campaign_join" not in loner


def test_large_registrar_needs_a_second_attribute_to_corroborate():
    # A shared very large registrar (NameSilo) with only generic NS and cloud ASN,
    # no cheap TLDs, is not enough: the group is related, not a campaign.
    members = [
        _c("philhealthbenepisyo.com", ["member", "benepisyo"], age=10, registrar="NameSilo, LLC",
           asn="AS13335", ns=["kip.ns.cloudflare.com"], cheap=False),
        _c("philhealthtulong.com", ["member", "tulong"], age=20, registrar="NameSilo, LLC",
           asn="AS13335", ns=["kip.ns.cloudflare.com"], cheap=False),
        _c("philhealthmiyembro.com", ["member", "miyembro"], age=30, registrar="NameSilo, LLC",
           asn="AS13335", ns=["kip.ns.cloudflare.com"], cheap=False),
    ]
    campaigns, related, dom_to_cid = cluster.build(members)
    assert campaigns == [] and len(related) == 1


def _mk(dom, terms, **kw):
    c = _c(dom, terms, **kw)
    c["families"] = themes.families_of("mmda", terms)
    return c


def test_lure_family_clusters_terms_that_differ():
    # mmda-mayhuliks (huli, mayhuli) and the ncap/lto domains share NO single term
    # but all belong to the traffic-fines lure family, so they cluster as one
    # campaign once the corroboration gate passes (window + distinctive NS here).
    members = [
        _mk("mmdancap.ltd", ["ncap"], age=20, registrar="NameMart Pte. Ltd.",
            ns=["ns1.operatordns.net"], asn="AS9999 Op"),
        _mk("mmda-ltoncap.icu", ["lto", "ncap"], age=25, registrar="NameMart Pte. Ltd.",
            ns=["ns1.operatordns.net"], asn="AS9999 Op"),
        _mk("mmdancap-ncr.sbs", ["ncap", "ncr"], age=30, registrar="NameMart Pte. Ltd.",
            ns=["ns1.operatordns.net"], asn="AS9999 Op"),
        _mk("mmda-mayhuliks.com", ["huli", "mayhuli"], age=40, registrar="NameMart Pte. Ltd.",
            ns=["ns1.operatordns.net"], asn="AS9999 Op"),
    ]
    campaigns, related, dom_to_cid = cluster.build(members)
    assert len(campaigns) == 1
    assert dom_to_cid.get("mmda-mayhuliks.com") == campaigns[0]["id"]


def test_campaign_survives_a_few_out_of_window_outliers():
    # Clustering on a lure family builds a larger, realistic set whose full span
    # can exceed the window. A tight burst holding the majority still corroborates;
    # the older outliers remain members.
    members = [_mk("mmdancap%d.icu" % i, ["ncap"], age=10 + i,
                   registrar="NameMart Pte. Ltd.", ns=["ns1.operatordns.net"],
                   asn="AS9999 Op") for i in range(5)]
    members.append(_mk("mmda-mayhuliks.com", ["mayhuli"], age=200,
                       registrar="NameMart Pte. Ltd.", ns=["ns1.operatordns.net"],
                       asn="AS9999 Op"))
    campaigns, related, dom_to_cid = cluster.build(members)
    assert len(campaigns) == 1
    assert "mmda-mayhuliks.com" in dom_to_cid  # the 200-day outlier is still a member
    assert any("burst" in r for r in campaigns[0]["corroboration"])


def test_generic_consumer_hosting_does_not_corroborate():
    # The PhilHealth case: a tight burst that shares only Namecheap shared hosting
    # (namecheaphosting.com nameservers, ASN 22612) and the Spaceship / Namecheap
    # registrars. All of that is generic consumer hosting, so it is a related group,
    # not a campaign, and nothing is boosted.
    members = [
        _c("philhealthbenefit.com", ["benefit"], age=10, reg="2026-09-20",
           registrar="NameCheap, Inc.", ns=["dns1.namecheaphosting.com"], asn="AS22612",
           cheap=False),
        _c("philhealthclaim.com", ["benefit", "claim"], age=20, reg="2026-09-10",
           registrar="Spaceship, Inc.", ns=["dns2.namecheaphosting.com"], asn="AS22612",
           cheap=False),
        _c("philhealthrefund.com", ["benefit", "refund"], age=30, reg="2026-08-31",
           registrar="NameCheap, Inc.", ns=["dns1.namecheaphosting.com"], asn="AS22612",
           cheap=False),
    ]
    campaigns, related, dom_to_cid = cluster.build(members)
    assert campaigns == [] and dom_to_cid == {}
    assert len(related) == 1


def test_outlier_sharing_registrar_and_nameserver_joins():
    # An out-of-burst member that still shares a distinctive attribute (registrar
    # plus non-generic nameserver) with the burst joins the campaign.
    burst = [_mk("mmdancap%d.icu" % i, ["ncap"], age=5 + i, registrar="NameMart Pte. Ltd.",
                 ns=["ns1.operatordns.net"], asn="AS9999 Op") for i in range(4)]
    outlier = _mk("mmda-oldhuli.com", ["huli", "mayhuli"], age=240,
                  registrar="NameMart Pte. Ltd.", ns=["ns1.operatordns.net"], asn="AS9999 Op")
    campaigns, related, dom_to_cid = cluster.build(burst + [outlier])
    assert len(campaigns) == 1
    assert dom_to_cid.get("mmda-oldhuli.com") == campaigns[0]["id"]
    assert not campaigns[0].get("outliers_related")
    assert "nameserver" in outlier.get("campaign_join", "")


def test_outlier_without_distinctive_overlap_is_related_outside_burst():
    # An out-of-burst member on a different registrar, a CDN nameserver and a cloud
    # ASN, with no favicon or page content, shares nothing distinctive: it is listed
    # as related outside the burst and scored on its own, not in the campaign.
    burst = [_mk("mmdancap%d.icu" % i, ["ncap"], age=5 + i, registrar="NameMart Pte. Ltd.",
                 ns=["ns1.operatordns.net"], asn="AS9999 Op") for i in range(4)]
    outlier = _mk("mmda-lonehuli.com", ["huli"], age=300, registrar="NameSilo, LLC",
                  ns=["kip.ns.cloudflare.com"], asn="AS13335")
    outlier["favicon_hash"], outlier["title"] = None, ""
    campaigns, related, dom_to_cid = cluster.build(burst + [outlier])
    assert len(campaigns) == 1
    assert "mmda-lonehuli.com" not in dom_to_cid
    assert "mmda-lonehuli.com" in {o["domain"] for o in campaigns[0]["outliers_related"]}


def test_lure_family_of_old_informational_sites_is_not_a_campaign():
    # Old informational PhilHealth name-matches in the membership family, registered
    # months apart with no shared distinctive infrastructure: a related group, never
    # a campaign, so lure-family clustering cannot boost informational sites.
    def mkp(dom, terms, age, reg):
        c = _c(dom, terms, age=age, reg=reg, registrar="GoDaddy.com, LLC",
               ns=["ns1.domaincontrol.com"], asn="AS13335", cheap=False)
        c["families"] = themes.families_of("philhealth", terms)
        return c
    members = [
        mkp("aboutphilhealth.org", ["member"], 400, "2025-09-07"),
        mkp("philhealthregistration.net", ["registration", "member"], 700, "2024-11-11"),
        mkp("philhealthmemberportal.com", ["portal", "member"], 1000, "2024-01-16"),
    ]
    campaigns, related, dom_to_cid = cluster.build(members)
    assert campaigns == [] and dom_to_cid == {}
    assert len(related) == 1 and related[0]["count"] == 3


def test_campaign_groups_members_by_registrar_with_abuse_email():
    def mk(dom, terms, registrar, abuse=None, **kw):
        c = _mk(dom, terms, registrar=registrar, ns=["ns1.operatordns.net"],
                asn="AS9999 Op", **kw)
        c["abuse_contact"] = abuse
        return c
    members = [
        mk("mmdancap.ltd", ["ncap"], "NameMart Pte. Ltd.", "abuse@namemart.example", age=20),
        mk("mmda-ltoncap.icu", ["lto", "ncap"], "NameSilo, LLC", "abuse@namesilo.com", age=25),
        mk("mmdancap-ncr.sbs", ["ncap", "ncr"], "NameMart Pte. Ltd.", None, age=30),
    ]
    campaigns, _r, _c2 = cluster.build(members)
    assert len(campaigns) == 1
    groups = {g["registrar"]: g for g in campaigns[0]["registrar_groups"]}
    assert set(groups) == {"NameMart Pte. Ltd.", "NameSilo, LLC"}
    assert groups["NameMart Pte. Ltd."]["abuse"] == "abuse@namemart.example"
    assert groups["NameMart Pte. Ltd."]["domains"] == ["mmdancap-ncr.sbs", "mmdancap.ltd"]
    assert groups["NameSilo, LLC"]["domains"] == ["mmda-ltoncap.icu"]


def test_campaign_carries_per_domain_registrar_from_rdap():
    # The campaign reports each member's own registrar and date, not one inferred
    # value, so a mixed NameMart / NameSilo campaign shows both.
    members = [
        _c("mmda-ltoncap.icu", ["lto", "ncap"], age=20, reg="2026-09-21",
           registrar="NameMart Pte. Ltd.", ns=["ns1.operatordns.net"], asn="AS9999 Op"),
        _c("mmdaltoncaps.sbs", ["lto", "ncap"], age=30, reg="2026-09-11",
           registrar="NameSilo, LLC", ns=["ns1.operatordns.net"], asn="AS9999 Op"),
        _c("mmdancap-ncr.work", ["ncap", "ncr"], age=25, reg="2026-09-16",
           registrar="NameMart Pte. Ltd.", ns=["ns1.operatordns.net"], asn="AS9999 Op"),
    ]
    campaigns, _related, _c2 = cluster.build(members)
    assert len(campaigns) == 1
    rows = {r["domain"]: r for r in campaigns[0]["member_rows"]}
    assert rows["mmda-ltoncap.icu"]["registrar"] == "NameMart Pte. Ltd."
    assert rows["mmdaltoncaps.sbs"]["registrar"] == "NameSilo, LLC"
    assert rows["mmda-ltoncap.icu"]["reg_date"] == "2026-09-21"
    # both distinct registrars are listed in the summary
    assert set(campaigns[0]["registrars"]) == {"NameMart Pte. Ltd.", "NameSilo, LLC"}
