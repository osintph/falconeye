"""Render an Attack Surface or Phishing Hunt report to a PDF file.

render_report(payload, out_path) is the only entry point. The payload is the
same structure the portal renders on screen, so the PDF and the screen cannot
disagree. ReportLab Platypus lays out the flowables; a two-pass canvas stamps
the watermark, header, footer and "Page x of Y" on every page. ASCII copy only.
No em dashes in this module.
"""
from __future__ import annotations

import os
import time
from datetime import datetime, timezone
from zoneinfo import ZoneInfo

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfgen import canvas
from reportlab.platypus import (BaseDocTemplate, Frame, NextPageTemplate, PageBreak,
                                PageTemplate, Paragraph, Spacer, Table, TableStyle)

_FONT_DIR = os.path.join(os.path.dirname(__file__), "fonts")
_REGISTERED = False


def _register_fonts() -> None:
    global _REGISTERED
    if _REGISTERED:
        return
    pdfmetrics.registerFont(TTFont("DejaVu", os.path.join(_FONT_DIR, "DejaVuSans.ttf")))
    pdfmetrics.registerFont(TTFont("DejaVu-Bold", os.path.join(_FONT_DIR, "DejaVuSans-Bold.ttf")))
    _REGISTERED = True


AMBER = colors.HexColor("#b4740c")
INK = colors.HexColor("#212529")
MUTED = colors.HexColor("#6b7280")
RULE = colors.HexColor("#d1d5db")
FILL = colors.HexColor("#f3f4f6")
OKC = colors.HexColor("#15803d")
FAILC = colors.HexColor("#b91c1c")
SEV = {"critical": colors.HexColor("#b91c1c"), "high": colors.HexColor("#c2410c"),
       "medium": colors.HexColor("#b4740c"), "low": colors.HexColor("#0369a1"),
       "info": MUTED}
VERDICT = {"likely phishing": colors.HexColor("#b91c1c"), "suspicious": colors.HexColor("#c2410c"),
           "brand-referencing": colors.HexColor("#0369a1"), "parked": MUTED,
           "unknown": colors.HexColor("#6b7280"), "unrelated": colors.HexColor("#0369a1")}

MANILA = ZoneInfo("Asia/Manila")


def _mode_label(mode, kind) -> str:
    """A human mode label for the cover, never a raw token like on_demand."""
    m = (mode or "").strip().lower()
    mapped = {"on_demand": "On-demand assessment", "public": "Public hunt",
              "operator": "Operator assessment"}.get(m)
    if mapped:
        return mapped
    if mode:
        return mode
    return "Public hunt" if kind == "hunt" else "On-demand assessment"


def _styles():
    return {
        "body": ParagraphStyle("body", fontName="DejaVu", fontSize=9, leading=12.5, textColor=INK),
        "small": ParagraphStyle("small", fontName="DejaVu", fontSize=7.5, leading=10, textColor=MUTED),
        "h2": ParagraphStyle("h2", fontName="DejaVu-Bold", fontSize=12, textColor=AMBER,
                             spaceBefore=12, spaceAfter=5, leading=15),
        "cell": ParagraphStyle("cell", fontName="DejaVu", fontSize=7.6, leading=9.5, textColor=INK),
        "cellh": ParagraphStyle("cellh", fontName="DejaVu-Bold", fontSize=7.4, leading=9.5, textColor=MUTED),
        # Character-level wrap so a long domain or date wraps inside the cell and is
        # never truncated.
        "cellw": ParagraphStyle("cellw", fontName="DejaVu", fontSize=7.6, leading=9.5,
                                textColor=INK, wordWrap="CJK"),
    }


def _sev_para(s, st):
    c = SEV.get(s, MUTED).hexval()[2:]
    return Paragraph(f'<font color="#{c}"><b>{s.upper()}</b></font>', st["cell"])


def _verdict_para(v, st):
    c = VERDICT.get(v, MUTED).hexval()[2:]
    return Paragraph(f'<font color="#{c}"><b>{(v or "").title()}</b></font>', st["cell"])


def _canvas_factory(domain, gen_utc, engagement):
    class NumberedCanvas(canvas.Canvas):
        def __init__(self, *a, **k):
            super().__init__(*a, **k)
            self._saved = []

        def showPage(self):
            self._saved.append(dict(self.__dict__))
            self._startPage()

        def save(self):
            total = len(self._saved)
            for st in self._saved:
                self.__dict__.update(st)
                self._decorate(total)
                super().showPage()
            super().save()

        def _decorate(self, total):
            w, h = A4
            if self._pageNumber > 1:
                self.setFont("DejaVu-Bold", 9)
                self.setFillColor(AMBER)
                self.drawString(18 * mm, h - 12 * mm, "FalconEye")
                self.setFont("DejaVu", 7.5)
                self.setFillColor(MUTED)
                self.drawRightString(w - 18 * mm, h - 12 * mm, domain[:60])
                self.setStrokeColor(RULE)
                self.setLineWidth(0.4)
                self.line(18 * mm, h - 14 * mm, w - 18 * mm, h - 14 * mm)
            self.setStrokeColor(RULE)
            self.setLineWidth(0.4)
            self.line(18 * mm, 14 * mm, w - 18 * mm, 14 * mm)
            self.setFont("DejaVu", 7)
            self.setFillColor(MUTED)
            foot = f"{domain}  -  generated {gen_utc}"
            if engagement:
                foot += f"  -  engagement {engagement}"
            self.drawString(18 * mm, 10 * mm, foot[:120])
            self.drawRightString(w - 18 * mm, 10 * mm, f"Page {self._pageNumber} of {total}")

    return NumberedCanvas


def _kv_table(rows, st, widths):
    t = Table(rows, colWidths=widths)
    t.setStyle(TableStyle([("FONT", (0, 0), (-1, 0), "DejaVu-Bold", 8),
                           ("TEXTCOLOR", (0, 0), (-1, 0), MUTED),
                           ("BACKGROUND", (0, 0), (-1, 0), FILL),
                           ("LINEBELOW", (0, 0), (-1, -1), 0.3, RULE),
                           ("VALIGN", (0, 0), (-1, -1), "TOP"),
                           ("TOPPADDING", (0, 0), (-1, -1), 3),
                           ("BOTTOMPADDING", (0, 0), (-1, -1), 3)]))
    return t


def _data_table(header, rows, widths, st):
    data = [[Paragraph(x, st["cellh"]) for x in header]] + rows
    t = Table(data, colWidths=widths, repeatRows=1)
    t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), FILL),
                           ("LINEBELOW", (0, 0), (-1, -1), 0.25, RULE),
                           ("VALIGN", (0, 0), (-1, -1), "TOP"),
                           ("TOPPADDING", (0, 0), (-1, -1), 2.5),
                           ("BOTTOMPADDING", (0, 0), (-1, -1), 2.5)]))
    return t


def render_report(payload: dict, out_path: str) -> None:
    """Render *payload* to a PDF at *out_path*."""
    _register_fonts()
    st = _styles()
    kind = payload.get("kind", "asm")
    title_subject = payload.get("title", "report")
    for _d in (chr(0x2014), chr(0x2013), chr(0x2012), chr(0x2015)):
        title_subject = str(title_subject).replace(_d, "-")
    gen_ts = payload.get("generated_ts") or time.time()
    gen_utc = datetime.fromtimestamp(gen_ts, timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    gen_manila = datetime.fromtimestamp(gen_ts, MANILA).strftime("%Y-%m-%d %H:%M:%S (Asia/Manila)")
    engagement = payload.get("engagement", "")

    doc = BaseDocTemplate(out_path, pagesize=A4,
                          title=f"FalconEye report {title_subject}", author="FalconEye",
                          leftMargin=18 * mm, rightMargin=18 * mm, topMargin=18 * mm,
                          bottomMargin=20 * mm)
    frame = Frame(doc.leftMargin, doc.bottomMargin, doc.width, doc.height, id="main")
    cover = Frame(doc.leftMargin, doc.bottomMargin, doc.width, doc.height, id="cover")

    wm_text = (title_subject or "FalconEye")[:40]
    if engagement:
        wm_text = f"{wm_text} / {engagement}"[:60]

    def _watermark(canvas_obj, _doc):
        # One faint, single-line diagonal string, drawn BEFORE the frame lays down
        # the content (onPage runs first), so it sits under the text and never
        # overlaps it as stray letters. Light grey, not letter-spaced.
        w, h = A4
        canvas_obj.saveState()
        canvas_obj.setFont("DejaVu-Bold", 38)
        canvas_obj.setFillColor(colors.Color(0.93, 0.92, 0.90))
        canvas_obj.translate(w / 2, h / 2)
        canvas_obj.rotate(26)
        canvas_obj.drawCentredString(0, 0, wm_text)
        canvas_obj.restoreState()

    doc.addPageTemplates([PageTemplate(id="cover", frames=[cover], onPage=_watermark),
                          PageTemplate(id="body", frames=[frame], onPage=_watermark)])
    el = []

    # Cover
    report_name = "Attack Surface Assessment" if kind == "asm" else "Phishing Domain Hunt"
    el.append(Spacer(1, 38 * mm))
    el.append(Paragraph('<font color="#b4740c"><b>FalconEye</b></font>',
                        ParagraphStyle("wm", fontName="DejaVu-Bold", fontSize=24)))
    el.append(Spacer(1, 6 * mm))
    el.append(Paragraph(report_name, ParagraphStyle("ct", fontName="DejaVu-Bold", fontSize=20,
                                                    textColor=INK, leading=24)))
    el.append(Spacer(1, 3 * mm))
    el.append(Paragraph(title_subject, ParagraphStyle("cd", fontName="DejaVu", fontSize=15,
                                                      textColor=AMBER)))
    el.append(Spacer(1, 10 * mm))
    cover_rows = [("Run time", f"{gen_manila}  /  {gen_utc}"),
                  ("Mode", _mode_label(payload.get("mode"), kind))]
    if engagement:
        cover_rows.append(("Engagement", engagement))
    if kind == "hunt":
        cover_rows.append(("Legitimate domain", payload.get("legit_domain") or "not provided"))
    cover_rows.append(("Notice", "Results are not kept. This PDF is the only copy; the server "
                                 "purges the on-screen results after download or within the hour."))
    if payload.get("incomplete"):
        cover_rows.append(("Status", "INCOMPLETE: at least one discovery source did not answer. "
                                     "See the source status below; a zero result here is not a "
                                     "clean result."))
    if kind == "hunt" and payload.get("nrd_off"):
        cover_rows.append(("Coverage", "Newly registered domain feed is not configured, so "
                                       "brand-new registrations may be missed."))
    for k, v in cover_rows:
        el.append(Paragraph(f"<b>{k}:</b> {v}", st["body"]))
        el.append(Spacer(1, 2 * mm))
    el.append(NextPageTemplate("body"))
    el.append(PageBreak())

    # Source status
    el.append(Paragraph("Source status", st["h2"]))
    srows = [[Paragraph("Source", st["cellh"]), Paragraph("Role", st["cellh"]),
              Paragraph("Status", st["cellh"])]]
    for s in payload.get("source_status", []):
        status = s.get("status", "skipped")
        c = {"answered": OKC, "failed": FAILC}.get(status, MUTED).hexval()[2:]
        role = _esc(s.get("role", ""))
        if s.get("note"):
            role += f' <font color="#6b7280">({_esc(s["note"])})</font>'
        srows.append([Paragraph(_esc(s.get("source", "")), st["cell"]),
                      Paragraph(role, st["cell"]),
                      Paragraph(f'<font color="#{c}"><b>{status.title()}</b></font>', st["cell"])])
    sstyle = _data_table(["", "", ""], srows[1:], [70 * mm, 50 * mm, 40 * mm], st)
    el.append(Table([srows[0]] + srows[1:], colWidths=[70 * mm, 50 * mm, 40 * mm], repeatRows=1,
                    style=TableStyle([("BACKGROUND", (0, 0), (-1, 0), FILL),
                                      ("LINEBELOW", (0, 0), (-1, -1), 0.25, RULE),
                                      ("TOPPADDING", (0, 0), (-1, -1), 3),
                                      ("BOTTOMPADDING", (0, 0), (-1, -1), 3)])))
    if payload.get("incomplete"):
        el.append(Spacer(1, 2 * mm))
        el.append(Paragraph('<font color="#b91c1c"><b>This run is INCOMPLETE.</b></font> One or '
                            "more discovery sources did not answer, so missing results below are "
                            "not evidence of absence.", st["body"]))

    # Executive summary
    el.append(Paragraph("Executive summary", st["h2"]))
    el.append(Paragraph(payload.get("summary_line", ""), st["body"]))
    el.append(Spacer(1, 3 * mm))
    counts = payload.get("severity_counts") or {}
    if kind == "asm":
        order = ["critical", "high", "medium", "low", "info"]
        crows = [[_sev_para(s, st), str(counts.get(s, 0))] for s in order]
    else:
        order = ["likely phishing", "suspicious", "brand-referencing", "parked",
                 "unknown", "unrelated"]
        crows = [[_verdict_para(s, st), str(counts.get(s, 0))] for s in order]
    el.append(_kv_table([["Category", "Count"]] + crows, st, [52 * mm, 22 * mm]))

    if kind == "hunt":
        p = payload.get("pipeline") or {}
        el.append(Spacer(1, 3 * mm))
        prows = [["Stage", "Count"],
                 ["Discovered (before cap)", str(p.get("discovered", 0))],
                 ["Considered (after cap)", str(p.get("considered", 0))],
                 ["Registered and resolving", str(p.get("resolved", 0))],
                 ["Possibly taken down", str(p.get("taken_down", 0))],
                 ["Registry wildcard, dropped", str(p.get("wildcard", 0))],
                 ["Irrelevant keyword matches, dropped", str(p.get("irrelevant", 0))],
                 ["Not registered", str(p.get("not_registered", 0))],
                 ["Fetched and assessed", str(p.get("fetched", 0))],
                 ["Not fetched (fetch cap)", str(p.get("not_fetched", 0))],
                 ["urlscan or certificate keyword hits", str(p.get("keyword_hits", 0))]]
        el.append(_kv_table(prows, st, [78 * mm, 22 * mm]))

        # Detected campaigns, at the top of the findings.
        def _group_block(c, label):
            w = c.get("window") or {}
            win = (f"{w.get('first')} to {w.get('last')}"
                   if w.get("first") else "dates not published")
            el.append(Paragraph(
                f"<b>{label}: {_esc(c.get('theme'))}</b> ({c.get('count', 0)} domains, "
                f"registered/seen {_esc(win)})", st["body"]))
            meta = []
            if c.get("corroboration"):
                meta.append("corroboration: " + _esc("; ".join(c["corroboration"])))
            regs = c.get("registrars") or []
            if regs:
                meta.append("registrars seen: " + _esc(", ".join(regs)))
            if c.get("tlds"):
                meta.append("TLDs: " + _esc(", ".join(c["tlds"])))
            if c.get("abuse"):
                meta.append("registrar abuse: " + _esc(c["abuse"]))
            if meta:
                el.append(Paragraph("; ".join(meta), st["small"]))
            # Per-domain registrar data from RDAP, not a single inferred value.
            mrows = c.get("member_rows") or [{"domain": d} for d in (c.get("members") or [])]
            hdr = ["Domain", "Registrar (RDAP)", "Registered", "Nameserver"]
            drows = [[Paragraph(_esc(m.get("domain")), st["cellw"]),
                      Paragraph(_esc(m.get("registrar") or "unknown"), st["cellw"]),
                      Paragraph(_esc(m.get("reg_date") or "n/a"), st["cellw"]),
                      Paragraph(_esc(m.get("ns") or ""), st["cellw"])] for m in mrows]
            el.append(_data_table(hdr, drows, [44 * mm, 44 * mm, 24 * mm, 46 * mm], st))
            # By registrar, with the RDAP abuse email, so one report per registrar
            # can list all of its domains in this campaign.
            groups = c.get("registrar_groups") or []
            if groups:
                el.append(Paragraph("By registrar (for abuse reports):", st["small"]))
                grows = [[Paragraph(_esc(g.get("registrar") or "unknown"), st["cellw"]),
                          Paragraph(_esc(g.get("abuse") or "no abuse email published"), st["cellw"]),
                          Paragraph(_esc(", ".join(g.get("domains") or [])), st["cellw"])]
                         for g in groups]
                el.append(_data_table(["Registrar", "Abuse email (RDAP)", "Domains"],
                                      grows, [40 * mm, 48 * mm, 70 * mm], st))
            # Members registered outside the burst that share no distinctive
            # attribute with it: listed here, scored on their own, not boosted.
            outs = c.get("outliers_related") or []
            if outs:
                el.append(Paragraph(
                    "Related, outside the burst (scored on their own, not part of "
                    "the campaign):", st["small"]))
                orows = [[Paragraph(_esc(o.get("domain")), st["cellw"]),
                          Paragraph(_esc(o.get("registrar") or "unknown"), st["cellw"]),
                          Paragraph(_esc(o.get("reg_date") or "n/a"), st["cellw"])]
                         for o in outs]
                el.append(_data_table(["Domain", "Registrar", "Registered"],
                                      orows, [60 * mm, 60 * mm, 38 * mm], st))
            el.append(Spacer(1, 2 * mm))

        camps = payload.get("campaigns") or []
        if camps:
            el.append(Paragraph("Detected campaigns", st["h2"]))
            for c in camps:
                _group_block(c, "Campaign")
        related = payload.get("related_groups") or []
        if related:
            el.append(Paragraph("Related brand-themed domains (not corroborated as a campaign)",
                                st["h2"]))
            for c in related:
                _group_block(c, "Group")

    # Findings (asm) or candidates (hunt)
    if kind == "asm":
        el.append(Paragraph("Findings", st["h2"]))
        if not payload.get("findings"):
            el.append(Paragraph("No findings.", st["body"]))
        for f in payload.get("findings", []):
            rows = [[_sev_para(f["severity"], st),
                     Paragraph(f"<b>{_esc(f.get('title'))}</b>  <font color='#6b7280'>"
                               f"{_esc(f.get('host') or '')}</font>", st["cell"])],
                    ["", Paragraph(f"<b>Evidence.</b> {_esc(f.get('detail') or 'n/a')}", st["cell"])],
                    ["", Paragraph(f"<b>Remediation.</b> {_esc(f.get('remediation') or _default_fix(f))}",
                                   st["cell"])]]
            ft = Table(rows, colWidths=[24 * mm, 150 * mm])
            ft.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP"),
                                    ("LEFTPADDING", (0, 0), (-1, -1), 2),
                                    ("TOPPADDING", (0, 0), (-1, -1), 2),
                                    ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
                                    ("LINEBELOW", (0, -1), (-1, -1), 0.3, RULE)]))
            el.append(ft)
            el.append(Spacer(1, 2 * mm))

        el.append(Paragraph("Hosts", st["h2"]))
        hdr = ["Host", "IP", "Open ports", "Server", "TLS", "Notes"]
        rows = []
        for h in payload.get("hosts", []):
            k = h.get("kind", "own")
            if k == "cdn":
                ports = f"behind CDN ({h.get('cdn') or 'CDN'}), ports not scanned"
            elif k == "reference":
                ports = f"reference only: CNAME to {h.get('cname') or 'third party'}"
            else:
                ports = ", ".join(str(p) for p in (h.get("ports") or [])) or "none"
            ips = h.get("resolved_ips") or []
            # One address per line so an address is never wrapped mid-value.
            ip_cell = "<br/>".join(_esc(ip) for ip in ips) if ips else "n/a"
            rows.append([Paragraph(_esc(h.get("host")), st["cell"]),
                         Paragraph(ip_cell, st["cell"]),
                         Paragraph(_esc(ports), st["cell"]),
                         Paragraph(_esc(h.get("server") or "n/a"), st["cell"]),
                         Paragraph(_esc(_tls_brief(h.get("tls"))), st["cell"]),
                         Paragraph(_esc(k), st["cell"])])
        if rows:
            el.append(_data_table(hdr, rows, [40 * mm, 32 * mm, 44 * mm, 16 * mm, 16 * mm, 26 * mm], st))
    else:
        el.append(Paragraph("Lookalike candidates", st["h2"]))
        el.append(Paragraph("Certificate and urlscan keyword hits are listed first, then by score. "
                            f"{(payload.get('pipeline') or {}).get('not_registered', 0)} generated "
                            "permutations did not resolve and are not listed.", st["small"]))
        el.append(Spacer(1, 1.5 * mm))
        hdr = ["Candidate", "Source", "Verdict", "Score", "Registered", "Evidence"]
        rows = []
        for c in payload.get("candidates", []):
            reg = c.get("registered")
            age = c.get("age_days")
            agestr = f" ({age}d)" if isinstance(age, int) and age >= 0 else ""
            reg_lines = []
            if reg:
                reg_lines.append(_esc(f"reg {reg}{agestr}"))
            elif c.get("reg_note"):
                reg_lines.append(_esc(c["reg_note"]))
            if c.get("ct_first_seen"):
                # If there is no registration date, the CT first-live date carries the age.
                reg_lines.append(_esc(f"first live (CT) {c['ct_first_seen']}"
                                      + ("" if reg else agestr)))
            if c.get("urlscan_first_seen"):
                reg_lines.append(_esc(f"urlscan first seen {c['urlscan_first_seen']}"))
            reg_html = "<br/>".join(reg_lines) or "n/a"
            dom = _esc(c.get("domain"))
            if c.get("campaign_id"):
                dom = f"<b>{dom}</b>"
            ev_parts = list(c.get("evidence") or [])
            if c.get("urlscan_result"):
                ev_parts.append(f"urlscan result {c['urlscan_result']}")
            rows.append([Paragraph(dom, st["cellw"]),
                         Paragraph(_esc(c.get("source") or "dnstwist"), st["cellw"]),
                         _verdict_para(c.get("verdict", "unrelated"), st),
                         Paragraph(str(c.get("score", 0)), st["cell"]),
                         Paragraph(reg_html, st["cellw"]),
                         Paragraph(_esc("; ".join(ev_parts) or "n/a"), st["cellw"])])
        if rows:
            el.append(_data_table(hdr, rows, [34 * mm, 22 * mm, 22 * mm, 14 * mm, 28 * mm, 54 * mm], st))
        else:
            el.append(Paragraph("No candidates found.", st["body"]))

    # Posture (asm) and references
    if kind == "asm" and payload.get("posture"):
        p = payload["posture"]
        el.append(Paragraph("Mail and DNS posture", st["h2"]))
        el.append(Paragraph(f"SPF: {_yn(p.get('spf'))}. DMARC: {_yn(p.get('dmarc'))} "
                            f"(policy {p.get('dmarc_policy') or 'n/a'}). MTA-STS: {_yn(p.get('mta_sts'))}. "
                            f"TLS-RPT: {_yn(p.get('tls_rpt'))}.", st["body"]))
    if payload.get("references_note"):
        el.append(Paragraph("CDN and third-party references", st["h2"]))
        el.append(Paragraph(_esc(payload["references_note"]), st["body"]))

    # Methodology and sources
    el.append(Paragraph("Methodology and caps", st["h2"]))
    el.append(Paragraph(_esc(payload.get("methodology", "")), st["body"]))
    el.append(Paragraph("Sources and attribution", st["h2"]))
    for line in payload.get("attribution", []):
        el.append(Paragraph(_esc(line), st["small"]))

    if kind == "hunt":
        el.append(Spacer(1, 3 * mm))
        el.append(Paragraph("Verdicts are automated assessments from public data, not "
                            "determinations; verify before acting.", st["small"]))

    subject = title_subject or "report"
    doc.build(el, canvasmaker=_canvas_factory(subject, gen_utc, engagement))


def _esc(s) -> str:
    s = "" if s is None else str(s)
    # Normalise em, en, figure and horizontal-bar dashes from any external data
    # (page titles, registrar names, evidence) to a hyphen, so no em dash reaches
    # the PDF whatever a fetched page contained.
    for d in (chr(0x2014), chr(0x2013), chr(0x2012), chr(0x2015)):
        s = s.replace(d, "-")
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _yn(v) -> str:
    return "present" if v else "absent"


def _tls_brief(tls) -> str:
    if not tls:
        return "n/a"
    return (tls.get("issuer") or "cert")[:18]


def _default_fix(f) -> str:
    kind = f.get("kind")
    return {
        "takeover": "Remove the dangling CNAME or re-claim the backing resource now.",
        "cert": "Renew the certificate and confirm auto-renewal.",
        "private_ip": "Remove the private address from public DNS.",
        "admin_surface": "Take the admin surface off the public internet or behind an allowlist.",
        "open_service": "Close the service to the internet or restrict it to known addresses.",
        "headers": "Add the missing security headers at the server or CDN.",
        "mail_posture": "Publish the missing mail authentication records.",
    }.get(kind, "Review and remediate as appropriate.")
