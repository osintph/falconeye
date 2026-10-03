"""
Traceroute output parsers for the Route Map tab (v3.35.0).

WHAT THIS PARSES
----------------
Four real-world shapes, auto-detected, because an investigator pastes whatever
their own machine produced:

  Windows tracert          RTTs first, then "name [ip]" or a bare address,
                           "Request timed out." for a dead hop, "<1 ms" for
                           sub-millisecond.
  Windows tracert -d       the same, with no name column.
  Unix traceroute          address first ("name (ip)" or, with -n, a bare
                           address), then one RTT per probe, "*" for a lost
                           probe, and "!H"-style unreachable codes. A hop that
                           answered from more than one address continues on
                           indented lines with no hop number, which is the
                           normal shape of an ECMP hop and not an anomaly.
  mtr --report / -w        "N.|-- host  Loss%  Snt  Last  Avg  Best  Wrst StDev",
                           "???" for a hop that never answered.

DETECTION, AND WHY IT IS A SCORE AND NOT A SNIFF
------------------------------------------------
The header lines ("Tracing route to", "traceroute to", "HOST:") are the obvious
signal and are used, but they are also the first thing a paste loses: people
select from the first hop down, or the tool is wrapped by a script that prints
its own banner. So each parser runs over the whole text, reports how many hop
lines it recognised, and the winner is the one that recognised the most. A
header match only breaks a tie.

The one genuine ambiguity is tracert versus traceroute, because
"1  1 ms  1 ms  1 ms  192.168.1.1" is a valid-looking body for both readings.
It is resolved structurally rather than by guessing: a traceroute hop body
always *begins* with an address, so :func:`_parse_traceroute` refuses a body
whose first token is a timing. That is a property of the format, not a
heuristic about this input.

WHAT A PARSER DOES NOT DO
-------------------------
No geolocation, no judgement, no network access: a Hop is what the text said,
including hops that answered from several addresses and hops that answered not
at all. Everything downstream (app/routemap/geo.py) reads Hop and never the
raw text, so adding a fifth format means adding a parser here and nothing else.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field

# A paste is operator-supplied text, so it is bounded before anything walks it.
# 30 hops at three probes each is a few kilobytes; 256 KB is room for a very
# wide mtr report plus banners, and well under the regex-compute cap the rest of
# the codebase uses for pasted input (REGEX_MAX_BODY_BYTES).
MAX_TRACE_BYTES = 256_000
# Independent of the byte cap: a trace with more lines than this is not a trace.
MAX_LINES = 2_000
# Protocol maximum. Anything beyond it is a parser artefact, not a hop.
MAX_HOPS = 255


class TraceParseError(ValueError):
    """The text could not be read as any supported traceroute output."""


@dataclass
class Hop:
    """One hop, exactly as the text reported it.

    ``addresses`` and ``hostnames`` are parallel only in the sense that both are
    first-seen-ordered and de-duplicated; a hop can have an address with no name
    (``traceroute -n``) or a name with no address (``mtr --report`` without
    ``--show-ips``), so neither list may be indexed against the other.
    """
    hop: int
    addresses: list[str] = field(default_factory=list)
    hostnames: list[str] = field(default_factory=list)
    rtts_ms: list[float] = field(default_factory=list)
    sent: int = 0
    lost: int = 0
    # traceroute's ICMP unreachable codes (!H host, !N network, !X admin, ...),
    # kept verbatim because they are the router's own words about why it stopped.
    codes: list[str] = field(default_factory=list)

    @property
    def min_rtt_ms(self) -> float | None:
        """The fastest probe. This is the only RTT the physics bound may use:
        the floor of several probes is the closest thing to propagation delay,
        and queueing can only ever push a sample up."""
        return min(self.rtts_ms) if self.rtts_ms else None

    @property
    def avg_rtt_ms(self) -> float | None:
        return round(sum(self.rtts_ms) / len(self.rtts_ms), 3) if self.rtts_ms else None

    @property
    def loss_pct(self) -> float | None:
        if not self.sent:
            return None
        return round(100.0 * self.lost / self.sent, 1)

    @property
    def responded(self) -> bool:
        return bool(self.addresses or self.hostnames)

    def add_address(self, addr: str) -> None:
        addr = addr.strip().strip("[]()")
        if not addr or addr in self.addresses:
            return
        try:
            # Normalise so 2001:DB8::1 and 2001:db8::1 are one address, and so a
            # token that only looks like an address is dropped here rather than
            # reaching the geolocation pipeline.
            addr = str(ipaddress.ip_address(addr))
        except ValueError:
            return
        if addr not in self.addresses:
            self.addresses.append(addr)

    def add_hostname(self, name: str) -> None:
        name = name.strip().strip(".")
        if not name or name in self.hostnames:
            return
        if _looks_like_address(name):
            return
        self.hostnames.append(name)


@dataclass
class ParsedTrace:
    parser: str                 # "tracert" | "traceroute" | "mtr"
    hops: list[Hop]
    target: str | None = None   # what the banner said was being traced, if present
    warnings: list[str] = field(default_factory=list)


# ------------------------------------------------------------------ helpers ----

def _looks_like_address(token: str) -> bool:
    try:
        ipaddress.ip_address(token.strip().strip("[]()"))
        return True
    except ValueError:
        return False


# A hostname worth sending to a hostname-geolocation service: dotted, with an
# alphabetic public-suffix-shaped last label. This deliberately rejects the
# names that are not router hostnames at all: "_gateway" and a LAN name like
# "router" (no dot), "???" (mtr's no-answer marker), and any bare
# address wearing a hostname column.
_HOSTNAME_RE = re.compile(r"^(?=.{1,253}$)(?:[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?\.)+[A-Za-z]{2,63}$")


def is_routable_hostname(name: str) -> bool:
    """Whether *name* is a public router hostname, not a local label.

    The gate on what may leave this server: only a name that passes here is
    ever sent to CAIDA Hoiho or written to the hostname cache.
    """
    name = (name or "").strip().strip(".")
    if not name or _looks_like_address(name):
        return False
    if name.startswith("_") or ".local" == name[-6:].lower():
        return False
    return bool(_HOSTNAME_RE.match(name))


def _clean(text: str) -> list[str]:
    if text is None:
        raise TraceParseError("no trace text given")
    if len(text.encode("utf-8", "replace")) > MAX_TRACE_BYTES:
        raise TraceParseError(
            f"the trace is larger than {MAX_TRACE_BYTES // 1000} KB; paste the hop list only")
    # Normalise the line endings a Windows paste carries, and drop the box
    # drawing some terminals wrap output in.
    lines = text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    if len(lines) > MAX_LINES:
        raise TraceParseError(f"the trace has more than {MAX_LINES} lines")
    return lines


def _dedupe_hops(hops: list[Hop]) -> list[Hop]:
    """Keep one Hop per hop number, merging repeats in first-seen order.

    mtr prints an extra line per additional path at the same hop, and a paste
    can contain the same hop twice when someone concatenates two runs. Merging
    is right for the first and harmless for the second.
    """
    merged: dict[int, Hop] = {}
    order: list[int] = []
    for hop in hops:
        if hop.hop in merged:
            target = merged[hop.hop]
            for addr in hop.addresses:
                target.add_address(addr)
            for name in hop.hostnames:
                target.add_hostname(name)
            target.rtts_ms.extend(hop.rtts_ms)
            target.sent += hop.sent
            target.lost += hop.lost
            for code in hop.codes:
                if code not in target.codes:
                    target.codes.append(code)
        else:
            merged[hop.hop] = hop
            order.append(hop.hop)
    return [merged[n] for n in sorted(order)]


# ------------------------------------------------------- Windows tracert -------
#
#   Tracing route to google.com [142.250.185.78]
#   over a maximum of 30 hops:
#
#     1     1 ms     1 ms     1 ms  192.168.1.1
#     2     *        *        *     Request timed out.
#     4    15 ms    14 ms    15 ms  host.example.net [203.0.113.1]
#     5    <1 ms     2 ms    <1 ms  10.0.0.1

_TRACERT_BANNER = re.compile(r"^\s*Tracing route to\s+(.+?)\s*(?:\[([^\]]+)\])?\s*$", re.I)
_TRACERT_HOP = re.compile(r"^\s*(\d{1,3})\s+(.*\S)\s*$")
# A probe column: "*", "<1 ms", "12 ms", "1.5 ms". The "<" form is Windows
# saying "faster than the clock can see", which is 0 for our purposes, not a
# missing probe.
_TRACERT_PROBE = re.compile(r"^(?:(\*)|(<)?\s*(\d+(?:\.\d+)?)\s*ms)(?:\s+|$)", re.I)
# Everything Windows prints in the host column when there is no host.
_TRACERT_DEAD = re.compile(
    r"^(?:Request timed out\.?|Destination (?:host|net) unreachable\.?"
    r"|Destination protocol unreachable\.?|TTL expired in transit\.?"
    r"|General failure\.?|Transmit failed.*)$", re.I)


def _parse_tracert(lines: list[str]) -> tuple[list[Hop], int, str | None, bool]:
    hops: list[Hop] = []
    target: str | None = None
    banner = False

    for raw in lines:
        if not raw.strip():
            continue
        match = _TRACERT_BANNER.match(raw)
        if match:
            banner = True
            target = (match.group(2) or match.group(1) or "").strip() or None
            continue

        match = _TRACERT_HOP.match(raw)
        if not match:
            continue
        number, body = int(match.group(1)), match.group(2)
        if not 1 <= number <= MAX_HOPS:
            continue

        hop = Hop(hop=number)
        rest = body
        while True:
            probe = _TRACERT_PROBE.match(rest)
            if not probe:
                break
            hop.sent += 1
            if probe.group(1):
                hop.lost += 1
            else:
                # "<1 ms" is reported as 0.0: a real answer, below the clock's
                # resolution. Recording it as a loss would invent packet loss on
                # every LAN hop of every Windows trace.
                hop.rtts_ms.append(0.0 if probe.group(2) else float(probe.group(3)))
            rest = rest[probe.end():]

        if not hop.sent:
            # No probe column at all, so this is not a tracert hop line. Most
            # often it is a Unix traceroute line, which is exactly the
            # ambiguity the score resolves.
            continue

        rest = rest.strip()
        if rest and not _TRACERT_DEAD.match(rest):
            named = re.match(r"^(\S+)\s*\[([^\]]+)\]\s*$", rest)
            if named:
                hop.add_hostname(named.group(1))
                hop.add_address(named.group(2))
            else:
                for token in rest.split():
                    if _looks_like_address(token):
                        hop.add_address(token)
                    elif is_routable_hostname(token):
                        hop.add_hostname(token)
        hops.append(hop)

    hops = _dedupe_hops(hops)
    return hops, len(hops), target, banner


# ---------------------------------------------------------- Unix traceroute ----
#
#    traceroute to 1.1.1.1 (1.1.1.1), 12 hops max, 40 byte packets
#     1  router (192.0.2.1)  10.821 ms *  3.741 ms
#     4  122.2.187.142.static.pldt.net (122.2.187.142)  8.323 ms
#        122.2.187.146.static.pldt.net (122.2.187.146)  8.015 ms
#     8  * * *
#     9  10.0.0.1 (10.0.0.1)  20.1 ms !H

_TRACEROUTE_BANNER = re.compile(
    r"^\s*traceroute(?:6)?\s+to\s+(\S+)\s*(?:\(([^)]+)\))?", re.I)
_TRACEROUTE_HOP = re.compile(r"^\s*(\d{1,3})\s+(.*\S)\s*$")
# An indented line continues the previous hop: an ECMP hop that answered from
# more than one address. No lookahead for a leading digit, because a
# continuation's first token very often starts with one
# ("122.2.187.146.static.pldt.net"); what makes a line a hop line is
# _TRACEROUTE_HOP matching, and that is tried first.
_TRACEROUTE_CONT = re.compile(r"^\s{2,}(\S.*\S|\S)\s*$")

# Tokens in a hop body, matched in order. "named" must precede "bare" so
# "host (1.2.3.4)" is one token rather than two, and "rtt" must precede "bare"
# so "8.323 ms" is a timing rather than something address-shaped.
_TRACEROUTE_TOKEN = re.compile(
    r"""
      (?P<star>\*)
    | (?P<named>(?P<host>[A-Za-z0-9_][A-Za-z0-9_.:-]*)\s+\((?P<ip>[0-9A-Fa-f:.]+)\))
    | (?P<rtt>\d+(?:\.\d+)?)\s*ms\b
    | (?P<code>![A-Za-z0-9]*)
    | (?P<bare>[0-9A-Fa-f:.]+)
    """,
    re.X,
)


def _traceroute_body_into(hop: Hop, body: str) -> bool:
    """Fold one hop body (or continuation line) into *hop*.

    Returns False when the body does not read as traceroute output, which is
    how a Windows tracert line is refused: a traceroute hop body always opens
    with an address or a lost probe, never with a timing.
    """
    seen_any = False
    first = True
    for match in _TRACEROUTE_TOKEN.finditer(body):
        kind = match.lastgroup if match.lastgroup in ("star", "rtt", "code") else (
            "named" if match.group("named") else "bare")
        if first and kind == "rtt":
            return False
        first = False
        seen_any = True
        if kind == "star":
            hop.sent += 1
            hop.lost += 1
        elif kind == "named":
            hop.add_hostname(match.group("host"))
            hop.add_address(match.group("ip"))
        elif kind == "bare":
            if _looks_like_address(match.group("bare")):
                hop.add_address(match.group("bare"))
            else:
                return False
        elif kind == "rtt":
            hop.sent += 1
            hop.rtts_ms.append(float(match.group("rtt")))
        elif kind == "code":
            code = match.group("code")
            if code not in hop.codes:
                hop.codes.append(code)
    return seen_any


def _parse_traceroute(lines: list[str]) -> tuple[list[Hop], int, str | None, bool]:
    hops: list[Hop] = []
    target: str | None = None
    banner = False
    current: Hop | None = None

    for raw in lines:
        if not raw.strip():
            current = None
            continue
        match = _TRACEROUTE_BANNER.match(raw)
        if match:
            banner = True
            target = (match.group(2) or match.group(1) or "").strip() or None
            current = None
            continue

        match = _TRACEROUTE_HOP.match(raw)
        if match:
            number = int(match.group(1))
            if not 1 <= number <= MAX_HOPS:
                current = None
                continue
            hop = Hop(hop=number)
            if _traceroute_body_into(hop, match.group(2)):
                hops.append(hop)
                current = hop
            else:
                current = None
            continue

        cont = _TRACEROUTE_CONT.match(raw)
        if cont and current is not None:
            _traceroute_body_into(current, cont.group(1))
            continue
        current = None

    hops = _dedupe_hops(hops)
    return hops, len(hops), target, banner


# ------------------------------------------------------------------- mtr -------
#
#   HOST: vps-e7d7933f                   Loss%   Snt   Last   Avg  Best  Wrst StDev
#     9.|-- vks19368.ip-103-5-15.asia (103.5.15.112)  0.0%  3   4.0   4.2   3.8   4.9  0.6
#    11.|-- ???                                      100.0  3   0.0   0.0   0.0   0.0  0.0
#
# Note the missing "%" on the 100.0 line: mtr drops it when the field is full.
# That is not a typo in the sample, it is what mtr prints, and the regex has to
# accept both.

_MTR_BANNER = re.compile(r"^\s*(?:Start:|HOST:)\s*(\S+)?", re.I)
_MTR_HOP = re.compile(
    r"^\s*(\d{1,3})\.\|--\s+(.+?)\s+"
    r"(\d+(?:\.\d+)?)%?\s+(\d+)\s+"
    r"(\d+(?:\.\d+)?)\s+(\d+(?:\.\d+)?)\s+(\d+(?:\.\d+)?)\s+(\d+(?:\.\d+)?)\s+(\d+(?:\.\d+)?)\s*$"
)
# mtr's extra-path continuation ("    |`|-- 10.0.0.2"), which carries an
# address and no statistics of its own.
_MTR_CONT = re.compile(r"^\s*\|[`\s|]*--\s+(\S+)(?:\s+\(([^)]+)\))?\s*$")
_MTR_NO_ANSWER = "???"


def _mtr_host_into(hop: Hop, host_part: str) -> None:
    host_part = host_part.strip()
    if not host_part or host_part == _MTR_NO_ANSWER:
        return
    named = re.match(r"^(\S+)\s+\(([^)]+)\)$", host_part)
    if named:
        hop.add_hostname(named.group(1))
        hop.add_address(named.group(2))
    elif _looks_like_address(host_part):
        hop.add_address(host_part)
    else:
        hop.add_hostname(host_part)


def _parse_mtr(lines: list[str]) -> tuple[list[Hop], int, str | None, bool]:
    hops: list[Hop] = []
    banner = False
    current: Hop | None = None

    for raw in lines:
        if not raw.strip():
            continue
        if _MTR_BANNER.match(raw) and "|--" not in raw:
            banner = True
            current = None
            continue

        match = _MTR_HOP.match(raw)
        if match:
            number = int(match.group(1))
            if not 1 <= number <= MAX_HOPS:
                current = None
                continue
            loss_pct = float(match.group(3))
            sent = int(match.group(4))
            hop = Hop(hop=number)
            hop.sent = sent
            # mtr reports loss as a percentage of what it sent, so the probe
            # count is derived rather than counted. Rounding to the nearest
            # probe is the only honest reading of "33.3% of 3".
            hop.lost = min(sent, max(0, round(sent * loss_pct / 100.0)))
            _mtr_host_into(hop, match.group(2))
            # Best, the column the physics bound wants. At 100% loss every
            # timing column is 0.0 and means "no sample", not "0 ms".
            if hop.lost < sent:
                hop.rtts_ms.append(float(match.group(7)))
            hops.append(hop)
            current = hop
            continue

        cont = _MTR_CONT.match(raw)
        if cont and current is not None:
            if cont.group(2):
                current.add_hostname(cont.group(1))
                current.add_address(cont.group(2))
            else:
                _mtr_host_into(current, cont.group(1))
            continue
        current = None

    hops = _dedupe_hops(hops)
    return hops, len(hops), None, banner


# -------------------------------------------------------------- detection ------

_PARSERS = (
    ("mtr", _parse_mtr),
    ("traceroute", _parse_traceroute),
    ("tracert", _parse_tracert),
)

PARSER_LABELS = {
    "mtr": "mtr --report",
    "traceroute": "Unix traceroute",
    "tracert": "Windows tracert",
}


def parse_trace(text: str) -> ParsedTrace:
    """Read *text* as traceroute output, whichever tool produced it.

    Raises TraceParseError when nothing recognised a single hop, because an
    empty hop list with a confident parser name is the one answer that would be
    worse than an error.
    """
    lines = _clean(text)

    results = []
    for name, parse in _PARSERS:
        hops, score, target, banner = parse(lines)
        results.append((score, banner, name, hops, target))

    # Most hop lines recognised wins; a banner breaks a tie, and the declaration
    # order in _PARSERS breaks what the banner cannot.
    results.sort(key=lambda r: (r[0], r[1]), reverse=True)
    score, _banner, name, hops, target = results[0]

    if not score:
        raise TraceParseError(
            "could not read this as traceroute output. Supported: Windows tracert "
            "(with or without -d), Unix traceroute (with or without -n), and "
            "mtr --report / --report-wide.")

    if len(hops) > MAX_HOPS:
        hops = hops[:MAX_HOPS]

    warnings = []
    # A gap means hops the tool numbered but the paste does not contain. Worth
    # saying, because a map drawn from hops 1 and 14 is not a map of the path.
    numbers = [h.hop for h in hops]
    expected = list(range(numbers[0], numbers[-1] + 1))
    missing = sorted(set(expected) - set(numbers))
    if missing:
        warnings.append(
            f"hop {', '.join(str(n) for n in missing[:8])}"
            f"{' and others' if len(missing) > 8 else ''} "
            "missing from the pasted text, so the path is drawn with a gap there")

    return ParsedTrace(parser=name, hops=hops, target=target, warnings=warnings)
