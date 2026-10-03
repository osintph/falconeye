"""The traceroute parsers: one trace, three tools, the same hops.

A paste comes from whatever the investigator's machine produced, so the parser
is the one place a format difference is allowed to exist. Everything
downstream reads Hop objects, which is why these tests compare the three
formats against each other rather than each against a hand-written expectation:
if tracert and traceroute of the same path disagree about which addresses were
seen, one of the parsers is wrong, and asserting them separately would hide it.

Fixtures are two real paths from a Manila origin (see
tests/fixtures/routemap/), rendered in all three formats.
"""
import pathlib

import pytest

from app.routemap.parse import (MAX_TRACE_BYTES, TraceParseError,
                                is_routable_hostname, parse_trace)

FIXTURES = pathlib.Path(__file__).resolve().parents[1] / "fixtures" / "routemap"
PATHS = ("heise", "amazon")
FORMATS = {"traceroute": "traceroute", "tracert": "tracert", "mtr": "mtr"}


def load(name):
    return (FIXTURES / f"{name}.txt").read_text()


@pytest.mark.parametrize("path", PATHS)
@pytest.mark.parametrize("fmt,parser", FORMATS.items())
def test_each_format_is_detected(path, fmt, parser):
    parsed = parse_trace(load(f"{path}_{fmt}"))
    assert parsed.parser == parser, (
        f"{path}_{fmt} was read as {parsed.parser}; the format sniffer picked "
        f"the wrong parser, which silently changes every hop downstream")


@pytest.mark.parametrize("path", PATHS)
def test_the_three_formats_agree_on_the_hops(path):
    """The same path, three tools: same hop numbers, same addresses."""
    runs = {fmt: parse_trace(load(f"{path}_{fmt}")) for fmt in FORMATS}
    numbers = {fmt: [h.hop for h in p.hops] for fmt, p in runs.items()}
    assert len(set(map(tuple, numbers.values()))) == 1, f"hop numbering differs: {numbers}"

    addresses = {fmt: [tuple(h.addresses) for h in p.hops] for fmt, p in runs.items()}
    assert len(set(map(tuple, addresses.values()))) == 1, (
        "the formats disagree about which addresses answered:\n"
        + "\n".join(f"  {fmt}: {a}" for fmt, a in addresses.items()))


@pytest.mark.parametrize("path", PATHS)
def test_hostnames_survive_every_format_that_carries_them(path):
    for fmt in FORMATS:
        parsed = parse_trace(load(f"{path}_{fmt}"))
        names = [n for h in parsed.hops for n in h.hostnames]
        assert any(".net" in n or ".de" in n for n in names), (
            f"{path}_{fmt}: no router hostnames survived parsing, so the "
            f"hostname-first geolocation has nothing to work with")


def test_timeouts_are_loss_not_missing_hops():
    """A hop that never answered is still a hop."""
    parsed = parse_trace(load("amazon_traceroute"))
    dead = [h for h in parsed.hops if not h.addresses]
    assert dead, "the amazon fixture has unanswered hops; they vanished"
    for hop in dead:
        assert hop.loss_pct == 100.0
        assert hop.min_rtt_ms is None


def test_windows_sub_millisecond_is_an_answer_not_a_loss():
    """"<1 ms" is a reply faster than the clock, not a dropped probe."""
    parsed = parse_trace(
        "  1    <1 ms    <1 ms    <1 ms  192.168.1.1\n")
    hop = parsed.hops[0]
    assert hop.loss_pct == 0.0, "'<1 ms' was counted as packet loss"
    assert hop.min_rtt_ms == 0.0


def test_mtr_hundred_percent_loss_has_no_percent_sign():
    """mtr drops the % when the field is full; the regex must accept both."""
    text = ("HOST: box                 Loss%   Snt   Last   Avg  Best  Wrst StDev\n"
            "  1.|-- 10.0.0.1           0.0%     3    1.0   1.0   1.0   1.0   0.0\n"
            "  2.|-- ???               100.0     3    0.0   0.0   0.0   0.0   0.0\n")
    parsed = parse_trace(text)
    assert parsed.parser == "mtr"
    assert parsed.hops[1].loss_pct == 100.0
    # At 100% loss every timing column reads 0.0 and means "no sample".
    assert parsed.hops[1].min_rtt_ms is None, "0.0 ms was taken as a real measurement"


def test_an_ecmp_hop_keeps_every_address_it_answered_from():
    """Continuation lines belong to the hop above them."""
    text = ("traceroute to x (1.1.1.1), 30 hops max, 60 byte packets\n"
            " 4  a.example.net (122.2.187.142)  8.323 ms\n"
            "    b.example.net (122.2.187.146)  8.015 ms\n"
            "    a.example.net (122.2.187.142)  6.227 ms\n")
    hop = parse_trace(text).hops[0]
    assert hop.addresses == ["122.2.187.142", "122.2.187.146"]
    assert hop.sent == 3, "the continuation probes were not counted"
    assert hop.min_rtt_ms == 6.227


def test_a_tracert_line_is_not_read_as_traceroute():
    """The one genuine ambiguity between the two Unix/Windows formats.

    "1  1 ms  1 ms  1 ms  192.168.1.1" is a plausible body for both readings.
    It is resolved structurally: a traceroute hop body always opens with an
    address, never with a timing.
    """
    parsed = parse_trace("  1     1 ms     1 ms     1 ms  192.168.1.1\n")
    assert parsed.parser == "tracert"
    assert parsed.hops[0].addresses == ["192.168.1.1"]
    assert parsed.hops[0].min_rtt_ms == 1.0


def test_unparseable_text_is_an_error_not_an_empty_trace():
    """An empty hop list with a confident parser name is worse than an error."""
    for junk in ("", "   \n\n", "hello world", "{\"json\": true}"):
        with pytest.raises(TraceParseError):
            parse_trace(junk)


def test_an_oversized_paste_is_refused_before_it_is_walked():
    with pytest.raises(TraceParseError):
        parse_trace("x" * (MAX_TRACE_BYTES + 1))


@pytest.mark.parametrize("name,routable", [
    ("hnk-b4-link.ip.twelve99.net", True),
    ("122.2.187.146.static.pldt.net", True),
    ("vks19368.ip-103-5-15.asia", True),
    # Not router hostnames, and so never sent to a third party.
    ("_gateway", False),
    ("router", False),
    ("???", False),
    ("192.168.1.1", False),
    ("2001:db8::1", False),
    ("", False),
    ("printer.local", False),
])
def test_only_real_router_hostnames_may_leave_this_server(name, routable):
    """The gate on what reaches CAIDA Hoiho and the hostname cache."""
    assert is_routable_hostname(name) is routable
