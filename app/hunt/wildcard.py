"""Wildcard and registry-landing detection for the Phishing Domain Hunt.

Some registries answer every label under a TLD with the same address or a registry
landing page. dot.ph answers any unregistered .ph, .com.ph, .net.ph and .org.ph
label with 45.79.222.138, so a permutation like mmdalogin.ph "resolves" without
anyone having registered it. A candidate whose answer matches that control answer
is NOT a real registration and must not be listed or scored.

Per TLD per run we resolve random control labels and compare each candidate's
answer (its IPs and CNAME) against the control. The signature is built from
answers, not guessed. A real registration resolves to its own address, which does
not match the control, so it is kept. No em dashes in this module.
"""
from __future__ import annotations

import os

from app.scanner.scope import registrable


def random_label(n: int = 14) -> str:
    """A random, almost-certainly-unregistered label."""
    return "zq" + os.urandom(16).hex()[:n]


def suffix_of(domain: str) -> str:
    """The registry suffix used as the control key: the public suffix of the
    registrable domain (ph, com.ph, com, xyz, ...). Falls back to the last label."""
    reg = registrable(domain) or domain
    return reg.split(".", 1)[1] if "." in reg else reg


def signature_from(answers: list) -> dict:
    """Build a wildcard signature from control-label resolve results. A TLD is a
    wildcard only if a random label actually resolved."""
    ips = set()
    cnames = set()
    hits = 0
    for a in answers or []:
        aips = set(a.get("ips") or [])
        if aips:
            hits += 1
            ips |= aips
        if a.get("cname"):
            cnames.add(a["cname"])
    return {"wildcard": hits > 0, "ips": frozenset(ips), "cnames": frozenset(cnames)}


def is_control_answer(cand_ips, cand_cname, sig: dict) -> bool:
    """True when a candidate's answer matches the TLD's wildcard control, meaning
    it is the registry catch-all and not a real registration."""
    if not sig or not sig.get("wildcard"):
        return False
    if cand_ips and (set(cand_ips) & sig["ips"]):
        return True
    if cand_cname and cand_cname in sig["cnames"]:
        return True
    return False
