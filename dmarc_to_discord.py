#!/usr/bin/env python3
"""
Relay parsedmarc aggregate-report webhooks to a Discord webhook.

parsedmarc's [webhook] aggregate_url should point at this server. Each POST
body is a single aggregate report (parsedmarc's JSON schema); we translate
it to Discord embeds and forward.

Env vars:
    DISCORD_WEBHOOK_URL   required
    LISTEN_HOST           default 127.0.0.1
    LISTEN_PORT           default 8080
"""

from __future__ import annotations

import json
import logging
import os
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

import requests

DISCORD_WEBHOOK_URL = os.environ.get("DISCORD_WEBHOOK_URL", "")
LISTEN_HOST = os.environ.get("LISTEN_HOST", "127.0.0.1")
LISTEN_PORT = int(os.environ.get("LISTEN_PORT", "8080"))

MAX_EMBEDS_PER_MESSAGE = 10
MAX_FIELD_VALUE_LEN = 1024

COLOR_PASS, COLOR_PARTIAL, COLOR_FAIL, COLOR_INFO = 0x2ECC71, 0xF39C12, 0xE74C3C, 0x3498DB


def truncate(s: str, n: int = MAX_FIELD_VALUE_LEN) -> str:
    return s if len(s) <= n else s[: n - 3] + "..."


def result_icon(r): return {"pass": "✅", "fail": "❌", "softfail": "⚠️", "neutral": "➖",
                            "none": "➖", "temperror": "⚠️", "permerror": "⚠️"}.get(r or "", "❓")


def bool_icon(b): return "✅" if b is True else "❌" if b is False else "❔"


def record_color(record):
    # Drive color by DMARC alignment, not by disposition: on a p=none policy every
    # failure has disposition=none, and we don't want real spoofing to look the same
    # as benign forwarder noise.
    dmarc = (record.get("alignment") or {}).get("dmarc")
    if dmarc is True:
        return COLOR_PASS
    if dmarc is False:
        return COLOR_FAIL
    return COLOR_PARTIAL  # alignment missing → unknown


def build_metadata_embed(report):
    meta = report.get("report_metadata", {})
    policy = report.get("policy_published", {})
    records = report.get("records", [])
    total = sum(r.get("count", 0) for r in records)
    passing = sum(r.get("count", 0) for r in records if r.get("alignment", {}).get("dmarc"))

    reporter_lines = [meta.get("org_name", "unknown"), meta.get("org_email", "")]
    if extra := meta.get("org_extra_contact_info"):
        reporter_lines.append(extra)

    fields = [
        {"name": "Reporter",
         "value": "\n".join(filter(None, reporter_lines)), "inline": True},
        {"name": "Report ID", "value": f"`{meta.get('report_id', 'unknown')}`", "inline": True},
        {"name": "Timespan (UTC)",
         "value": f"{meta.get('begin_date', '?')} →\n{meta.get('end_date', '?')}", "inline": False},
        {"name": "Published Policy",
         "value": (f"**Domain:** `{policy.get('domain', '?')}`\n"
                   f"**p / sp:** `{policy.get('p', '?')}` / `{policy.get('sp', '?')}`\n"
                   f"**adkim / aspf:** `{policy.get('adkim', '?')}` / `{policy.get('aspf', '?')}`\n"
                   f"**pct:** `{policy.get('pct') or '100'}`  •  **fo:** `{policy.get('fo', '?')}`"),
         "inline": False},
        {"name": "Summary",
         "value": f"**Records:** {len(records)}\n**Messages:** {total}\n**DMARC pass:** {passing} / {total}",
         "inline": False},
    ]
    if errors := (meta.get("errors") or []):
        fields.append({"name": "Errors",
                       "value": truncate("\n".join(f"• {e}" for e in errors)), "inline": False})
    return {"title": f"DMARC Aggregate Report — {policy.get('domain', 'unknown')}",
            "color": COLOR_INFO, "fields": fields}


def diagnose_record(record):
    """One-line explanation of why DMARC passed or failed for this record."""
    align = record.get("alignment") or {}
    auth = record.get("auth_results") or {}
    ids = record.get("identifiers") or {}
    header_from = ids.get("header_from") or "?"
    spf_results = auth.get("spf") or []
    dkim_results = auth.get("dkim") or []

    dmarc = align.get("dmarc")
    if dmarc is None:
        return None  # parsedmarc didn't supply alignment; don't fabricate a verdict

    if dmarc:
        via = [name for name, ok in (("SPF", align.get("spf")), ("DKIM", align.get("dkim"))) if ok]
        return "✅ **DMARC pass** — aligned via " + (" + ".join(via) if via else "?")

    parts = []
    spf_pass = next((r for r in spf_results if (r.get("result") or "").lower() == "pass"), None)
    if not spf_results:
        parts.append("SPF not evaluated")
    elif spf_pass:
        parts.append(f"SPF passed on `{spf_pass.get('domain', '?')}` (not aligned with `{header_from}`)")
    else:
        worst = spf_results[0]
        parts.append(f"SPF `{worst.get('result', '?')}` on `{worst.get('domain', '?')}`")

    dkim_pass = next((r for r in dkim_results if (r.get("result") or "").lower() == "pass"), None)
    if not dkim_results:
        parts.append("DKIM not signed")
    elif dkim_pass:
        parts.append(f"DKIM passed on `{dkim_pass.get('domain', '?')}` (not aligned with `{header_from}`)")
    else:
        failed = ", ".join(f"`{r.get('domain', '?')}`/`{r.get('selector', '?')}`→`{r.get('result', '?')}`"
                           for r in dkim_results)
        parts.append(f"DKIM failed ({failed})")

    return "❌ **DMARC fail** — " + "; ".join(parts)


def build_record_embed(record, idx, total, policy_domain=None):
    src, align = record.get("source", {}), record.get("alignment", {})
    pol, ids, auth = record.get("policy_evaluated", {}), record.get("identifiers", {}), record.get("auth_results", {})
    rdns = src.get("reverse_dns") or "—"
    asn = src.get("asn")
    as_str = f"AS{asn} ({src.get('as_name', '?')})" if asn else "—"
    if asn and (as_domain := src.get("as_domain")):
        as_str += f" — `{as_domain}`"

    sender_bits = []
    if name := src.get("name"):
        sender_bits.append(f"**{name}**")
    if base := src.get("base_domain"):
        sender_bits.append(f"`{base}`")
    sender_line = " ".join(sender_bits) + "\n" if sender_bits else ""

    header_from = ids.get("header_from") or "?"
    hf_note = ""
    if policy_domain and header_from != "?" and header_from.lower() != policy_domain.lower():
        hf_note = "  *(subdomain — `sp` applies)*"
    from_lines = [f"**Header From:** `{header_from}`{hf_note}",
                  f"**Envelope From:** `{ids.get('envelope_from') or '—'}`"]
    if env_to := ids.get("envelope_to"):
        from_lines.append(f"**Envelope To:** `{env_to}`")

    fields = [
        {"name": "Source",
         "value": sender_line +
                  f"**IP:** `{src.get('ip_address', '?')}` ({src.get('country', '??')})\n"
                  f"**rDNS:** `{rdns}`\n**ASN:** {as_str}", "inline": False},
    ]
    if verdict := diagnose_record(record):
        fields.append({"name": "Verdict", "value": truncate(verdict), "inline": False})
    fields += [
        {"name": "Messages", "value": f"**{record.get('count', 0)}**", "inline": True},
        {"name": "Disposition", "value": f"`{pol.get('disposition', '?')}`", "inline": True},
        {"name": "Identifiers", "value": "\n".join(from_lines), "inline": False},
        {"name": "Alignment",
         "value": f"{bool_icon(align.get('dmarc'))} DMARC\n"
                  f"{bool_icon(align.get('spf'))} SPF\n"
                  f"{bool_icon(align.get('dkim'))} DKIM", "inline": True},
        {"name": "Policy Evaluated",
         "value": f"{result_icon(pol.get('spf'))} SPF: `{pol.get('spf', '?')}`\n"
                  f"{result_icon(pol.get('dkim'))} DKIM: `{pol.get('dkim', '?')}`", "inline": True},
    ]
    for k, label, scope_key in (("dkim", "Auth: DKIM", "selector"), ("spf", "Auth: SPF", "scope")):
        results = auth.get(k, [])
        if not results:
            continue
        lines = [f"{result_icon(r.get('result'))} `{r.get('domain', '?')}` "
                 f"({scope_key}=`{r.get(scope_key, '?')}`) → `{r.get('result', '?')}`"
                 for r in results]
        fields.append({"name": label, "value": truncate("\n".join(lines)), "inline": False})
    if overrides := (pol.get("policy_override_reasons") or []):
        lines = [f"• `{o.get('type', '?')}`: {o.get('comment', '') or '(no comment)'}"
                 for o in overrides]
        fields.append({"name": "Override Reasons", "value": truncate("\n".join(lines)), "inline": False})
    return {"title": f"Record {idx}/{total} — {src.get('ip_address', '?')}",
            "color": record_color(record), "fields": fields}


def send_to_discord(report):
    embeds = [build_metadata_embed(report)]
    records = report.get("records", [])
    policy_domain = (report.get("policy_published") or {}).get("domain")
    for i, rec in enumerate(records, start=1):
        embeds.append(build_record_embed(rec, i, len(records), policy_domain))

    for i in range(0, len(embeds), MAX_EMBEDS_PER_MESSAGE):
        payload = {"embeds": embeds[i: i + MAX_EMBEDS_PER_MESSAGE], "username": "parsedmarc"}
        while True:
            r = requests.post(DISCORD_WEBHOOK_URL, json=payload, timeout=15)
            if r.status_code == 429:
                try:
                    delay = float(r.json().get("retry_after", 1))
                except Exception:
                    delay = 1.0
                time.sleep(delay)
                continue
            r.raise_for_status()
            break
        time.sleep(0.5)


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        try:
            report = json.loads(body)
        except json.JSONDecodeError as e:
            self.send_error(400, f"invalid JSON: {e}")
            return
        try:
            send_to_discord(report)
        except Exception as e:
            logging.exception("forwarding to Discord failed")
            self.send_error(502, f"discord forward failed: {e}")
            return
        self.send_response(204)
        self.end_headers()

    def do_GET(self):
        # cheap health check
        if self.path in ("/health", "/healthz", "/"):
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"ok\n")
        else:
            self.send_error(404)

    def log_message(self, fmt, *args):
        logging.info("%s - %s", self.address_string(), fmt % args)


def main():
    if not DISCORD_WEBHOOK_URL:
        sys.exit("ERROR: DISCORD_WEBHOOK_URL required")
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s")
    srv = ThreadingHTTPServer((LISTEN_HOST, LISTEN_PORT), Handler)
    logging.info("listening on %s:%d", LISTEN_HOST, LISTEN_PORT)
    srv.serve_forever()


if __name__ == "__main__":
    main()
