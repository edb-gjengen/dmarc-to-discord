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


def result_icon(r): return {"pass": "✅", "fail": "❌", "softfail": "⚠️",
                            "neutral": "➖", "temperror": "⚠️", "permerror": "⚠️"}.get(r or "", "❓")


def bool_icon(b): return "✅" if b else "❌"


def record_color(record):
    if record.get("alignment", {}).get("dmarc"):
        return COLOR_PASS
    if record.get("policy_evaluated", {}).get("disposition") in ("quarantine", "reject"):
        return COLOR_FAIL
    return COLOR_PARTIAL


def build_metadata_embed(report):
    meta = report.get("report_metadata", {})
    policy = report.get("policy_published", {})
    records = report.get("records", [])
    total = sum(r.get("count", 0) for r in records)
    passing = sum(r.get("count", 0) for r in records if r.get("alignment", {}).get("dmarc"))

    fields = [
        {"name": "Reporter",
         "value": f"{meta.get('org_name', 'unknown')}\n{meta.get('org_email', '')}", "inline": True},
        {"name": "Report ID", "value": f"`{meta.get('report_id', 'unknown')}`", "inline": True},
        {"name": "Timespan (UTC)",
         "value": f"{meta.get('begin_date', '?')} →\n{meta.get('end_date', '?')}", "inline": False},
        {"name": "Published Policy",
         "value": (f"**Domain:** `{policy.get('domain', '?')}`\n"
                   f"**p / sp:** `{policy.get('p', '?')}` / `{policy.get('sp', '?')}`\n"
                   f"**adkim / aspf:** `{policy.get('adkim', '?')}` / `{policy.get('aspf', '?')}`\n"
                   f"**pct:** `{policy.get('pct', '?')}`  •  **fo:** `{policy.get('fo', '?')}`"),
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


def build_record_embed(record, idx, total):
    src, align = record.get("source", {}), record.get("alignment", {})
    pol, ids, auth = record.get("policy_evaluated", {}), record.get("identifiers", {}), record.get("auth_results", {})
    rdns = src.get("reverse_dns") or "—"
    asn = src.get("asn")
    as_str = f"AS{asn} ({src.get('as_name', '?')})" if asn else "—"

    fields = [
        {"name": "Source",
         "value": f"**IP:** `{src.get('ip_address', '?')}` ({src.get('country', '??')})\n"
                  f"**rDNS:** `{rdns}`\n**ASN:** {as_str}", "inline": False},
        {"name": "Messages", "value": f"**{record.get('count', 0)}**", "inline": True},
        {"name": "Disposition", "value": f"`{pol.get('disposition', '?')}`", "inline": True},
        {"name": "Header From", "value": f"`{ids.get('header_from', '?')}`", "inline": True},
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
    for i, rec in enumerate(records, start=1):
        embeds.append(build_record_embed(rec, i, len(records)))

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
