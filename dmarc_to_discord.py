#!/usr/bin/env python3
"""
Relay parsedmarc aggregate-report webhooks to a Discord webhook.

parsedmarc's [webhook] aggregate_url should point at this server. Each POST
body is a single aggregate report (parsedmarc's JSON schema); we translate
it to Discord embeds and forward.

Env vars:
    DISCORD_WEBHOOK_URL   required
    WEBHOOK_SECRET        optional; if set, POSTs must arrive at /<secret>
    LISTEN_HOST           default 127.0.0.1
    LISTEN_PORT           default 8080
"""

from __future__ import annotations

import hmac
import json
import logging
import os
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import urlsplit

import requests

DISCORD_WEBHOOK_URL = os.environ.get("DISCORD_WEBHOOK_URL", "")
WEBHOOK_SECRET = os.environ.get("WEBHOOK_SECRET", "")
LISTEN_HOST = os.environ.get("LISTEN_HOST", "127.0.0.1")
LISTEN_PORT = int(os.environ.get("LISTEN_PORT", "8080"))

# Discord's limits: embeds per message, characters in one field's value, and characters
# across all embeds in a message (titles, field names and values).
MAX_EMBEDS_PER_MESSAGE = 10
MAX_FIELD_VALUE_LEN = 1024
MAX_MESSAGE_EMBED_CHARS = 6000

COLOR_PASS, COLOR_PARTIAL, COLOR_FAIL, COLOR_INFO = 0x2ECC71, 0xF39C12, 0xE74C3C, 0x3498DB


def val(d, key, default="—"):
    """d[key], or `default` when the key is missing or its value is None or empty.

    parsedmarc sends absent report fields as null, so .get(key, default) alone would
    print "None".
    """
    v = (d or {}).get(key)
    return default if v is None or v == "" else v


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

    reporter_lines = [val(meta, "org_name", "unknown"), val(meta, "org_email", "")]
    if extra := meta.get("org_extra_contact_info"):
        reporter_lines.append(extra)
    if generator := meta.get("generator"):  # RFC 9990
        reporter_lines.append(f"*{generator}*")

    # RFC 7489 reports carry pct and fo; RFC 9990 ones drop pct and add np (policy for
    # non-existent subdomains), t (testing mode) and the policy discovery method.
    # Each is shown only when the report has it.
    p_line = f"**p / sp:** `{val(policy, 'p', '?')}` / `{val(policy, 'sp')}`"
    if np := policy.get("np"):
        p_line = (f"**p / sp / np:** `{val(policy, 'p', '?')}` / `{val(policy, 'sp')}` "
                  f"/ `{np}`")
    extras = [f"**{label}:** `{policy[key]}`" for key, label in
              (("pct", "pct"), ("fo", "fo"), ("testing", "t"), ("discovery_method", "discovery"))
              if policy.get(key) not in (None, "")]
    if (policy.get("testing") or "").lower() == "y":
        extras.append("*(testing mode)*")
    policy_lines = [f"**Domain:** `{val(policy, 'domain', '?')}`", p_line,
                    f"**adkim / aspf:** `{val(policy, 'adkim')}` / `{val(policy, 'aspf')}`"]
    if extras:
        policy_lines.append("  •  ".join(extras))

    fields = [
        {"name": "Reporter",
         "value": "\n".join(filter(None, reporter_lines)), "inline": True},
        {"name": "Report ID", "value": f"`{val(meta, 'report_id', 'unknown')}`", "inline": True},
        {"name": "Timespan (UTC)",
         "value": f"{val(meta, 'begin_date', '?')} →\n{val(meta, 'end_date', '?')}", "inline": False},
        {"name": "Published Policy", "value": truncate("\n".join(policy_lines)), "inline": False},
        {"name": "Summary",
         "value": f"**Records:** {len(records)}\n**Messages:** {total}\n**DMARC pass:** {passing} / {total}",
         "inline": False},
    ]
    errors = meta.get("errors") or []
    if errors:
        fields.append({"name": "Errors",
                       "value": truncate("\n".join(f"• {e}" for e in errors)), "inline": False})
    return {"title": f"DMARC Aggregate Report — {val(policy, 'domain', 'unknown')}",
            "color": COLOR_PARTIAL if errors else COLOR_INFO, "fields": fields}


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
        parts.append(f"SPF passed on `{val(spf_pass, 'domain', '?')}` (not aligned with `{header_from}`)")
    else:
        worst = spf_results[0]
        parts.append(f"SPF `{val(worst, 'result', '?')}` on `{val(worst, 'domain', '?')}`")

    dkim_pass = next((r for r in dkim_results if (r.get("result") or "").lower() == "pass"), None)
    if not dkim_results:
        parts.append("DKIM not signed")
    elif dkim_pass:
        parts.append(f"DKIM passed on `{val(dkim_pass, 'domain', '?')}` (not aligned with `{header_from}`)")
    else:
        failed = ", ".join(f"`{val(r, 'domain', '?')}`/`{val(r, 'selector', '?')}`→`{val(r, 'result', '?')}`"
                           for r in dkim_results)
        parts.append(f"DKIM failed ({failed})")

    return "❌ **DMARC fail** — " + "; ".join(parts)


def build_record_embed(record, idx, total, policy_domain=None):
    src, align = record.get("source", {}), record.get("alignment", {})
    pol, ids, auth = record.get("policy_evaluated", {}), record.get("identifiers", {}), record.get("auth_results", {})
    rdns = src.get("reverse_dns") or "—"
    asn = src.get("asn")
    as_str = f"AS{asn} ({val(src, 'as_name', '?')})" if asn else "—"
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
                  f"**IP:** `{val(src, 'ip_address', '?')}` ({val(src, 'country', '??')})\n"
                  f"**rDNS:** `{rdns}`\n**ASN:** {as_str}", "inline": False},
    ]
    if verdict := diagnose_record(record):
        fields.append({"name": "Verdict", "value": truncate(verdict), "inline": False})
    fields += [
        {"name": "Messages", "value": f"**{record.get('count', 0)}**", "inline": True},
        {"name": "Disposition", "value": f"`{val(pol, 'disposition', '?')}`", "inline": True},
        {"name": "Identifiers", "value": "\n".join(from_lines), "inline": False},
        {"name": "Alignment",
         "value": f"{bool_icon(align.get('dmarc'))} DMARC\n"
                  f"{bool_icon(align.get('spf'))} SPF\n"
                  f"{bool_icon(align.get('dkim'))} DKIM", "inline": True},
        {"name": "Policy Evaluated",
         "value": f"{result_icon(pol.get('spf'))} SPF: `{val(pol, 'spf', '?')}`\n"
                  f"{result_icon(pol.get('dkim'))} DKIM: `{val(pol, 'dkim', '?')}`", "inline": True},
    ]
    for k, label, scope_key in (("dkim", "Auth: DKIM", "selector"), ("spf", "Auth: SPF", "scope")):
        results = auth.get(k, [])
        if not results:
            continue
        # human_result (RFC 9990) is the reporter's own note, such as "2048-bit key".
        lines = [f"{result_icon(r.get('result'))} `{val(r, 'domain', '?')}` "
                 f"({scope_key}=`{val(r, scope_key, '?')}`) → `{val(r, 'result', '?')}`"
                 + (f" — {r['human_result']}" if r.get("human_result") else "")
                 for r in results]
        fields.append({"name": label, "value": truncate("\n".join(lines)), "inline": False})
    if overrides := (pol.get("policy_override_reasons") or []):
        lines = [f"• `{val(o, 'type', '?')}`: {val(o, 'comment', '') or '(no comment)'}"
                 for o in overrides]
        fields.append({"name": "Override Reasons", "value": truncate("\n".join(lines)), "inline": False})
    return {"title": f"Record {idx}/{total} — {val(src, 'ip_address', '?')}",
            "color": record_color(record), "fields": fields}


def embed_chars(embed):
    """The characters Discord counts toward MAX_MESSAGE_EMBED_CHARS for one embed."""
    return len(embed.get("title", "")) + sum(
        len(f["name"]) + len(f["value"]) for f in embed.get("fields", []))


def build_messages(report):
    """The Discord webhook payloads for one report: its embeds, packed in order into
    messages within MAX_EMBEDS_PER_MESSAGE and MAX_MESSAGE_EMBED_CHARS."""
    embeds = [build_metadata_embed(report)]
    records = report.get("records", [])
    policy_domain = (report.get("policy_published") or {}).get("domain")
    for i, rec in enumerate(records, start=1):
        embeds.append(build_record_embed(rec, i, len(records), policy_domain))

    batches, batch, chars = [], [], 0
    for embed in embeds:
        size = embed_chars(embed)
        if batch and (len(batch) == MAX_EMBEDS_PER_MESSAGE
                      or chars + size > MAX_MESSAGE_EMBED_CHARS):
            batches.append(batch)
            batch, chars = [], 0
        batch.append(embed)
        chars += size
    if batch:
        batches.append(batch)
    return [{"embeds": b, "username": "parsedmarc"} for b in batches]


def send_to_discord(report):
    for payload in build_messages(report):
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
    def _authorized(self) -> bool:
        # When no secret is configured the guard is disabled (local convenience).
        # Otherwise the request path must equal "/<secret>"; parsedmarc preserves
        # the full aggregate_url, so the secret rides along in the path. Constant-
        # time compare avoids leaking the secret via response timing.
        if not WEBHOOK_SECRET:
            return True
        path = urlsplit(self.path).path
        return hmac.compare_digest(path, "/" + WEBHOOK_SECRET)

    def do_POST(self):
        if not self._authorized():
            # 404 (not 401) so the endpoint doesn't advertise that it exists.
            self.send_error(404)
            return
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
    if WEBHOOK_SECRET:
        logging.info("secret guard enabled; POST to /<WEBHOOK_SECRET>")
    else:
        logging.warning("WEBHOOK_SECRET unset; accepting unauthenticated POSTs on any path")
    srv.serve_forever()


if __name__ == "__main__":
    main()
