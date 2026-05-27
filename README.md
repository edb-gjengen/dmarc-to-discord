# dmarc-to-discord

A tiny HTTP relay that turns [parsedmarc](https://github.com/domainaware/parsedmarc) aggregate-report webhooks into nicely formatted Discord embeds.

parsedmarc parses DMARC aggregate reports from your inbox and POSTs each one as JSON to a webhook URL of your choosing. This service is that webhook: it listens for parsedmarc's POSTs, builds one metadata embed plus one embed per record (source IP, alignment, disposition, auth results, override reasons), and forwards them to a Discord channel.

## How it looks

Each report produces:

- **1 metadata embed** — reporter, report ID, timespan, published policy (`p`, `sp`, `adkim`, `aspf`, `pct`, `fo`), and a pass/total summary.
- **1 embed per record** — source IP/country/rDNS/ASN, message count, disposition, header-from, DMARC/SPF/DKIM alignment, policy-evaluated SPF/DKIM, raw auth results, and any policy override reasons.

Embeds are colored green (DMARC aligned), red (quarantine/reject), or orange (anything else). Discord allows max 10 embeds per message, so larger reports are split across multiple messages.

## Configuration

Environment variables:

| Variable | Default | Description |
| --- | --- | --- |
| `DISCORD_WEBHOOK_URL` | *(required)* | Discord channel webhook URL |
| `LISTEN_HOST` | `127.0.0.1` | bind address |
| `LISTEN_PORT` | `8080` | bind port |

## Running

Requires Python 3.9+ and `requests`.

```sh
pip install requests
DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/... ./dmarc_to_discord.py
```

`GET /`, `/health`, and `/healthz` return `200 ok` for liveness checks.

## Wiring up parsedmarc

In `parsedmarc.ini`:

```ini
[webhook]
aggregate_url = http://127.0.0.1:8080/
```

(parsedmarc also supports `forensic_url` and `smtp_tls_url`; this relay currently only handles the aggregate-report schema.)

## Running as a systemd service

A unit file is included. It expects the script at `/usr/local/bin/dmarc_to_discord.py` and the webhook URL in `/etc/dmarc-to-discord.env`:

```sh
sudo install -m 0755 dmarc_to_discord.py /usr/local/bin/
sudo install -m 0644 dmarc-to-discord.service /etc/systemd/system/
echo 'DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/...' | sudo tee /etc/dmarc-to-discord.env
sudo chmod 0600 /etc/dmarc-to-discord.env
sudo systemctl daemon-reload
sudo systemctl enable --now dmarc-to-discord.service
```

The unit runs under `DynamicUser=` with the filesystem locked down (`ProtectSystem=strict`, `ProtectHome=true`, no kernel/cgroup access, network restricted to `AF_INET`/`AF_INET6`) and is ordered `Before=parsedmarc.service` so parsedmarc's first POSTs aren't refused.

## Notes

- The server speaks plain HTTP. Bind to `127.0.0.1` (the default) and run parsedmarc on the same host, or terminate TLS in front of it.
- Discord 429s are honored via `retry_after`; there's a 0.5 s gap between messages to stay friendly to the rate limiter.
- No persistence — if Discord is down when a report arrives, the report is dropped (parsedmarc will not retry).
