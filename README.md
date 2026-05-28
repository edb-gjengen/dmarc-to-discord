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
| `WEBHOOK_SECRET` | *(unset)* | if set, POSTs must arrive at `/<secret>`; mismatches get `404`. Leave unset to disable the guard |
| `LISTEN_HOST` | `127.0.0.1` | bind address |
| `LISTEN_PORT` | `8080` | bind port |

When the relay is reachable beyond a trusted private network, set `WEBHOOK_SECRET` to a long random string (e.g. `openssl rand -hex 32`) and put it in the parsedmarc URL — it's a shared secret, so keep TLS in front of it. The secret is compared in constant time, and the health endpoints (`/`, `/health`, `/healthz`) stay open regardless.

## Running

This project uses [uv](https://docs.astral.sh/uv/) for Python and dependency management.

```sh
uv run dmarc-to-discord
# or, for local hacking:
DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/... uv run dmarc-to-discord
```

`GET /`, `/health`, and `/healthz` return `200 ok` for liveness checks.

## Wiring up parsedmarc

In `parsedmarc.ini`:

```ini
[webhook]
aggregate_url = http://127.0.0.1:8080/
# with WEBHOOK_SECRET set:
# aggregate_url = https://dmarc.example.com/<secret>
```

(parsedmarc also supports `forensic_url` and `smtp_tls_url`; this relay currently only handles the aggregate-report schema.)

## Running with Docker

The included `Dockerfile` builds the service with uv. The image:

- exposes port `8080` and binds to `0.0.0.0` inside the container (override with `LISTEN_PORT` / `LISTEN_HOST`);
- requires the `DISCORD_WEBHOOK_URL` environment variable;
- honors `WEBHOOK_SECRET` for the path-based auth guard (recommended when public);
- runs as an unprivileged user;
- serves `/healthz` (returns `200 ok`) for container health checks.

```sh
docker build -t dmarc-to-discord .
docker run -p 8080:8080 \
  -e DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/... \
  -e WEBHOOK_SECRET=$(openssl rand -hex 32) \
  dmarc-to-discord
```

Any platform that builds from a Dockerfile can deploy it: point it at this
repository, set `DISCORD_WEBHOOK_URL`, expose port `8080`, and use `/healthz`
as the health check.

## Notes

- The server speaks plain HTTP. Terminate TLS in front of it, or keep it on a private network with parsedmarc.
- Discord 429s are honored via `retry_after`; there's a 0.5 s gap between messages to stay friendly to the rate limiter.
- No persistence — if Discord is down when a report arrives, the report is dropped (parsedmarc will not retry).
