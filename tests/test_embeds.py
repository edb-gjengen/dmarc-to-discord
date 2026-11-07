"""Embeds built from parsedmarc 11.2.1's output for the sample aggregate reports in its
repository (samples/aggregate, parsed with --offline). The 2286-record report is cut to
its first 30 records.

    uv run python -m unittest
"""

import copy
import json
import unittest
from pathlib import Path

import dmarc_to_discord as d2d

FIXTURE = Path(__file__).parent / "fixtures" / "parsedmarc-11.2.1-samples.json"
REPORTS = json.loads(FIXTURE.read_text())
RFC9990_ID = "3v98abbp8ya9n3va8yr8oa3ya"


def texts(embed):
    yield embed["title"]
    for f in embed["fields"]:
        yield f["name"]
        yield f["value"]


def field(embed, name):
    return next(f["value"] for f in embed["fields"] if f["name"] == name)


class DiscordLimits(unittest.TestCase):
    def test_every_report_fits(self):
        for report in REPORTS:
            rid = report["report_metadata"]["report_id"]
            with self.subTest(report=rid):
                messages = d2d.build_messages(report)
                embeds = [e for m in messages for e in m["embeds"]]
                self.assertEqual(len(embeds), 1 + len(report["records"]))
                for m in messages:
                    self.assertLessEqual(len(m["embeds"]), d2d.MAX_EMBEDS_PER_MESSAGE)
                    self.assertLessEqual(sum(map(d2d.embed_chars, m["embeds"])),
                                         d2d.MAX_MESSAGE_EMBED_CHARS)
                for e in embeds:
                    self.assertLessEqual(len(e["title"]), 256)
                    self.assertLessEqual(len(e["fields"]), 25)
                    for f in e["fields"]:
                        self.assertLessEqual(len(f["name"]), 256)
                        self.assertLessEqual(len(f["value"]), d2d.MAX_FIELD_VALUE_LEN)

    def test_large_embeds_split_by_size(self):
        report = copy.deepcopy(next(r for r in REPORTS if len(r["records"]) == 30))
        for rec in report["records"]:
            rec["auth_results"]["dkim"] = [
                {"domain": f"d{i}.example.com", "selector": "s" * 40, "result": "pass"}
                for i in range(12)]
        messages = d2d.build_messages(report)
        self.assertTrue(any(len(m["embeds"]) < d2d.MAX_EMBEDS_PER_MESSAGE
                            for m in messages[:-1]), "nothing was split by size")
        for m in messages:
            self.assertLessEqual(sum(map(d2d.embed_chars, m["embeds"])),
                                 d2d.MAX_MESSAGE_EMBED_CHARS)


class NullFields(unittest.TestCase):
    def test_no_none_in_any_embed(self):
        for report in REPORTS:
            for m in d2d.build_messages(report):
                for e in m["embeds"]:
                    for t in texts(e):
                        self.assertNotIn("None", t, f"{e['title']}: {t!r}")


class Rfc9990(unittest.TestCase):
    def setUp(self):
        report = next(r for r in REPORTS if r["report_metadata"]["report_id"] == RFC9990_ID)
        self.meta = d2d.build_metadata_embed(report)
        self.record = d2d.build_record_embed(report["records"][0], 1, 1, "example.com")

    def test_policy_shows_new_tags_and_no_pct(self):
        policy = field(self.meta, "Published Policy")
        self.assertIn("**p / sp / np:** `quarantine` / `none` / `none`", policy)
        self.assertIn("**t:** `n`", policy)
        self.assertIn("**discovery:** `treewalk`", policy)
        self.assertNotIn("pct", policy)
        self.assertNotIn("testing mode", policy)

    def test_generator_under_reporter(self):
        self.assertIn("*Example DMARC Aggregate Reporter v1.2*", field(self.meta, "Reporter"))

    def test_pass_disposition(self):
        self.assertEqual(field(self.record, "Disposition"), "`pass`")

    def test_testing_mode_flagged(self):
        report = next(r for r in REPORTS if r["policy_published"].get("testing") == "y")
        self.assertIn("*(testing mode)*", field(d2d.build_metadata_embed(report), "Published Policy"))


class HumanResult(unittest.TestCase):
    def test_appended_to_auth_line(self):
        report = next(r for r in REPORTS for rec in r["records"]
                      for a in rec["auth_results"]["dkim"] if a.get("human_result"))
        rec = next(rec for rec in report["records"]
                   if any(a.get("human_result") for a in rec["auth_results"]["dkim"]))
        embed = d2d.build_record_embed(rec, 1, 1)
        self.assertIn("— 2048-bit key", field(embed, "Auth: DKIM"))


class Rfc7489(unittest.TestCase):
    def test_pct_and_fo_shown_when_present(self):
        report = next(r for r in REPORTS
                      if r["policy_published"].get("pct") and r["policy_published"].get("fo"))
        policy = field(d2d.build_metadata_embed(report), "Published Policy")
        self.assertIn(f"**pct:** `{report['policy_published']['pct']}`", policy)
        self.assertIn(f"**fo:** `{report['policy_published']['fo']}`", policy)
        self.assertIn("**p / sp:**", policy)


if __name__ == "__main__":
    unittest.main()
