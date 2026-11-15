from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path

NODE_DIR = Path(__file__).resolve().parents[1]
if str(NODE_DIR) not in sys.path:
    sys.path.insert(0, str(NODE_DIR))

_TEMP_DIR = tempfile.TemporaryDirectory()
os.environ["OPENSHIELD_NODE_DB_PATH"] = str(Path(_TEMP_DIR.name) / "test-node.sqlite3")

try:
    import app as node_app  # noqa: E402
    from fastapi.testclient import TestClient

    HAS_FASTAPI = True
    HAS_TEST_CLIENT = True
except Exception:
    node_app = None  # type: ignore[assignment]
    TestClient = None  # type: ignore[assignment]
    HAS_FASTAPI = False
    HAS_TEST_CLIENT = False


@unittest.skipUnless(HAS_FASTAPI and node_app is not None, "fastapi not installed in host python")
class TestFastApiNode(unittest.TestCase):
    def test_router_access_line_parser_and_ip_normalization(self) -> None:
        self.assertEqual(node_app._normalize_ip("::ffff:203.0.113.50:54321"), "203.0.113.50")
        self.assertFalse(node_app._is_usable_source_ip("127.0.0.1"))
        self.assertTrue(node_app._is_usable_source_ip("203.0.113.50"))

        sample_log = "\n".join(
            [
                "dropbear[101]: Bad password attempt for root from 203.0.113.50:55001",
                "dropbear[102]: Bad password attempt for root from 203.0.113.50:55002",
                "uhttpd[200]: luci: failed login for admin from 198.51.100.22",
                "kernel: fw4 DROP IN=wan SRC=192.0.2.88 DST=192.168.1.1 PROTO=TCP DPT=22",
            ]
        )
        entries = node_app._parse_router_access_lines(sample_log, "2026-11-15T01:00:00Z")
        self.assertEqual(len(entries), 3)
        ssh = next(e for e in entries if e["service"] == "ssh")
        self.assertEqual(ssh["attemptsCount"], 2)
        self.assertEqual(ssh["srcIp"], "203.0.113.50")

    def test_http_endpoints_if_httpx_available(self) -> None:
        if not HAS_TEST_CLIENT or TestClient is None:
            self.skipTest("fastapi TestClient (httpx) unavailable in environment")

        try:
            client = TestClient(node_app.app)
        except RuntimeError:
            self.skipTest("httpx not installed for FastAPI TestClient")

        health_res = client.get("/health")
        self.assertEqual(health_res.status_code, 200)
        self.assertEqual(health_res.json()["status"], "ready")

        raw_log = "dropbear[99]: Bad password attempt for root from 203.0.113.99:44112\n"
        r1 = client.post(
            "/api/v1/ingest/router-logs?sourceIntegrationId=openwrt-node",
            content=raw_log,
            headers={"content-type": "text/plain"},
        )
        self.assertEqual(r1.status_code, 202)
        self.assertEqual(r1.json()["eventsIngested"], 1)

        r2 = client.post(
            "/api/v1/ingest/router-logs",
            json={
                "sourceIntegrationId": "openwrt-node",
                "entries": [{"srcIp": "198.51.100.80", "service": "luci", "attemptsCount": 4}],
            },
        )
        self.assertEqual(r2.status_code, 202)
        self.assertEqual(r2.json()["eventsIngested"], 1)

        events_res = client.get("/api/v1/events?limit=10")
        self.assertEqual(events_res.status_code, 200)
        events = events_res.json()["events"]
        self.assertGreaterEqual(len(events), 2)
        self.assertTrue(any(ev["eventType"] == "router.access_attempt" for ev in events))


if __name__ == "__main__":
    unittest.main()
