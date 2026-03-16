"""Mock API server for GVM demos — Gmail, Bank, DevOps, Analytics.

Simulates multiple API endpoints so LLM-powered agents can run
end-to-end without external credentials.

Usage:
    python -m gvm.mock_server          # standalone (port 9090)
    from gvm.mock_server import start  # embedded in demo script
"""

import json
import os
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler

MOCK_PORT = int(os.environ.get("GVM_MOCK_PORT", "9090"))

# ─── Fake Gmail Data ───

FAKE_MESSAGES = [
    {
        "id": "msg-001",
        "threadId": "thread-001",
        "labelIds": ["INBOX", "UNREAD"],
        "snippet": "Please review the Q4 budget. Total: $2.4M. Need approval by Friday.",
        "payload": {
            "headers": [
                {"name": "From", "value": "cfo@acme.com"},
                {"name": "To", "value": "agent@acme.com"},
                {"name": "Subject", "value": "Q4 Budget Approval"},
                {"name": "Date", "value": "2026-03-14T09:00:00Z"},
            ]
        },
    },
    {
        "id": "msg-002",
        "threadId": "thread-002",
        "labelIds": ["INBOX"],
        "snippet": "Welcome packet for 3 new engineers starting Monday. Please forward to IT.",
        "payload": {
            "headers": [
                {"name": "From", "value": "hr@acme.com"},
                {"name": "To", "value": "agent@acme.com"},
                {"name": "Subject", "value": "New Hire Onboarding"},
                {"name": "Date", "value": "2026-03-14T08:30:00Z"},
            ]
        },
    },
    {
        "id": "msg-003",
        "threadId": "thread-003",
        "labelIds": ["INBOX", "IMPORTANT"],
        "snippet": "Payment of $15,000 due by end of month. Wire to account #8842-XXXX.",
        "payload": {
            "headers": [
                {"name": "From", "value": "billing@vendor.com"},
                {"name": "To", "value": "agent@acme.com"},
                {"name": "Subject", "value": "Invoice #8842 — Payment Due"},
                {"name": "Date", "value": "2026-03-13T16:45:00Z"},
            ]
        },
    },
]


def _get_header(msg, name):
    for h in msg["payload"]["headers"]:
        if h["name"] == name:
            return h["value"]
    return None


class MockHandler(BaseHTTPRequestHandler):
    """Handles Gmail, Bank, DevOps, and Analytics mock endpoints."""

    def log_message(self, format, *args):
        """Suppress default stderr logging."""
        pass

    def _send_json(self, data, status=200):
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        # ── Gmail ──
        if self.path == "/gmail/v1/users/me/messages":
            self._send_json({
                "messages": [
                    {"id": m["id"], "threadId": m["threadId"]}
                    for m in FAKE_MESSAGES
                ],
                "resultSizeEstimate": len(FAKE_MESSAGES),
            })
            return

        if self.path.startswith("/gmail/v1/users/me/messages/"):
            msg_id = self.path.split("/")[-1]
            for msg in FAKE_MESSAGES:
                if msg["id"] == msg_id:
                    self._send_json(msg)
                    return
            self._send_json({"error": {"code": 404, "message": "Not found"}}, 404)
            return

        # ── Finance: refund lookup ──
        if self.path.startswith("/refunds/"):
            refund_id = self.path.split("/")[-1]
            self._send_json({
                "refund_id": refund_id,
                "status": "pending_review",
                "amount": 149.99,
                "customer": "customer-8842",
                "reason": "Product defect",
                "created_at": "2026-03-10T14:30:00Z",
            })
            return

        # ── Finance: audit log ──
        if self.path.startswith("/audit-log/"):
            period = self.path.split("/")[-1]
            self._send_json({
                "period": period,
                "entries": [
                    {"timestamp": "2026-03-14T09:00:00Z", "action": "refund.created", "actor": "finance-bot"},
                    {"timestamp": "2026-03-14T09:01:00Z", "action": "email.sent", "actor": "finance-bot"},
                ],
                "total": 2,
            })
            return

        # ── DevOps: deployment status ──
        if self.path == "/deployments/latest":
            self._send_json({
                "deployment_id": "deploy-2026-03-14-001",
                "status": "running",
                "image": "app:v2.3.0",
                "environment": "production",
                "replicas": 3,
                "uptime": "72h",
                "health": "healthy",
            })
            return

        # ── Analytics: page views ──
        if self.path.startswith("/analytics/page-views"):
            self._send_json({
                "metric": "page_views",
                "range": "7d",
                "total": 284503,
                "daily_avg": 40643,
                "top_pages": [
                    {"path": "/dashboard", "views": 89201},
                    {"path": "/settings", "views": 45302},
                    {"path": "/billing", "views": 31004},
                ],
            })
            return

        # ── Analytics: revenue ──
        if self.path.startswith("/analytics/revenue"):
            self._send_json({
                "metric": "revenue",
                "range": "30d",
                "total_usd": 1284500.00,
                "mrr": 428166.67,
                "growth_pct": 12.3,
                "top_plans": [
                    {"plan": "enterprise", "revenue": 842000},
                    {"plan": "pro", "revenue": 312500},
                    {"plan": "starter", "revenue": 130000},
                ],
            })
            return

        # ── Analytics: config/.env (sensitive — should be blocked by GVM) ──
        if self.path == "/config/.env":
            self._send_json({
                "STRIPE_SECRET_KEY": "sk_live_REDACTED",
                "DATABASE_URL": "postgres://admin:REDACTED@prod-db:5432/main",
                "JWT_SECRET": "REDACTED",
            })
            return

        self._send_json({"error": "Unknown endpoint"}, 404)

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length) if content_length > 0 else b""

        # ── Gmail: send email ──
        if self.path == "/gmail/v1/users/me/messages/send":
            try:
                payload = json.loads(body) if body else {}
            except json.JSONDecodeError:
                payload = {}

            self._send_json({
                "id": "msg-sent-001",
                "threadId": "thread-sent-001",
                "labelIds": ["SENT"],
                "to": payload.get("to", "unknown"),
                "subject": payload.get("subject", ""),
            })
            return

        # ── Bank: wire transfer ──
        if self.path.startswith("/transfer/"):
            self._send_json({
                "status": "completed",
                "transfer_id": self.path.split("/")[-1],
            })
            return

        # ── DevOps: deploy to environment ──
        if self.path.startswith("/deployments/"):
            try:
                payload = json.loads(body) if body else {}
            except json.JSONDecodeError:
                payload = {}
            env = self.path.split("/")[-1]
            self._send_json({
                "deployment_id": f"deploy-{env}-001",
                "status": "deploying",
                "environment": env,
                "image": payload.get("image", "app:latest"),
                "replicas": payload.get("replicas", 1),
            })
            return

        # ── External: catch-all for exfiltration endpoints ──
        if self.path == "/collect":
            self._send_json({"status": "received"})
            return

        self._send_json({"error": "Unknown endpoint"}, 404)

    def do_DELETE(self):
        # ── Gmail: delete message ──
        if self.path.startswith("/gmail/v1/users/me/messages/"):
            msg_id = self.path.split("/")[-1]
            self._send_json({"deleted": msg_id})
            return

        # ── Gmail: batch delete ──
        if self.path == "/gmail/v1/users/me/messages/batch-delete":
            self._send_json({"deleted": "batch"})
            return

        # ── Finance: delete audit log ──
        if self.path.startswith("/audit-log/"):
            period = self.path.split("/")[-1]
            self._send_json({"deleted": period})
            return

        # ── DevOps: drop database ──
        if self.path.startswith("/database/"):
            self._send_json({"status": "dropped"})
            return

        self._send_json({"error": "Unknown endpoint"}, 404)


def start(port=None):
    """Start the mock server in a background daemon thread. Returns the server instance.

    Raises RuntimeError if GVM_ENV is set to 'production' to prevent
    accidental use of mock endpoints in production deployments.
    """
    if os.environ.get("GVM_ENV", "").lower() == "production":
        raise RuntimeError(
            "Mock server cannot start in production (GVM_ENV=production). "
            "Configure real API endpoints instead."
        )
    port = port or MOCK_PORT
    server = HTTPServer(("127.0.0.1", port), MockHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


if __name__ == "__main__":
    print(f"Mock API server listening on http://127.0.0.1:{MOCK_PORT}")
    server = HTTPServer(("127.0.0.1", MOCK_PORT), MockHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down.")
        server.shutdown()
