"""Mock Gmail & Bank API server for GVM demo.

Simulates Gmail API and Bank API endpoints so the LangChain demo
can run end-to-end without external credentials.

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
    """Handles Gmail API and Bank API mock endpoints."""

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
        # GET /gmail/v1/users/me/messages — list inbox
        if self.path == "/gmail/v1/users/me/messages":
            self._send_json({
                "messages": [
                    {"id": m["id"], "threadId": m["threadId"]}
                    for m in FAKE_MESSAGES
                ],
                "resultSizeEstimate": len(FAKE_MESSAGES),
            })
            return

        # GET /gmail/v1/users/me/messages/{id} — get single message
        if self.path.startswith("/gmail/v1/users/me/messages/"):
            msg_id = self.path.split("/")[-1]
            for msg in FAKE_MESSAGES:
                if msg["id"] == msg_id:
                    self._send_json(msg)
                    return
            self._send_json({"error": {"code": 404, "message": "Not found"}}, 404)
            return

        self._send_json({"error": "Unknown endpoint"}, 404)

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length) if content_length > 0 else b""

        # POST /gmail/v1/users/me/messages/send — send email
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

        # POST /transfer/{id} — bank transfer (mock; normally blocked by SRR)
        if self.path.startswith("/transfer/"):
            self._send_json({
                "status": "completed",
                "transfer_id": self.path.split("/")[-1],
            })
            return

        self._send_json({"error": "Unknown endpoint"}, 404)

    def do_DELETE(self):
        # DELETE /gmail/v1/users/me/messages/{id} — delete message
        if self.path.startswith("/gmail/v1/users/me/messages/"):
            msg_id = self.path.split("/")[-1]
            self._send_json({"deleted": msg_id})
            return

        self._send_json({"error": "Unknown endpoint"}, 404)


def start(port=None):
    """Start the mock server in a background daemon thread. Returns the server instance."""
    port = port or MOCK_PORT
    server = HTTPServer(("127.0.0.1", port), MockHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


if __name__ == "__main__":
    print(f"Mock Gmail/Bank server listening on http://127.0.0.1:{MOCK_PORT}")
    server = HTTPServer(("127.0.0.1", MOCK_PORT), MockHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down.")
        server.shutdown()
