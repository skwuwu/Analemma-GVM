#!/usr/bin/env python3
"""Mock GitHub API server for E2E tests. Avoids rate limiting."""
import http.server
import json
import sys

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 9999

ROUTES = {
    "/": json.dumps({"current_user_url": "https://api.github.com/user", "rate_limit": "mock"}),
    "/repos/skwuwu/Analemma-GVM": json.dumps({"name": "Analemma-GVM", "full_name": "skwuwu/Analemma-GVM", "private": False}),
    "/repos/t/t/issues": json.dumps([{"id": 1, "title": "test issue"}]),
    "/repos/t/t/pulls": json.dumps([]),
    "/repos/t/t/pulls/1/merge": "",  # PUT/DELETE target
    "/repos/t/t/git/refs/heads/main": "",  # DELETE target
    "/repos/t/t/commits": json.dumps([{"sha": "abc123"}]),
    "/repos/t/t/labels": json.dumps([]),
    "/repos/t/t/contents/README.md": json.dumps({"name": "README.md", "content": "dGVzdA=="}),
    "/repos/t/t/actions/runs": json.dumps({"workflow_runs": []}),
    "/repos/t/t/issues/1/comments": json.dumps([]),
    "/get": json.dumps({"url": "http://mock/get", "origin": "127.0.0.1"}),  # httpbin /get mock
    "/post": "",  # will echo body
}

def _echo_headers_payload(headers):
    """Snapshot of the auth-relevant headers the proxy actually delivered.

    Used by the credential-injection sub-tests in ec2-e2e-test.sh (Test 76):
    the proxy is supposed to strip every agent-supplied auth header and
    inject only the value configured in secrets.toml — this endpoint lets
    the test see exactly what arrived on the upstream side of the wire.
    """
    return json.dumps({
        "host": headers.get("Host", ""),
        "authorization": headers.get("Authorization", ""),
        "x_api_key": headers.get("x-api-key", ""),
        "apikey": headers.get("apikey", ""),
        "x_auth_token": headers.get("x-auth-token", ""),
        "cookie": headers.get("Cookie", ""),
    })


class MockHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        path = self.path.split("?")[0]
        if path == "/echo-headers":
            body = _echo_headers_payload(self.headers)
            status = 200
        else:
            body = ROUTES.get(path, json.dumps({"message": "Not Found", "mock": True}))
            status = 200 if path in ROUTES else 404
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(body.encode())

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length) if content_length else b""
        path = self.path.split("?")[0]
        if path == "/echo-headers":
            response = _echo_headers_payload(self.headers)
        elif path == "/post":
            # Echo body like httpbin
            response = json.dumps({"data": body.decode("utf-8", errors="replace"), "url": "http://mock/post"})
        else:
            response = ROUTES.get(path, json.dumps({"message": "accepted", "mock": True}))
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(response.encode())

    do_PUT = do_POST
    do_DELETE = do_GET
    do_PATCH = do_POST

    def log_message(self, format, *args):
        pass  # Suppress request logging

if __name__ == "__main__":
    server = http.server.HTTPServer(("127.0.0.1", PORT), MockHandler)
    print(f"Mock GitHub API on port {PORT}", flush=True)
    server.serve_forever()
