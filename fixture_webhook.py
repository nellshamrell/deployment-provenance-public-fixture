"""Fixture-only GitHub webhook intake; never approves a deployment itself."""

import hashlib
import hmac
import json
import os
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


REPO = "nellshamrell/deployment-provenance-public-fixture"
ENVIRONMENTS = frozenset({
    "force-app-provenance", "force-app-reject", "force-app-conflict",
    "force-app-missing", "force-app-nonconflict",
})
CALLBACK = re.compile(
    rf"https://api\.github\.com/repos/{re.escape(REPO)}/actions/runs/"
    r"([1-9][0-9]*)/deployment_protection_rule"
)
BODY_LIMIT = 256 * 1024


def inspect_event(secret, event, signature, body):
    expected = "sha256=" + hmac.new(secret, body, hashlib.sha256).hexdigest()
    if not isinstance(signature, str) or not re.fullmatch(r"sha256=[0-9a-f]{64}", signature):
        return 401, None
    if not hmac.compare_digest(expected, signature):
        return 401, None
    if event == "ping":
        return 204, None
    if event != "deployment_protection_rule":
        return 400, None
    try:
        payload = json.loads(body)
    except (ValueError, UnicodeError):
        return 400, None
    if not isinstance(payload, dict) or payload.get("action") != "requested":
        return 400, None
    repo = payload.get("repository")
    installation = payload.get("installation")
    env = payload.get("environment")
    url = payload.get("deployment_callback_url")
    match = CALLBACK.fullmatch(url) if isinstance(url, str) else None
    if not (
        isinstance(repo, dict) and repo.get("full_name") == REPO
        and isinstance(env, str) and env in ENVIRONMENTS
        and isinstance(installation, dict)
        and type(installation.get("id")) is int and installation["id"] > 0
        and match
    ):
        return 403, None
    return 202, {
        "environment": env, "run_id": int(match[1]),
        "installation_id": installation["id"],
    }


def handler_for(secret):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def respond(self, status):
            self.send_response(status)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def do_GET(self):
            self.respond(204 if self.path == "/healthz" else 404)

        def do_POST(self):
            if self.path != "/github-webhook":
                self.respond(404)
                return
            length = self.headers.get("Content-Length", "")
            if not re.fullmatch(r"[0-9]{1,6}", length):
                self.respond(400)
                return
            count = int(length)
            if count > BODY_LIMIT:
                self.respond(413)
                return
            self.connection.settimeout(5)
            try:
                body = self.rfile.read(count)
            except TimeoutError:
                self.respond(408)
                return
            if len(body) != count:
                self.respond(400)
                return
            status, details = inspect_event(
                secret, self.headers.get("X-GitHub-Event"),
                self.headers.get("X-Hub-Signature-256"), body,
            )
            if details is not None:
                print(json.dumps(details), flush=True)
            self.respond(status)

    return Handler


if __name__ == "__main__":
    webhook_secret = os.environ.get("FIXTURE_WEBHOOK_SECRET", "").encode()
    if len(webhook_secret) < 32:
        raise SystemExit("Set FIXTURE_WEBHOOK_SECRET from the private secret store.")
    with ThreadingHTTPServer(("127.0.0.1", 8765), handler_for(webhook_secret)) as server:
        server.serve_forever()
