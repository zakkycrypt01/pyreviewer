"""
PyReviewer Server - High Performance Python Code Review Service
Runs natively with Python 3 standard library or behind Gunicorn/Uvicorn.
Built for Docker and Render Deployment.
"""

import http.server
import json
import os
import sys
from pathlib import Path
from urllib.parse import urlparse

# Add app directory to path
BASE_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE_DIR))

from app.analyzer import analyze_code, generate_dockerfile, generate_dockerignore, generate_render_yaml
from app.repo_scanner import scan_repository

PORT = int(os.environ.get("PORT", 8080))
STATIC_DIR = BASE_DIR / "static"

SAMPLE_SNIPPETS = {
    "microservice": '''import os
import time
import sqlite3
from fastapi import FastAPI

app = FastAPI()
DB_NAME = "users.db"
ADMIN_TOKEN = "sk_live_994828194a8d01bfe48201"  # Hardcoded token

def query_user(user_id, cache=[]):  # Mutable default
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    # SQL injection vulnerability
    query = f"SELECT id, username, email FROM users WHERE id = '{user_id}'"
    cursor.execute(query)
    record = cursor.fetchone()
    cache.append(record)
    return record

@app.get("/users/{user_id}")
async def get_user_endpoint(user_id: str):
    time.sleep(1.5)  # Blocking sleep in async function
    try:
        user = query_user(user_id)
        assert user is not None  # Assert for runtime validation
        return {"status": "ok", "user": user}
    except:
        pass  # Silent failure swallowing
''',
    "pipeline": '''import os
import pickle
import urllib.request

def process_batch(items, results=[]):  # Mutable default
    # Unpythonic C-style indexing
    for i in range(len(items)):
        item = items[i]
        payload = pickle.loads(item)  # Insecure deserialization
        results.append(payload)
    return results

def backup_data(remote_host, filename):
    # Insecure shell command
    cmd = f"scp {filename} root@{remote_host}:/backups/"
    os.system(cmd)
''',
    "clean": '''import asyncio
import logging
import os
from typing import Optional, List, Dict, Any
import httpx
from pydantic import BaseModel

logger = logging.getLogger(__name__)

class UserResponse(BaseModel):
    id: str
    username: str
    is_active: bool

async def fetch_user_record(user_id: str, timeout_seconds: float = 5.0) -> Optional[UserResponse]:
    """Fetches user record asynchronously from upstream microservice with timeout."""
    api_url = os.getenv("USER_SERVICE_URL", "https://api.internal.service")
    token = os.getenv("SERVICE_AUTH_TOKEN", "")

    headers = {"Authorization": f"Bearer {token}"}
    
    try:
        async with httpx.AsyncClient(timeout=timeout_seconds) as client:
            response = await client.get(f"{api_url}/users/{user_id}", headers=headers)
            response.raise_for_status()
            data = response.json()
            return UserResponse(**data)
    except httpx.HTTPStatusError as exc:
        logger.error(f"Upstream returned HTTP {exc.response.status_code} for user {user_id}")
        return None
    except Exception as exc:
        logger.exception(f"Unexpected error fetching user {user_id}: {exc}")
        return None
'''
}


class PyReviewerHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(STATIC_DIR), **kwargs)

    def do_GET(self):
        parsed = urlparse(self.path)
        
        # Healthcheck endpoint for Render & Docker
        if parsed.path == "/healthz":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({
                "status": "healthy",
                "service": "PyReviewer",
                "version": "2.0.0",
                "engine": "Python AST & Security Analyzer",
                "docker_ready": True
            }).encode("utf-8"))
            return

        # Sample snippet loader
        if parsed.path == "/api/snippets":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(SAMPLE_SNIPPETS).encode("utf-8"))
            return

        # Serve index.html for root or SPA fallback
        if parsed.path in ["/", "/index.html"]:
            self.path = "/index.html"
            return super().do_GET()

        return super().do_GET()

    def do_POST(self):
        parsed = urlparse(self.path)
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length)

        try:
            payload = json.loads(body.decode("utf-8")) if body else {}
        except Exception:
            self._send_json(400, {"error": "Invalid JSON body"})
            return

        if parsed.path == "/api/analyze":
            code = payload.get("code", "")
            if not code.strip():
                self._send_json(400, {"error": "No Python code provided"})
                return

            result = analyze_code(code)
            self._send_json(200, result)
            return

        if parsed.path == "/api/dockerize":
            imports = payload.get("imports", [])
            has_main = payload.get("has_main", False)
            dockerfile = generate_dockerfile(imports, has_main)
            dockerignore = generate_dockerignore()
            render_yaml = generate_render_yaml(imports)
            self._send_json(200, {
                "dockerfile": dockerfile,
                "dockerignore": dockerignore,
                "render_yaml": render_yaml
            })
            return

        if parsed.path == "/api/scan-repo":
            repo_url = payload.get("repo_url", "")
            if not repo_url.strip():
                self._send_json(400, {"error": "Please provide a valid GitHub repository URL."})
                return

            scan_result = scan_repository(repo_url)
            status_code = 200 if "error" not in scan_result else 400
            self._send_json(status_code, scan_result)
            return

        if parsed.path == "/api/export-pr":
            code = payload.get("code", "")
            analysis = analyze_code(code)
            pr_markdown = self._format_pr_markdown(analysis)
            self._send_json(200, {"pr_markdown": pr_markdown})
            return

        self._send_json(404, {"error": "Endpoint not found"})

    def _format_pr_markdown(self, analysis: dict) -> str:
        metrics = analysis["metrics"]
        issues = analysis["issues"]
        
        md = [
            "## 🤖 PyReviewer Automated Code & Docker Audit",
            "",
            f"**Security Rating:** `{metrics['security_rating']}` | "
            f"**Maintainability Score:** `{metrics['maintainability_score']}/100` | "
            f"**Cyclomatic Complexity:** `{metrics['cyclomatic_complexity']}` | "
            f"**Container Readiness:** `{metrics['container_readiness']}`",
            "",
            "### 🔍 Detected Issues & Suggestions"
        ]

        if not issues:
            md.append("✅ **No critical issues detected. Clean, idiomatic Python!**")
        else:
            for item in issues:
                sev_icon = "🚨" if item["severity"] == "CRITICAL" else "⚠️" if item["severity"] == "HIGH" else "ℹ️"
                md.append(f"- {sev_icon} **Line {item['line']} [{item['code']} - {item['title']}]** (`{item['severity']}`)")
                md.append(f"  - *Issue:* {item['message']}")
                md.append(f"  - *Fix:* {item['suggestion']}")
                md.append("")

        if analysis.get("diff_text"):
            md.extend([
                "### 📝 Suggested Refactor Diff",
                "```diff",
                analysis["diff_text"].strip(),
                "```",
                ""
            ])

        md.extend([
            "---",
            "*Reviewed by PyReviewer • Dockerized for Render Deployment*"
        ])
        return "\n".join(md)

    def _send_json(self, status: int, data: dict):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(json.dumps(data).encode("utf-8"))


def run():
    server_address = ("", PORT)
    httpd = http.server.HTTPServer(server_address, PyReviewerHandler)
    print(f"[PyReviewer] Serving on port {PORT} (http://localhost:{PORT})")
    print(f"[PyReviewer] Healthcheck endpoint: http://localhost:{PORT}/healthz")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[PyReviewer] Shutting down.")
        httpd.server_close()


if __name__ == "__main__":
    run()
