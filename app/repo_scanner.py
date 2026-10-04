"""
PyReviewer Repository Scanner Engine
Clones public GitHub repositories, builds an interactive file tree,
runs multi-file AST security audits, and writes comprehensive audit reports.
"""

import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Dict, List, Any, Optional

from app.analyzer import analyze_code, generate_dockerfile, generate_dockerignore, generate_render_yaml

IGNORE_DIRS = {
    '.git', '.github', 'venv', '.venv', 'env', '.env', '__pycache__',
    'node_modules', 'site-packages', 'build', 'dist', '.pytest_cache',
    '.tox', 'htmlcov', '.mypy_cache', 'migrations', 'eggs', '.eggs'
}

DEMO_REPOS = {
    "https://github.com/demo/ecommerce-microservices": {
        "title": "E-Commerce FastAPI Microservices (Demo)",
        "files": {
            "app/main.py": """import os
import time
from fastapi import FastAPI, Depends, HTTPException
from app.db import get_db_cursor
from app.auth import verify_token

app = FastAPI(title="Store API")
SECRET_KEY = "sk_live_prod_8984928194a8d01bfe48201"

@app.get("/items/{item_id}")
async def read_item(item_id: str, db = Depends(get_db_cursor)):
    time.sleep(1.0)  # Blocking I/O in async def!
    query = f"SELECT * FROM items WHERE id = '{item_id}'"  # SQL Injection
    db.execute(query)
    record = db.fetchone()
    if not record:
        raise HTTPException(status_code=404, detail="Item not found")
    return {"item": record}

@app.post("/items/batch")
async def batch_create(items: list = []):  # Mutable default!
    for i in range(len(items)):  # Unpythonic loop
        print("Processing", items[i])
    return {"count": len(items)}
""",
            "app/db.py": """import sqlite3

def get_db_cursor():
    conn = sqlite3.connect("store.db")
    try:
        yield conn.cursor()
    finally:
        conn.close()
""",
            "app/auth.py": """import os

def verify_token(token: str):
    try:
        # Insecure evaluation
        res = eval(token)
        return True
    except:
        pass  # Silent failure
    return False
""",
            "app/tasks.py": """import os
import subprocess

def run_backup(bucket_name: str, file_path: str):
    # Insecure shell=True command injection
    cmd = f"aws s3 cp {file_path} s3://{bucket_name}/"
    subprocess.run(cmd, shell=True)
"""
        }
    }
}


def parse_github_url(url: str) -> Optional[Dict[str, str]]:
    """Validates and extracts owner and repo from a GitHub URL."""
    clean_url = url.strip().rstrip('/')
    match = re.match(r'^https?://github\.com/([a-zA-Z0-9_\-\.]+)/([a-zA-Z0-9_\-\.]+)(?:\.git)?(?:/.*)?$', clean_url)
    if not match:
        return None
    return {
        "owner": match.group(1),
        "repo": match.group(2).removesuffix('.git'),
        "clean_url": f"https://github.com/{match.group(1)}/{match.group(2).removesuffix('.git')}"
    }


def scan_repository(repo_url: str, max_files: int = 150) -> Dict[str, Any]:
    """Clones a GitHub repository shallowly and performs full codebase analysis."""
    parsed = parse_github_url(repo_url)
    
    # Check if demo repo requested or fallback
    if repo_url in DEMO_REPOS or not parsed:
        if repo_url in DEMO_REPOS:
            demo_data = DEMO_REPOS[repo_url]
            return _analyze_memory_files(demo_data["files"], "demo/ecommerce-microservices")
        return {"error": "Invalid GitHub repository URL. Format must be: https://github.com/owner/repository"}

    owner = parsed["owner"]
    repo = parsed["repo"]
    clone_url = parsed["clean_url"]

    temp_dir = tempfile.mkdtemp(prefix="pyreviewer_")

    try:
        # Clone with depth 1
        cmd = ["git", "clone", "--depth", "1", "--single-branch", clone_url, temp_dir]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        
        if proc.returncode != 0:
            # If clone fails, check stderr
            err = proc.stderr.strip() or proc.stdout.strip()
            return {"error": f"Failed to clone repository: {err}"}

        # Scan directory
        repo_path = Path(temp_dir)
        py_files: List[Path] = []
        for root, dirs, files in os.walk(repo_path):
            dirs[:] = [d for d in dirs if d not in IGNORE_DIRS]
            for file in files:
                if file.endswith('.py'):
                    py_files.append(Path(root) / file)
                    if len(py_files) >= max_files:
                        break
            if len(py_files) >= max_files:
                break

        if not py_files:
            return {"error": "No Python (.py) files found in the specified repository."}

        # Read requirements or dependencies if exist
        req_file = repo_path / "requirements.txt"
        requirements_content = req_file.read_text(encoding="utf-8", errors="ignore") if req_file.exists() else ""

        # Analyze each file
        file_map: Dict[str, Any] = {}
        all_imports: List[str] = []
        all_issues: List[Dict[str, Any]] = []
        total_loc = 0
        total_cc = 0

        for file_path in py_files:
            rel_path = str(file_path.relative_to(repo_path))
            try:
                content = file_path.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue

            analysis = analyze_code(content)
            loc = analysis["metrics"]["code_lines"]
            total_loc += loc
            total_cc += analysis["metrics"]["cyclomatic_complexity"]
            all_imports.extend(analysis["detected_imports"])

            crit_count = sum(1 for i in analysis["issues"] if i["severity"] == "CRITICAL")
            high_count = sum(1 for i in analysis["issues"] if i["severity"] == "HIGH")

            if crit_count > 0:
                risk = "danger"
            elif high_count > 0:
                risk = "warning"
            else:
                risk = "safe"

            # Tag issues with file path
            for issue in analysis["issues"]:
                issue_with_file = dict(issue)
                issue_with_file["file"] = rel_path
                all_issues.append(issue_with_file)

            file_map[rel_path] = {
                "path": rel_path,
                "content": content,
                "metrics": analysis["metrics"],
                "issues": analysis["issues"],
                "risk": risk,
                "diff_text": analysis["diff_text"],
                "refactored_code": analysis["refactored_code"]
            }

        unique_imports = sorted(list(set(all_imports)))
        
        # Overall Grade Calculation
        total_critical = sum(1 for i in all_issues if i["severity"] == "CRITICAL")
        total_high = sum(1 for i in all_issues if i["severity"] == "HIGH")
        total_medium = sum(1 for i in all_issues if i["severity"] == "MEDIUM")

        if total_critical > 3:
            repo_grade = "F"
        elif total_critical > 0 or total_high > 5:
            repo_grade = "D"
        elif total_high > 1 or total_medium > 8:
            repo_grade = "C"
        elif total_medium > 0:
            repo_grade = "B"
        else:
            repo_grade = "A"

        # Detect Frameworks
        frameworks = []
        if "fastapi" in unique_imports: frameworks.append("FastAPI")
        if "flask" in unique_imports: frameworks.append("Flask")
        if "django" in unique_imports: frameworks.append("Django")
        if "sqlalchemy" in unique_imports: frameworks.append("SQLAlchemy")
        if "torch" in unique_imports or "pytorch" in unique_imports: frameworks.append("PyTorch")
        if "pandas" in unique_imports: frameworks.append("Pandas")
        if "celery" in unique_imports: frameworks.append("Celery")
        if not frameworks: frameworks.append("Standard Python CLI / Microservice")

        # Hotspots (top 5 files by critical/high issues and complexity)
        hotspots = sorted(
            file_map.values(),
            key=lambda x: (
                sum(1 for i in x["issues"] if i["severity"] == "CRITICAL") * 5 +
                sum(1 for i in x["issues"] if i["severity"] == "HIGH") * 2 +
                x["metrics"]["cyclomatic_complexity"]
            ),
            reverse=True
        )[:5]

        # Generate Repo-Wide Dockerfile and render.yaml
        has_main = any(f in file_map for f in ["main.py", "app.py", "server.py", "wsgi.py"])
        repo_dockerfile = generate_dockerfile(unique_imports, has_main)
        repo_dockerignore = generate_dockerignore()
        repo_render_yaml = generate_render_yaml(unique_imports)

        # Generate Comprehensive Markdown Report
        markdown_report = _generate_markdown_report(
            repo_name=f"{owner}/{repo}",
            repo_url=clone_url,
            total_files=len(file_map),
            total_loc=total_loc,
            repo_grade=repo_grade,
            all_issues=all_issues,
            frameworks=frameworks,
            hotspots=hotspots
        )

        # Build File Tree Structure
        tree = _build_tree_hierarchy(list(file_map.keys()), file_map)

        return {
            "success": True,
            "repo_name": f"{owner}/{repo}",
            "repo_url": clone_url,
            "total_files": len(file_map),
            "total_loc": total_loc,
            "repo_grade": repo_grade,
            "total_critical": total_critical,
            "total_high": total_high,
            "total_medium": total_medium,
            "detected_frameworks": frameworks,
            "file_tree": tree,
            "files": file_map,
            "hotspots": [h["path"] for h in hotspots],
            "dockerfile": repo_dockerfile,
            "dockerignore": repo_dockerignore,
            "render_yaml": repo_render_yaml,
            "detailed_report": markdown_report
        }

    except subprocess.TimeoutExpired:
        return {"error": "Git clone operation timed out after 30 seconds. The repository may be too large."}
    except Exception as e:
        return {"error": f"Internal scan error: {str(e)}"}
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


def _analyze_memory_files(files_dict: Dict[str, str], repo_name: str) -> Dict[str, Any]:
    """Analyzes a virtual/demo dictionary of files."""
    file_map = {}
    all_imports = []
    all_issues = []
    total_loc = 0
    total_cc = 0

    for path, content in files_dict.items():
        analysis = analyze_code(content)
        loc = analysis["metrics"]["code_lines"]
        total_loc += loc
        total_cc += analysis["metrics"]["cyclomatic_complexity"]
        all_imports.extend(analysis["detected_imports"])

        crit_count = sum(1 for i in analysis["issues"] if i["severity"] == "CRITICAL")
        high_count = sum(1 for i in analysis["issues"] if i["severity"] == "HIGH")

        risk = "danger" if crit_count > 0 else "warning" if high_count > 0 else "safe"

        for issue in analysis["issues"]:
            item = dict(issue)
            item["file"] = path
            all_issues.append(item)

        file_map[path] = {
            "path": path,
            "content": content,
            "metrics": analysis["metrics"],
            "issues": analysis["issues"],
            "risk": risk,
            "diff_text": analysis["diff_text"],
            "refactored_code": analysis["refactored_code"]
        }

    unique_imports = sorted(list(set(all_imports)))
    total_critical = sum(1 for i in all_issues if i["severity"] == "CRITICAL")
    total_high = sum(1 for i in all_issues if i["severity"] == "HIGH")
    total_medium = sum(1 for i in all_issues if i["severity"] == "MEDIUM")

    repo_grade = "F" if total_critical > 0 else "D" if total_high > 2 else "B"
    frameworks = ["FastAPI", "SQLite3"]

    hotspots = sorted(
        file_map.values(),
        key=lambda x: len(x["issues"]),
        reverse=True
    )

    markdown_report = _generate_markdown_report(
        repo_name=repo_name,
        repo_url=f"https://github.com/{repo_name}",
        total_files=len(file_map),
        total_loc=total_loc,
        repo_grade=repo_grade,
        all_issues=all_issues,
        frameworks=frameworks,
        hotspots=hotspots
    )

    tree = _build_tree_hierarchy(list(file_map.keys()), file_map)

    return {
        "success": True,
        "repo_name": repo_name,
        "repo_url": f"https://github.com/{repo_name}",
        "total_files": len(file_map),
        "total_loc": total_loc,
        "repo_grade": repo_grade,
        "total_critical": total_critical,
        "total_high": total_high,
        "total_medium": total_medium,
        "detected_frameworks": frameworks,
        "file_tree": tree,
        "files": file_map,
        "hotspots": [h["path"] for h in hotspots],
        "dockerfile": generate_dockerfile(unique_imports, True),
        "dockerignore": generate_dockerignore(),
        "render_yaml": generate_render_yaml(unique_imports),
        "detailed_report": markdown_report
    }


def _build_tree_hierarchy(paths: List[str], file_map: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Builds a nested folder and file tree for the UI."""
    root_nodes = []
    
    for path in sorted(paths):
        parts = path.split('/')
        file_info = file_map.get(path, {})
        node = {
            "name": parts[-1],
            "path": path,
            "type": "file",
            "risk": file_info.get("risk", "safe"),
            "issue_count": len(file_info.get("issues", [])),
            "loc": file_info.get("metrics", {}).get("code_lines", 0)
        }
        root_nodes.append(node)
        
    return root_nodes


def _generate_markdown_report(
    repo_name: str,
    repo_url: str,
    total_files: int,
    total_loc: int,
    repo_grade: str,
    all_issues: List[Dict[str, Any]],
    frameworks: List[str],
    hotspots: List[Dict[str, Any]]
) -> str:
    """Generates an executive, audit-grade Markdown report."""
    crit_count = sum(1 for i in all_issues if i["severity"] == "CRITICAL")
    high_count = sum(1 for i in all_issues if i["severity"] == "HIGH")
    med_count = sum(1 for i in all_issues if i["severity"] == "MEDIUM")

    lines = [
        f"# 🛡️ Codebase Security & Quality Audit Report",
        f"**Repository:** [{repo_name}]({repo_url})  ",
        f"**Audit Engine:** PyReviewer AST & OWASP Scanner  ",
        f"**Status:** Complete  ",
        "",
        "---",
        "",
        "## 1. Executive Summary",
        "",
        f"| Metric | Value |",
        f"| :--- | :--- |",
        f"| **Overall Security Rating** | `{repo_grade}` |",
        f"| **Python Files Scanned** | `{total_files}` |",
        f"| **Total Lines of Code** | `{total_loc:,}` |",
        f"| **Critical Vulnerabilities** | `{crit_count}` |",
        f"| **High-Risk Issues** | `{high_count}` |",
        f"| **Medium Quality Issues** | `{med_count}` |",
        f"| **Detected Tech Stack** | `{', '.join(frameworks)}` |",
        "",
        "---",
        "",
        "## 2. Top Risk Hotspots (Priority Refactoring Targets)",
        "",
        "The following files account for the highest concentration of security and concurrency risks:",
        ""
    ]

    for idx, spot in enumerate(hotspots[:5], start=1):
        crit = sum(1 for i in spot["issues"] if i["severity"] == "CRITICAL")
        high = sum(1 for i in spot["issues"] if i["severity"] == "HIGH")
        lines.append(f"{idx}. **`{spot['path']}`** — `{spot['metrics']['code_lines']} LOC` | `{crit}` Critical | `{high}` High | CC: `{spot['metrics']['cyclomatic_complexity']}`")

    lines.extend([
        "",
        "---",
        "",
        "## 3. Detailed OWASP & Concurrency Findings",
        ""
    ])

    if not all_issues:
        lines.append("✅ **No security vulnerabilities or anti-patterns detected.**")
    else:
        for issue in all_issues:
            icon = "🚨" if issue["severity"] == "CRITICAL" else "⚠️" if issue["severity"] == "HIGH" else "ℹ️"
            lines.extend([
                f"### {icon} `{issue.get('file', 'unknown')}`: Line {issue['line']} — {issue['title']}",
                f"- **Rule ID:** `{issue['code']}`",
                f"- **Severity:** `{issue['severity']}` ({issue['category']})",
                f"- **Description:** {issue['message']}",
                f"- **Remediation:** {issue['suggestion']}",
                ""
            ])

    lines.extend([
        "---",
        "",
        "## 4. Containerization & Render Deployment Readiness",
        "",
        "- **Dockerfile:** Multi-stage production container generated with non-root security user `appuser`.",
        "- **Render Blueprint:** Configured with `render.yaml` and healthcheck `/healthz` for zero-downtime deployment.",
        "",
        "*Report automatically generated by PyReviewer.*"
    ])

    return "\n".join(lines)
