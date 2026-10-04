"""
PyReviewer AST, Security & Docker Packaging Analysis Engine
Deterministic Python Abstract Syntax Tree analysis with zero cloud dependencies.
"""

import ast
import difflib
import re
import sys
from typing import Dict, List, Any, Optional

class PythonASTAnalyzer(ast.NodeVisitor):
    def __init__(self, source_code: str):
        self.source = source_code
        self.lines = source_code.splitlines()
        self.issues: List[Dict[str, Any]] = []
        self.imports: List[str] = []
        self.functions_count = 0
        self.classes_count = 0
        self.async_functions_count = 0
        self.branch_count = 1  # Base cyclomatic complexity
        self.has_main_block = False

    def visit_Import(self, node: ast.Import):
        for alias in node.names:
            self.imports.append(alias.name.split('.')[0])
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        if node.module:
            self.imports.append(node.module.split('.')[0])
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef):
        self.functions_count += 1
        self._check_function(node, is_async=False)
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef):
        self.functions_count += 1
        self.async_functions_count += 1
        self._check_function(node, is_async=True)
        self.generic_visit(node)

    def _check_function(self, node, is_async: bool):
        # 1. Check mutable default arguments
        for default in node.args.defaults + node.args.kw_defaults:
            if default is not None and isinstance(default, (ast.List, ast.Dict, ast.Set)):
                self.issues.append({
                    "line": default.lineno,
                    "col": default.col_offset,
                    "code": "IDIOM-001",
                    "title": "Mutable Default Argument",
                    "severity": "CRITICAL",
                    "category": "Idiomatic Python",
                    "message": f"Function '{node.name}' uses a mutable default argument ({type(default).__name__.lower()}). Default arguments are evaluated once at definition time, creating shared mutable state between calls.",
                    "suggestion": "Replace default with 'None' and initialize inside the function: 'if arg is None: arg = []'."
                })

        # 2. Check missing return type annotation on public functions
        if not node.name.startswith('_') and node.returns is None:
            self.issues.append({
                "line": node.lineno,
                "col": node.col_offset,
                "code": "TYPE-001",
                "title": "Missing Return Type Annotation",
                "severity": "INFO",
                "category": "Type Safety",
                "message": f"Public function '{node.name}' lacks a return type annotation.",
                "suggestion": f"Add explicit return type, e.g. 'def {node.name}(...) -> None:' or '-> str:'."
            })

        # 3. Check for blocking calls inside async function
        if is_async:
            for child in ast.walk(node):
                if isinstance(child, ast.Call):
                    call_name = self._get_call_name(child.func)
                    if call_name in ["time.sleep", "sleep"]:
                        self.issues.append({
                            "line": child.lineno,
                            "col": child.col_offset,
                            "code": "PERF-001",
                            "title": "Blocking Call in Async Function",
                            "severity": "CRITICAL",
                            "category": "Concurrency & Async",
                            "message": f"Synchronous '{call_name}()' blocks the entire event loop in async function '{node.name}'.",
                            "suggestion": "Use 'await asyncio.sleep()' instead."
                        })
                    elif call_name in ["requests.get", "requests.post", "urllib.request.urlopen"]:
                        self.issues.append({
                            "line": child.lineno,
                            "col": child.col_offset,
                            "code": "PERF-002",
                            "title": "Synchronous HTTP in Async Function",
                            "severity": "HIGH",
                            "category": "Concurrency & Async",
                            "message": f"Synchronous '{call_name}()' blocks concurrent request processing.",
                            "suggestion": "Use an async HTTP client such as 'httpx.AsyncClient()' or 'aiohttp.ClientSession()'."
                        })

    def visit_Call(self, node: ast.Call):
        call_name = self._get_call_name(node.func)

        # Security: eval() and exec()
        if call_name in ["eval", "exec"]:
            self.issues.append({
                "line": node.lineno,
                "col": node.col_offset,
                "code": "SEC-001",
                "title": "Arbitrary Code Execution Risk",
                "severity": "CRITICAL",
                "category": "Security (OWASP)",
                "message": f"Dangerous call to '{call_name}()' allows arbitrary code execution if user inputs reach this call.",
                "suggestion": "Use 'ast.literal_eval()' for safe parsing of literals or refactor to deterministic logic."
            })

        # Security: subprocess with shell=True
        if call_name in ["subprocess.run", "subprocess.Popen", "subprocess.call", "subprocess.check_output", "os.system"]:
            if call_name == "os.system":
                self.issues.append({
                    "line": node.lineno,
                    "col": node.col_offset,
                    "code": "SEC-002",
                    "title": "Insecure OS Shell Command",
                    "severity": "CRITICAL",
                    "category": "Security (OWASP)",
                    "message": "'os.system()' is susceptible to shell injection vulnerabilities.",
                    "suggestion": "Use 'subprocess.run([args], shell=False)' with arguments passed as an explicit list."
                })
            else:
                for kw in node.keywords:
                    if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                        self.issues.append({
                            "line": node.lineno,
                            "col": node.col_offset,
                            "code": "SEC-002",
                            "title": "Subprocess Shell Injection Hazard",
                            "severity": "CRITICAL",
                            "category": "Security (OWASP)",
                            "message": f"'{call_name}(..., shell=True)' passes command to system shell, enabling command injection.",
                            "suggestion": "Set 'shell=False' and split commands into a list of arguments."
                        })

        # Security: pickle.loads
        if call_name in ["pickle.loads", "pickle.load", "_pickle.loads"]:
            self.issues.append({
                "line": node.lineno,
                "col": node.col_offset,
                "code": "SEC-003",
                "title": "Insecure Deserialization (Pickle)",
                "severity": "HIGH",
                "category": "Security (OWASP)",
                "message": "Unpickling untrusted data can lead to remote code execution.",
                "suggestion": "Use JSON or Protocol Buffers for serializing untrusted payloads."
            })

        self.generic_visit(node)

    def visit_For(self, node: ast.For):
        self.branch_count += 1
        # Check range(len(...)) anti-pattern
        if isinstance(node.iter, ast.Call):
            call_name = self._get_call_name(node.iter.func)
            if call_name == "range" and len(node.iter.args) == 1:
                inner_call = node.iter.args[0]
                if isinstance(inner_call, ast.Call) and self._get_call_name(inner_call.func) == "len":
                    self.issues.append({
                        "line": node.lineno,
                        "col": node.col_offset,
                        "code": "IDIOM-002",
                        "title": "Unpythonic range(len(...)) Loop",
                        "severity": "MEDIUM",
                        "category": "Idiomatic Python",
                        "message": "Using 'range(len(...))' to index items is an unpythonic C-style loop pattern.",
                        "suggestion": "Iterate directly over the collection: 'for item in items:' or use 'for idx, item in enumerate(items):'."
                    })
        self.generic_visit(node)

    def visit_While(self, node: ast.While):
        self.branch_count += 1
        self.generic_visit(node)

    def visit_If(self, node: ast.If):
        self.branch_count += 1
        # Check if __name__ == '__main__'
        if isinstance(node.test, ast.Compare):
            left = node.test.left
            if isinstance(left, ast.Name) and left.id == "__name__":
                self.has_main_block = True
        self.generic_visit(node)

    def visit_ExceptHandler(self, node: ast.ExceptHandler):
        self.branch_count += 1
        # 1. Bare except:
        if node.type is None:
            self.issues.append({
                "line": node.lineno,
                "col": node.col_offset,
                "code": "IDIOM-003",
                "title": "Bare 'except:' Catches SystemExit and KeyboardInterrupt",
                "severity": "HIGH",
                "category": "Reliability & Error Handling",
                "message": "A bare 'except:' catches all exceptions, preventing Ctrl+C termination and masking unexpected system errors.",
                "suggestion": "Specify concrete exceptions: 'except (ValueError, KeyError) as e:' or at minimum 'except Exception as e:'."
            })
        
        # 2. Silent failure: except ...: pass
        if len(node.body) == 1 and isinstance(node.body[0], ast.Pass):
            self.issues.append({
                "line": node.lineno,
                "col": node.col_offset,
                "code": "IDIOM-004",
                "title": "Silent Exception Swallowing",
                "severity": "HIGH",
                "category": "Reliability & Error Handling",
                "message": "Silently suppressing exceptions with 'pass' hides critical runtime failures and creates invisible bugs.",
                "suggestion": "Log the error using Python's 'logging' module or re-raise with 'raise'."
            })
        self.generic_visit(node)

    def visit_Assert(self, node: ast.Assert):
        self.issues.append({
            "line": node.lineno,
            "col": node.col_offset,
            "code": "SEC-004",
            "title": "Assert Used for Runtime Validation",
            "severity": "MEDIUM",
            "category": "Security (OWASP)",
            "message": "'assert' statements are stripped when Python is run with optimizations ('python -O'). Never use assert for production security or data validation.",
            "suggestion": "Raise explicit exceptions: 'if not condition: raise ValueError(...)'"
        })
        self.generic_visit(node)

    def visit_ClassDef(self, node: ast.ClassDef):
        self.classes_count += 1
        self.generic_visit(node)

    def _get_call_name(self, node) -> str:
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            val = self._get_call_name(node.value)
            return f"{val}.{node.attr}" if val else node.attr
        return ""

    def scan_regex_patterns(self):
        """Scans for patterns AST might overlook, such as hardcoded secrets and raw SQL f-strings."""
        secret_pattern = re.compile(
            r'(?i)(api[_-]?key|secret|password|auth[_-]?token|private[_-]?key)\s*=\s*["\']([a-zA-Z0-9_\-\.\/+=]{8,})["\']'
        )
        sql_pattern = re.compile(
            r'(?i)(SELECT|INSERT|UPDATE|DELETE|DROP)\s+.*f["\'].*\{.*\}.*["\']'
        )

        for idx, line in enumerate(self.lines, start=1):
            sec_match = secret_pattern.search(line)
            if sec_match and not any(ign in line.lower() for ign in ["dummy", "example", "os.getenv", "os.environ"]):
                self.issues.append({
                    "line": idx,
                    "col": sec_match.start(),
                    "code": "SEC-005",
                    "title": "Hardcoded Secret / API Key",
                    "severity": "CRITICAL",
                    "category": "Security (OWASP)",
                    "message": f"Potential hardcoded credential '{sec_match.group(1)}' found in source code.",
                    "suggestion": "Load credentials from environment variables: 'os.getenv(\"API_KEY\")' or use a secrets manager."
                })

            sql_match = sql_pattern.search(line)
            if sql_match:
                self.issues.append({
                    "line": idx,
                    "col": sql_match.start(),
                    "code": "SEC-006",
                    "title": "SQL Injection Risk (f-string in Query)",
                    "severity": "CRITICAL",
                    "category": "Security (OWASP)",
                    "message": "Raw f-string formatting in SQL query creates severe SQL injection vulnerabilities.",
                    "suggestion": "Use parameterized queries with bind variables: 'cursor.execute(\"SELECT * FROM users WHERE id = %s\", (user_id,))'."
                })


def analyze_code(source_code: str) -> Dict[str, Any]:
    """Runs full AST, Security, and Metrics analysis on Python code."""
    lines = source_code.splitlines()
    total_lines = len(lines)
    blank_lines = sum(1 for line in lines if not line.strip())
    comment_lines = sum(1 for line in lines if line.strip().startswith('#'))
    code_lines = total_lines - blank_lines - comment_lines

    try:
        tree = ast.parse(source_code)
        syntax_valid = True
        syntax_error = None
    except SyntaxError as e:
        return {
            "syntax_valid": False,
            "syntax_error": {
                "line": e.lineno or 1,
                "col": e.offset or 0,
                "message": e.msg,
                "text": e.text.strip() if e.text else ""
            },
            "issues": [{
                "line": e.lineno or 1,
                "col": e.offset or 0,
                "code": "SYNTAX-001",
                "title": "Python Syntax Error",
                "severity": "CRITICAL",
                "category": "Syntax",
                "message": f"Python parser encountered syntax error: {e.msg}",
                "suggestion": "Fix the syntax at the indicated line before running further checks."
            }],
            "metrics": {
                "total_lines": total_lines,
                "code_lines": code_lines,
                "cyclomatic_complexity": 0,
                "security_rating": "F",
                "container_readiness": "0%"
            },
            "dockerfile": "",
            "render_yaml": "",
            "refactored_code": source_code,
            "diff_text": ""
        }

    analyzer = PythonASTAnalyzer(source_code)
    analyzer.visit(tree)
    analyzer.scan_regex_patterns()

    unique_imports = sorted(list(set(analyzer.imports)))

    critical_count = sum(1 for i in analyzer.issues if i["severity"] == "CRITICAL")
    high_count = sum(1 for i in analyzer.issues if i["severity"] == "HIGH")
    medium_count = sum(1 for i in analyzer.issues if i["severity"] == "MEDIUM")

    if critical_count > 0:
        security_rating = "F"
    elif high_count > 1:
        security_rating = "D"
    elif high_count == 1 or medium_count > 2:
        security_rating = "C"
    elif medium_count > 0:
        security_rating = "B"
    else:
        security_rating = "A"

    cc = analyzer.branch_count
    maintainability = max(20, min(100, int(100 - (cc * 2.5) - (critical_count * 15) - (high_count * 8))))

    container_score = 90
    if not analyzer.has_main_block and "fastapi" not in unique_imports and "flask" not in unique_imports:
        container_score -= 15
    if critical_count > 0:
        container_score -= 25

    refactored_code = generate_refactored_code(source_code, analyzer.issues)

    diff = list(difflib.unified_diff(
        source_code.splitlines(keepends=True),
        refactored_code.splitlines(keepends=True),
        fromfile="original.py",
        tofile="refactored.py",
        n=3
    ))
    diff_text = "".join(diff)

    dockerfile = generate_dockerfile(unique_imports, analyzer.has_main_block)
    dockerignore = generate_dockerignore()
    render_yaml = generate_render_yaml(unique_imports)

    return {
        "syntax_valid": True,
        "syntax_error": None,
        "issues": sorted(analyzer.issues, key=lambda x: (x["line"], x["severity"] != "CRITICAL")),
        "detected_imports": unique_imports,
        "metrics": {
            "total_lines": total_lines,
            "code_lines": code_lines,
            "comment_lines": comment_lines,
            "functions_count": analyzer.functions_count,
            "classes_count": analyzer.classes_count,
            "cyclomatic_complexity": cc,
            "maintainability_score": maintainability,
            "security_rating": security_rating,
            "container_readiness": f"{max(10, min(100, container_score))}%"
        },
        "dockerfile": dockerfile,
        "dockerignore": dockerignore,
        "render_yaml": render_yaml,
        "refactored_code": refactored_code,
        "diff_text": diff_text
    }


def generate_refactored_code(original: str, issues: List[Dict[str, Any]]) -> str:
    res = original

    # Fix mutable default arguments
    res = re.sub(
        r'def\s+([a-zA-Z_0-9]+)\((.*?)(\w+)\s*:\s*list\s*=\s*\[\](.*?)\):',
        r'def \1(\2\3: Optional[list] = None\4):\n    if \3 is None:\n        \3 = []',
        res
    )
    res = re.sub(
        r'def\s+([a-zA-Z_0-9]+)\((.*?)(\w+)\s*=\s*\[\](.*?)\):',
        r'def \1(\2\3 = None\4):\n    if \3 is None:\n        \3 = []',
        res
    )

    # Fix range(len(items)) -> enumerate(items)
    res = re.sub(
        r'for\s+([a-zA-Z_0-9]+)\s+in\s+range\(len\(([a-zA-Z_0-9]+)\)\):',
        r'for \1, item in enumerate(\2):',
        res
    )

    # Fix blocking time.sleep in async def
    if "async def" in res and "time.sleep" in res:
        res = res.replace("time.sleep", "await asyncio.sleep")
        if "import asyncio" not in res:
            res = "import asyncio\n" + res

    # Fix bare except
    res = re.sub(r'except:\s*\n\s*pass', 'except Exception as err:\n        logging.error(f"Handled error: {err}")', res)
    res = re.sub(r'except:\s*', 'except Exception as err:\n        ', res)

    # Replace os.system with subprocess.run(..., shell=False)
    res = re.sub(r'os\.system\((.*?)\)', r'subprocess.run([\1], check=True)', res)

    # Fix hardcoded secrets pattern to os.getenv
    res = re.sub(
        r'(?i)(api[_-]?key|secret|password)\s*=\s*["\']([a-zA-Z0-9_\-\.\/+=]{8,})["\']',
        r'\1 = os.getenv("\1".upper(), "")',
        res
    )

    if "os.getenv" in res and "import os" not in res:
        res = "import os\n" + res
    if "logging." in res and "import logging" not in res:
        res = "import logging\n" + res

    return res


def generate_dockerfile(imports: List[str], has_main: bool) -> str:
    is_fastapi = "fastapi" in imports
    is_flask = "flask" in imports

    if is_fastapi:
        cmd = '["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "10000"]'
        port = "10000"
    elif is_flask:
        cmd = '["gunicorn", "--bind", "0.0.0.0:10000", "app:app"]'
        port = "10000"
    elif has_main:
        cmd = '["python", "main.py"]'
        port = "8000"
    else:
        cmd = '["python", "server.py"]'
        port = "8000"

    return f"""# ==============================================================================
# Production Multi-Stage Dockerfile for Python (Optimized for Render)
# Generated by PyReviewer
# ==============================================================================

# Stage 1: Build & Dependencies
FROM python:3.12-slim AS builder

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \\
    PYTHONUNBUFFERED=1 \\
    PIP_NO_CACHE_DIR=1

# Install build dependencies if native C modules exist
RUN apt-get update && apt-get install -y --no-install-recommends \\
    gcc \\
    libpq-dev \\
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --user --no-warn-script-location -r requirements.txt

# Stage 2: Hardened Non-Root Production Runtime
FROM python:3.12-slim AS runner

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \\
    PYTHONUNBUFFERED=1 \\
    PATH="/home/appuser/.local/bin:$PATH" \\
    PORT={port}

# Create non-root unprivileged service user
RUN groupadd -g 10001 appuser && \\
    useradd -u 10001 -g appuser -s /bin/bash -m appuser

# Copy installed wheels and binaries from builder
COPY --from=builder /root/.local /home/appuser/.local
COPY --chown=appuser:appuser . .

USER appuser

EXPOSE {port}

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \\
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:' + os.getenv('PORT', '{port}') + '/healthz')" || exit 1

CMD {cmd}
"""


def generate_dockerignore() -> str:
    return """__pycache__/
*.pyc
*.pyo
*.pyd
.Python
env/
venv/
.venv/
.git/
.gitignore
.dockerignore
.DS_Store
*.log
.env
.env.*
.pytest_cache/
.coverage
htmlcov/
dist/
build/
*.egg-info/
"""


def generate_render_yaml(imports: List[str]) -> str:
    return """# ==============================================================================
# Render Blueprint Specification (render.yaml)
# Generated by PyReviewer
# Deploy on Render: https://dashboard.render.com/blueprints
# ==============================================================================
services:
  - type: web
    name: pyreviewer-service
    env: docker
    plan: free
    region: oregon
    dockerfilePath: ./Dockerfile
    dockerContext: .
    healthCheckPath: /healthz
    autoDeploy: true
    envVars:
      - key: PORT
        value: 10000
      - key: PYTHONUNBUFFERED
        value: 1
      - key: ENVIRONMENT
        value: production
"""
