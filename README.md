# PyReviewer 🐍⚡
### Production-Grade Python AST, Security & Docker Packaging Reviewer
> *Built for my friend Dave for the **[Hacktoberfest Weekend Challenge: Build for a Friend](https://dev.to/challenges/hacktoberfest-weekend-2026-10-01)***
> *Featured Partner Category: **Best Use of Render ($200)***

[![Dockerized](https://img.shields.io/badge/Container-Docker%20Multi--Stage-blue.svg)](Dockerfile)
[![Deploy on Render](https://img.shields.io/badge/Deploy%20on-Render-00dfa2.svg)](render.yaml)
[![Open Source Python](https://img.shields.io/badge/Python-3.12%20%7C%203.14-yellow.svg)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-emerald.svg)](LICENSE)

---

## 🎯 The Story: Built for My Friend Dave

My close friend **Dave** is a self-taught junior Python developer transitioning into backend engineering and data pipelines. 

While Dave builds great prototypes, he frequently encounters classic junior traps that cause headaches during code reviews:
1. **Concurrency Hazards**: Calling blocking synchronous functions (`time.sleep()`, `requests.get()`) inside FastAPI `async def` endpoints, freezing the entire Uvicorn worker.
2. **Subtle Idiomatic Bugs**: Using mutable default parameters (`def connect(pool=[])`), creating shared state between distinct API requests.
3. **Security Vulnerabilities**: Writing raw SQL queries using f-strings (`f"SELECT ... WHERE id = '{user_id}'"`), using `os.system()` with unsanitized parameters, or unpickling untrusted payloads with `pickle.loads()`.
4. **Containerization Headaches**: Struggling to write clean Dockerfiles, resulting in 1.8GB bloated images, running containers as `root`, and forgetting `.dockerignore`.
5. **Review Delays**: Waiting hours or days for friends or senior developers to review pull requests.

**PyReviewer** is Dave’s automated senior pair programmer. It analyzes raw Python source code using **Python's native Abstract Syntax Tree (AST)**, calculates cyclomatic complexity and maintainability indices, flags OWASP security flaws with line numbers, produces an automated Git diff refactor, and generates production-ready, multi-stage **Dockerfiles** and `render.yaml` manifests ready for 1-click deployment on **Render**.

---

## 🚀 Key Features

- 🔍 **Deep AST & OWASP Security Inspection**:
  - `SEC-001`: Arbitrary code execution hazards (`eval`, `exec`).
  - `SEC-002`: Shell injection via `subprocess` or `os.system`.
  - `SEC-003`: Insecure deserialization (`pickle.loads`).
  - `SEC-005`: SQL Injection via string interpolation in queries.
  - `SEC-006`: Hardcoded API tokens and secret credentials.
- ⚡ **Async & Concurrency Audits**:
  - `PERF-001`: Detects synchronous blocking calls (`time.sleep`, `requests.get`) inside `async def` functions that block event loops.
- 🐍 **Idiomatic Python Refactoring**:
  - `IDIOM-001`: Mutable default arguments (`def f(x=[])`).
  - `IDIOM-002`: Unpythonic `range(len(items))` indexing.
  - `IDIOM-003`: Silent exception swallowing (`except: pass`).
- 🐳 **Automated Multi-Stage Dockerfile Synthesis**:
  - Inspects project dependencies (`fastapi`, `flask`, `sqlalchemy`, etc.).
  - Generates a hardened, multi-stage `Dockerfile` with non-root user `appuser` and healthcheck endpoints.
  - Generates `.dockerignore`.
- ☁️ **Deployable on Render**:
  - Pre-configured `render.yaml` Blueprint for Render web service deployments.
  - Built-in `/healthz` monitoring endpoint.
- 📝 **GitHub Pull Request Export**:
  - Formats all findings into a Markdown PR review comment ready to paste directly into GitHub.

---

## 🏗️ Architecture

```mermaid
graph TD
    A[Python Source Code] --> B[Python AST Parser (ast.parse)]
    B --> C[AST NodeVisitor Engine]
    C --> D[Security & OWASP Scanner]
    C --> E[Concurrency & Async Inspector]
    C --> F[Idiomatic Python Rules]
    D & E & F --> G[Metrics Calculator (Complexity, LOC, Maintainability)]
    G --> H[Senior Refactor Synthesizer & Unified Diff (difflib)]
    H --> I[Dependency Introspector]
    I --> J[Production Multi-Stage Dockerfile]
    I --> K[Render Blueprint Specification (render.yaml)]
    J & K --> L[🚀 Deploy to Render]
```

---

## 🚢 Deploying to Render with Docker

### Method 1: One-Click Render Blueprint (Recommended)
1. Fork or push this repository to GitHub.
2. Go to the [Render Dashboard](https://dashboard.render.com/blueprints).
3. Click **New +** > **Blueprint**.
4. Connect your repository. Render automatically reads `render.yaml`, builds the multi-stage Docker container, and deploys your service with automatic SSL and health checking.

### Method 2: Render Docker Web Service
1. In the Render Dashboard, click **New +** > **Web Service**.
2. Select your repository and choose **Docker** as the runtime.
3. Set the Health Check Path to `/healthz`.
4. Click **Create Web Service**.

---

## 💻 Local Development

PyReviewer is designed with zero external dependency bloat. It runs natively using Python 3's standard library:

```bash
# 1. Clone repository
git clone https://github.com/hay43/pyreviewer.git
cd pyreviewer

# 2. Start server
python3 server.py

# 3. Open in browser
# Access http://localhost:8080
```

### Running with Docker Locally

```bash
# Build Docker container
docker build -t pyreviewer:latest .

# Run container
docker run -p 8080:8080 pyreviewer:latest

# Verify healthcheck
curl http://localhost:8080/healthz
```

---

## 🏆 Hacktoberfest Weekend Challenge: Build for a Friend

- **Category**: **Best Use of Render ($200)**
- **Theme**: Build for a Friend (Dave, self-taught junior Python engineer)
- **Author**: Abdulaleem Zakariyah ([@hay_43](https://dev.to/hay_43))
- **Tags**: `#hf26challenge`, `#weekendchallenge`, `#devchallenge`, `#render`
