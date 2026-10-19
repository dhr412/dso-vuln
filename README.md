# DevSecOps Agentic Vulnerability Remediation PoC

A **local-first, minimal proof of concept** showing how four small agents can
process a scanner finding, inspect source context, propose a targeted
secure-code change, validate the candidate, and hand it to a human for
approval.

> ⚠️ **Teaching/demo only.** Scanner findings and AI-proposed fixes require
> human review. This PoC does **not** guarantee exploitability detection,
> eliminate false positives, or guarantee regression-free patches. It never
> modifies your files, opens a pull request, commits, or deploys anything.

The default demo mode is fully deterministic and runs **offline** — no API
key, no model server, no network access. A local
[Ollama](https://ollama.com) model is optional and disabled by default.

---

## Requirements

- Python 3.9 or newer (tested on 3.13)
- [uv](https://docs.astral.sh/uv/) (used for the environment and commands)
- `streamlit`, `pytest`, and (optionally) `requests` — installed from
  `requirements.txt`

## Setup

```pwsh
# from the project root
uv venv .venv
uv pip install -r requirements.txt
```

## Run the app

```pwsh
uv run streamlit run app.py
```

Then open the URL Streamlit prints (default <http://localhost:8501>).

## Run the tests

```pwsh
uv run pytest test_app.py -v
```

Expected: **62 passed** (roughly 25 seconds). The Critic agent runs these same
trusted tests during validation.

---

## Using the bundled demo (no uploads, no model, no network)

1. Leave **Enable Ollama** off in the sidebar.
2. Keep the input mode on **Bundled demo**.
3. Click **▶ Run agents**.
4. Review the sections in order:
   - **Findings** — the normalized `sample_semgrep.json` finding.
   - **Agent Trace** — Planner → Research → Developer → Critic.
   - **Source Context** — a bounded snippet of `vulnerable_app.py` around line 7.
   - **Patch Review** — the unified diff and the Critic's validation checklist
     (`non_empty`, `bounded_size`, `allowed_file`, `ast_parse`, `unit_tests`).
   - **Human Review / Governance Gate** — approve or reject.
5. Click **✅ Approve candidate** to enable the downloads:
   - `candidate.patch` — the proposed unified diff
   - `audit_record.json` — the per-run audit record
   - `summary_report.md` — a Markdown summary

The expected deterministic patch is exactly two lines inside
`get_user_by_name`:

```diff
-    query = "SELECT * FROM users WHERE username = '" + username + "'"
-    cursor.execute(query)
+    query = "SELECT * FROM users WHERE username = ?"
+    cursor.execute(query, (username,))
```

## Uploading your own inputs

- **Scanner JSON** — a Semgrep-style report with a top-level `results` array.
  Fields are read defensively (`check_id`, `path`, `start.line`, `extra.message`,
  `extra.severity`, and optional `extra.metadata` such as `cwe`, `owasp`, and
  `references`). Missing severity becomes `UNKNOWN`; malformed numbers default
  to `0` instead of crashing.
- **Source ZIP (optional)** — inspected in a disposable temporary workspace.
  Extraction rejects invalid archives, absolute paths, drive-letter paths,
  `..` traversal, backslash traversal, NUL bytes, symlinks, archives over 200
  members, and uncompressed content over 50 MB.

If a reported file is missing or outside the extracted workspace, the app says
so rather than guessing. A finding that does not match the one supported safe
transformation is **not** auto-patched; the app explains why and offers a
manual suggestion.

## Optional: local Ollama (disabled by default)

Only enable this if you have a local Ollama server. Nothing here is required
for the demo.

```pwsh
# one-time: pull a model, then start the server
ollama pull codellama
ollama serve
```

In the sidebar, turn on **Enable Ollama**, set the URL (default
`http://localhost:11434`) and model (default `codellama`), then run. LLM output
is requested as constrained JSON, shape-validated, and always labelled
**🟠 Ollama (untrusted draft)**. If Ollama is unavailable or returns an
unexpected shape, the app shows a clear error and suggests returning to the
deterministic path; it never pretends a model ran. To avoid Ollama entirely,
leave the toggle off — that is the default.

---

## Project layout (flat, monolithic)

```
app.py               # Streamlit UI + Planner, Research, Developer, Critic, audit
test_app.py          # Unit tests (parsing, patching, ZIP safety, critic, audit)
sample_semgrep.json  # Bundled Semgrep-style finding fixture
vulnerable_app.py    # DELIBERATELY vulnerable SQLite training fixture (not real)
requirements.txt
README.md
poc_report.md        # Scope, implementation, and actual test results
.gitignore
```

Runtime workspaces are created in the operating system temp directory and do
not change this layout.

## Safety and governance controls

- Never writes to the uploaded archive or the original project; only produces a
  separate patch artifact.
- All archive member paths are validated before writing; traversal, absolute
  paths, and symlinks are rejected.
- The Critic verifies the diff targets an allowed file, the patched Python
  parses with `ast.parse`, and the candidate is non-empty and bounded, then runs
  the project's own trusted unit tests.
- A failed candidate is retried at most once (two attempts total); each attempt
  is recorded and the loop stops safely.
- Audit records contain finding identifiers, agent decisions, a patch SHA-256,
  critic checks, retry count, human decision, and provider mode — not full
  source code or secrets.
- No automatic commits, pull requests, deployments, or external lookups.

See [`poc_report.md`](poc_report.md) for scope, demonstrated results, and known
limitations.
