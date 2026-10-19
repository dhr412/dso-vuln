# DevSecOps Agentic Vulnerability Remediation PoC — Report

**Status:** Implemented and tested. All statements below reflect commands that
were actually run in this environment (Windows, Python 3.13, Streamlit 1.66,
pytest 9.1.1, managed with `uv`).

## Objective and scope

Demonstrate a **local-first** agentic workflow that takes a security-scanner
finding, inspects nearby source, proposes a focused remediation, validates the
candidate, and requires human approval before any artifact can be downloaded.
This is a teaching/demo PoC, not a production scanner or autonomous patching
service. It does not claim to detect all exploitable issues, remove false
positives, or guarantee regression-free patches.

## Implemented agent workflow

All agents live in the single `app.py`:

1. **Planner** — calls `parse_semgrep_report`, normalizes findings
   (`check_id`, `path`, `start.line`, `extra.message`, `extra.severity`, optional
   `extra.metadata`), marks missing severity `UNKNOWN`, sorts by
   severity → rule → path → line, and emits a readable plan plus a five-step
   execution graph.
2. **Research** — shows a bounded snippet around the reported line and
   summarizes weakness, evidence, impact, and uncertainty. For the bundled
   SQL-injection rule it explains why concatenation is unsafe and why
   parameterized queries are the expected fix. Knowledge is local/bundled; the
   app displays scanner-provided CWE/OWASP/reference metadata but does not
   query live CVE or threat-intelligence sources.
3. **Developer** — produces a unified diff. For the bundled rule it applies one
   narrow deterministic transformation (string concatenation → SQLite
   parameterized query). Unsupported findings are **not** rewritten; the app
   explains it cannot safely auto-patch and shows a manual suggestion.
4. **Critic** — validates non-empty, bounded, allowed-file, and `ast.parse`
   checks, runs the project's own trusted unit tests, then returns a structured
   verdict. A failed candidate is retried **at most once** (two attempts total).
5. **Human governance gate** — approve/reject. Approval only enables downloads;
   it never writes to the source, opens a PR, or deploys.

An optional, disabled-by-default **Ollama** provider sits behind the same
interface; its output is requested as constrained JSON, shape-validated, and
labelled **untrusted**. If it is unavailable it produces a clear error and the
user can return to deterministic mode.

## How to install and run

```pwsh
uv venv .venv
uv pip install -r requirements.txt
uv run streamlit run app.py     # UI (default http://localhost:8501)
uv run pytest test_app.py -v    # tests
```

## Demo scenario and expected safe patch

The bundled fixture `vulnerable_app.py` contains a deliberate SQL-injection
pattern and `sample_semgrep.json` reports it at line 7. The deterministic patch
changes only the two offending lines in `get_user_by_name`:

```diff
--- a/vulnerable_app.py
+++ b/vulnerable_app.py
@@ -4,8 +4,8 @@
 def get_user_by_name(db_path: str, username: str) -> list:
     conn = sqlite3.connect(db_path)
     cursor = conn.cursor()
-    query = "SELECT * FROM users WHERE username = '" + username + "'"
-    cursor.execute(query)
+    query = "SELECT * FROM users WHERE username = ?"
+    cursor.execute(query, (username,))
     results = cursor.fetchall()
     conn.close()
     return results
```

## Validation performed and actual results

- **Unit tests:** `uv run pytest test_app.py -v` → **62 passed in 24.96s**.
  Coverage includes report parsing (valid, malformed JSON, wrong types, empty,
  invalid line values), severity normalization, planner ordering, bounded
  snippets, deterministic patching, semantic parameterization, workspace/path
  resolution containment, ZIP-slip/ absolute/backslash/symlink/oversize
  rejection, critic verdicts, the retry loop, and audit fields.
- **Patch is semantically correct:** a test executes the patched fixture against
  an in-memory-created SQLite table and confirms `"alice"` returns one row while
  the payload `"' OR '1'='1"` returns none (parameterized, not interpolated).
- **Diff is well formed:** headers are `--- a/...` / `+++ b/...` followed by a
  proper `@@` hunk; only the two offending lines change.
- **UI smoke test (headless, `streamlit.testing.v1.AppTest`):** initial render →
  Run agents → Planner/Research/Developer/Critic all complete (`critic passed ·
  retries=0`, all five checks ✅) → Approve → success and downloads enabled.
- **Server smoke test:** `streamlit run app.py` served
  `GET /_stcore/health` → **200 ok**.
- **Original inputs unmodified:** SHA-256 before/after the workflow was
  unchanged — `vulnerable_app.py`
  `b1c45ad18be04574c59c0d74437ab96ab6c43fb1d78e41d33bfa06ad690a3bda`,
  `sample_semgrep.json`
  `c35bf482d74676931ad0818b04deebd356fb7766d74c7900f65a8d27c8283156`.

## Audit trail

Each run builds a JSON audit record containing: timestamp (UTC), finding
identifiers (rule, path, line), concise agent decisions, patch SHA-256, the
Critic check map, retry count, human decision, and provider mode
(`deterministic` or `ollama`). It intentionally excludes full source code and
secrets.

## Safety and governance controls

- Disposable temp workspace only; uploaded archives and original files are never
  mutated. A separate `.patch` artifact is produced.
- Every archive member is validated (no absolute/drive paths, `..`, NUL bytes,
  symlinks; bounded member count and total size).
- Critic runs only this project's trusted tests; it never executes uploaded
  repository code or its test commands automatically.
- Human approval is required before any artifact is downloaded.
- No commits, pull requests, deployments, or automatic external lookups.

## Known limitations and next steps

- Only **one** deterministic safe transformation is implemented (the bundled
  SQL-injection rule); everything else is refuse-and-explain.
- No dynamic data-flow or exploitability confirmation; static checks cannot
  prove behavioral correctness.
- The target-repository test-execution feature is intentionally **not**
  implemented (it would require explicit, warned, time-limited, disposable
  opt-in).
- The Ollama path is implemented and shape-validated but was not exercised
  against a live model in this environment; only the deterministic path was
  end-to-end tested.
- Temporary workspaces are left for the OS to clean up and are not tracked by
  the project.
- Future work: additional safe rules, richer repository context, trusted local
  vulnerability metadata, and review-gated CI/PR generation.
