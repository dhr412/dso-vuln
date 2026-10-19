from __future__ import annotations

import ast
import difflib
import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import textwrap
import zipfile
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any

import streamlit as st

MAX_ZIP_MEMBERS = 200
MAX_ZIP_TOTAL_BYTES = 50 * 1024 * 1024
MAX_SNIPPET_LINES = 20
MAX_LLM_PATCH_CHARS = 200_000
SUPPORTED_AUTO_PATCH_RULES = {
    "python.lang.security.audit.formatted-sql-query.formatted-sql-query",
}
OLLAMA_DEFAULT_URL = "http://localhost:11434"
OLLAMA_DEFAULT_MODEL = "codellama"


@dataclass
class Finding:
    check_id: str
    path: str
    line: int
    col: int
    message: str
    severity: str
    cwe: list[str] = field(default_factory=list)
    owasp: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)


@dataclass
class TaskPlan:
    findings: list[Finding]
    selected: Finding
    reason: str
    execution_graph: list[str]


@dataclass
class ResearchResult:
    finding: Finding
    snippet: str
    snippet_start: int
    summary: str
    evidence: str
    impact: str
    uncertainty: str
    provider: str


@dataclass
class DeveloperResult:
    finding: Finding
    original_code: str
    patched_code: str
    diff: str
    explanation: str
    provider: str
    attempt: int = 1


@dataclass
class CriticVerdict:
    passed: bool
    checks: dict[str, bool]
    errors: list[str]
    status_explanation: str
    test_output: str


@dataclass
class AuditRecord:
    timestamp: str
    finding_id: str
    finding_path: str
    finding_line: int
    agent_decisions: dict[str, str]
    patch_sha256: str
    critic_checks: dict[str, bool]
    retry_count: int
    human_decision: str
    provider_mode: str



BUNDLED_REPORT_PATH = Path(__file__).parent / "sample_semgrep.json"
BUNDLED_SOURCE_PATH = Path(__file__).parent / "vulnerable_app.py"

def _read_bundled(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except OSError:
        return ""


BUNDLED_REPORT_TEXT = _read_bundled(BUNDLED_REPORT_PATH)
BUNDLED_SOURCE_TEXT = _read_bundled(BUNDLED_SOURCE_PATH)



def _severity_rank(s: str) -> int:
    return {"ERROR": 0, "WARNING": 1, "INFO": 2, "UNKNOWN": 3}.get(s.upper(), 3)


def _as_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _as_str_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item) for item in value]


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def _bounded_snippet(source_lines: list[str], target_line: int,
                     context: int = MAX_SNIPPET_LINES // 2) -> tuple[str, int]:
    n = len(source_lines)
    target_idx = max(0, min(target_line - 1, n - 1))
    start = max(0, target_idx - context)
    end   = min(n, target_idx + context + 1)
    numbered = [
        f"{i + 1:4d} | {source_lines[i]}"
        for i in range(start, end)
    ]
    return "\n".join(numbered), start + 1



def _safe_extract_zip(zip_bytes: bytes) -> tuple[str, list[str]]:
    workspace = tempfile.mkdtemp(prefix="poc_ws_")
    workspace_path = Path(workspace).resolve()

    try:
        try:
            zf = zipfile.ZipFile(io.BytesIO(zip_bytes))
        except zipfile.BadZipFile as exc:
            raise ValueError(f"Not a valid ZIP archive: {exc}") from exc

        with zf:
            members = zf.infolist()

            if len(members) > MAX_ZIP_MEMBERS:
                raise ValueError(
                    f"Archive has {len(members)} members; limit is {MAX_ZIP_MEMBERS}."
                )
            total = sum(m.file_size for m in members)
            if total > MAX_ZIP_TOTAL_BYTES:
                raise ValueError(
                    f"Archive uncompressed size {total / 1e6:.1f} MB exceeds "
                    f"limit of {MAX_ZIP_TOTAL_BYTES / 1e6:.0f} MB."
                )

            extracted: list[str] = []
            written = 0
            for member in members:
                raw = member.filename.replace("\\", "/")

                if "\x00" in raw:
                    raise ValueError(
                        f"NUL byte in archive member name rejected: {member.filename!r}"
                    )

                if raw.startswith("/") or re.match(r"^[A-Za-z]:", raw):
                    raise ValueError(
                        f"Absolute path in archive rejected: {member.filename!r}"
                    )

                parts = PurePosixPath(raw).parts
                if any(p == ".." for p in parts):
                    raise ValueError(
                        f"Path traversal in archive rejected: {member.filename!r}"
                    )
                if member.is_dir():
                    continue

                mode = (member.external_attr >> 16) & 0xFFFF
                if (mode & 0o170000) == 0o120000:
                    raise ValueError(
                        f"Symlink in archive rejected: {member.filename!r}"
                    )

                safe_parts = [p for p in parts if p not in ("", ".")]
                if not safe_parts:
                    continue
                safe_rel = Path(*safe_parts)
                dest = (workspace_path / safe_rel).resolve()

                if not dest.is_relative_to(workspace_path):
                    raise ValueError(
                        f"Path traversal detected for member: {member.filename!r}"
                    )

                try:
                    data = zf.read(member.filename)
                except (RuntimeError, zipfile.BadZipFile) as exc:
                    raise ValueError(
                        f"Could not read archive member {member.filename!r}: {exc}"
                    ) from exc

                written += len(data)
                if written > MAX_ZIP_TOTAL_BYTES:
                    raise ValueError(
                        f"Extracted contents exceed the "
                        f"{MAX_ZIP_TOTAL_BYTES / 1e6:.0f} MB limit."
                    )

                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_bytes(data)
                extracted.append(safe_rel.as_posix())

        return workspace, extracted
    except Exception:
        shutil.rmtree(workspace, ignore_errors=True)
        raise


def _resolve_source_file(workspace: str | None, report_path: str,
                         bundled_source: str | None = None
                         ) -> tuple[str | None, str | None]:
    if workspace:
        ws = Path(workspace).resolve()
        candidate = (ws / report_path).resolve()
        if not candidate.is_relative_to(ws):
            return None, f"Path '{report_path}' escapes the workspace."
        if candidate.is_file():
            return str(candidate), None
        return None, (
            f"File '{report_path}' not found inside the uploaded archive. "
            f"Check that the ZIP preserves the path used by the scanner report."
        )
    if bundled_source:
        return None, None
    return None, f"No workspace and no bundled source for '{report_path}'."



def parse_semgrep_report(raw: str | bytes) -> list[Finding]:
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8", errors="replace")
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JSON: {exc}") from exc

    if not isinstance(data, dict):
        raise ValueError("Expected a JSON object at the top level.")
    results = data.get("results")
    if not isinstance(results, list):
        raise ValueError("Expected a 'results' array in the report.")
    if not results:
        raise ValueError("The scanner report contains no findings.")

    findings: list[Finding] = []
    for idx, r in enumerate(results):
        if not isinstance(r, dict):
            continue
        check_id  = str(r.get("check_id") or f"unknown-rule-{idx}")
        path      = str(r.get("path") or "unknown")
        start     = r.get("start")
        start     = start if isinstance(start, dict) else {}
        line      = _as_int(start.get("line", 0), 0)
        col       = _as_int(start.get("col", 0), 0)
        extra     = r.get("extra")
        extra     = extra if isinstance(extra, dict) else {}
        message   = str(extra.get("message") or "No message provided.")
        raw_sev   = str(extra.get("severity") or "UNKNOWN").upper()
        severity  = raw_sev if raw_sev in ("ERROR", "WARNING", "INFO") else "UNKNOWN"
        meta      = extra.get("metadata")
        meta      = meta if isinstance(meta, dict) else {}
        cwe       = _as_str_list(meta.get("cwe"))
        owasp     = _as_str_list(meta.get("owasp"))
        refs      = _as_str_list(meta.get("references"))
        findings.append(Finding(check_id, path, line, col, message, severity, cwe, owasp, refs))

    if not findings:
        raise ValueError("The scanner report contains no usable findings.")
    return findings



class PlannerAgent:

    def run(self, findings: list[Finding]) -> TaskPlan:
        if not findings:
            raise ValueError("No findings to plan.")

        sorted_f = sorted(
            findings,
            key=lambda f: (_severity_rank(f.severity), f.check_id, f.path, f.line),
        )
        selected = sorted_f[0]

        reason = (
            f"Selected finding '{selected.check_id}' in '{selected.path}' "
            f"at line {selected.line} (severity={selected.severity}) "
            f"because it has the highest priority rank among {len(findings)} finding(s)."
        )

        graph = [
            f"[1] Planner   → normalised {len(findings)} finding(s), selected top priority",
            f"[2] Research  → inspect '{selected.path}' around line {selected.line}",
            f"[3] Developer → generate remediation diff",
            f"[4] Critic    → validate diff (syntax, scope, tests) — up to 1 retry",
            f"[5] Human     → approve or reject candidate patch",
        ]

        return TaskPlan(
            findings=sorted_f,
            selected=selected,
            reason=reason,
            execution_graph=graph,
        )



BUNDLED_SQL_SUMMARY = """
**Weakness:** CWE-89 – SQL Injection via string concatenation.

**Evidence in code (line {line}):**
The function `get_user_by_name` builds a SQL query by concatenating the
`username` argument directly into the query string:

```python
query = "SELECT * FROM users WHERE username = '" + username + "'"
```

**Why this is risky:**
An attacker who controls `username` can inject arbitrary SQL. For example,
passing `' OR '1'='1` causes the query to return every row; passing
`'; DROP TABLE users;--` destroys the table. The database cannot distinguish
intended SQL keywords from injected ones because they arrive in the same string.

**Expected remediation:**
Use a parameterized query so the database driver handles quoting:

```python
cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
```

**Impact:** Confidentiality (data exfiltration), Integrity (data destruction),
potentially Authentication bypass.

**Remaining uncertainty:** This PoC does not dynamically trace data flow to
confirm the value of `username` originates from untrusted external input.
Confirming exploitability requires manual review or dynamic analysis.

**Note:** CWE/OWASP references are taken from the scanner report metadata;
this PoC has not queried live CVE databases or external threat-intelligence sources.
""".strip()


class ResearchAgent:

    def run(
        self,
        finding: Finding,
        source_text: str,
        provider: str = "deterministic",
        ollama_cfg: dict | None = None,
    ) -> ResearchResult:
        lines = source_text.splitlines()
        snippet, start = _bounded_snippet(lines, finding.line)

        if provider == "ollama" and ollama_cfg:
            return self._ollama_research(finding, snippet, start, ollama_cfg)

        if finding.check_id in SUPPORTED_AUTO_PATCH_RULES:
            summary_raw = BUNDLED_SQL_SUMMARY.format(line=finding.line)
        else:
            summary_raw = (
                f"Rule '{finding.check_id}' is not in the bundled knowledge base. "
                f"The finding message is: {finding.message}\n\n"
                f"No detailed bundled analysis is available. "
                f"Refer to the scanner documentation and the CWE/OWASP references in the report."
            )

        return ResearchResult(
            finding=finding,
            snippet=snippet,
            snippet_start=start,
            summary=summary_raw,
            evidence=f"Snippet shown above from '{finding.path}' lines {start}+.",
            impact=(
                "Confidentiality, Integrity, Authentication bypass (SQL injection)."
                if finding.check_id in SUPPORTED_AUTO_PATCH_RULES
                else "Refer to CWE/OWASP metadata in the scanner report."
            ),
            uncertainty=(
                "Exploitability not dynamically confirmed; manual review required."
            ),
            provider="deterministic",
        )


    def _ollama_research(
        self,
        finding: Finding,
        snippet: str,
        snippet_start: int,
        cfg: dict,
    ) -> ResearchResult:
        import requests

        prompt = textwrap.dedent(f"""\
            You are a security code reviewer. Analyse this code snippet and the
            scanner finding below. Reply ONLY with a JSON object with these keys:
            summary, evidence, impact, uncertainty.

            Finding: {finding.message}
            Rule: {finding.check_id}
            Severity: {finding.severity}

            Code snippet (starting at line {snippet_start}):
            ```
            {snippet}
            ```

            Respond ONLY with a JSON object. No prose outside the JSON.
        """)

        try:
            resp = requests.post(
                f"{cfg['url']}/api/generate",
                json={"model": cfg["model"], "prompt": prompt, "stream": False},
                timeout=30,
            )
            resp.raise_for_status()
            raw_text = resp.json().get("response", "")
            parsed = self._extract_json(raw_text)
        except Exception as exc:
            raise RuntimeError(f"Ollama research failed: {exc}") from exc

        required = ("summary", "evidence", "impact", "uncertainty")
        if not all(
            isinstance(parsed.get(k), str) and parsed[k].strip() for k in required
        ):
            raise RuntimeError(
                "Ollama returned an unexpected response shape; expected a JSON "
                "object with string keys: " + ", ".join(required) + ". "
                "No result was produced — disable Ollama to use the deterministic path."
            )

        return ResearchResult(
            finding=finding,
            snippet=snippet,
            snippet_start=snippet_start,
            summary=parsed["summary"],
            evidence=parsed["evidence"],
            impact=parsed["impact"],
            uncertainty=parsed["uncertainty"],
            provider="ollama",
        )

    @staticmethod
    def _extract_json(text: str) -> dict:
        match = re.search(r"\{.*\}", text, re.DOTALL)
        if match:
            try:
                return json.loads(match.group())
            except json.JSONDecodeError:
                pass
        return {}



_SQL_INJECT_PATTERN = re.compile(
    r'^(?P<indent>[ \t]*)query\s*=\s*"SELECT \* FROM users WHERE username = \'"'
    r'\s*\+\s*username\s*\+\s*"\'"[ \t]*\n',
    re.MULTILINE,
)
_SQL_EXECUTE_PATTERN = re.compile(
    r'^(?P<indent>[ \t]*)cursor\.execute\(query\)[ \t]*\n',
    re.MULTILINE,
)

_SAFE_QUERY_BODY   = 'query = "SELECT * FROM users WHERE username = ?"\n'
_SAFE_EXECUTE_BODY = 'cursor.execute(query, (username,))\n'

DETERMINISTIC_EXPLANATION = """
**Remediation applied (deterministic rule):**

Replaced the vulnerable string-concatenated query with a parameterized query.

**Before:**
```python
query = "SELECT * FROM users WHERE username = '" + username + "'"
cursor.execute(query)
```

**After:**
```python
query = "SELECT * FROM users WHERE username = ?"
cursor.execute(query, (username,))
```

The `?` placeholder causes the SQLite driver to transmit the value as a separate
parameter rather than interpolating it into the SQL text, preventing injection.

**Scope:** Only the two lines inside `get_user_by_name` that build and execute
the unsafe query have been changed. No other code was modified.

**Provider:** deterministic rule — not an LLM draft.
""".strip()


class DeveloperAgent:

    def run(
        self,
        finding: Finding,
        source_text: str,
        source_path: str,
        provider: str = "deterministic",
        ollama_cfg: dict | None = None,
        attempt: int = 1,
    ) -> DeveloperResult:
        if provider == "ollama" and ollama_cfg:
            return self._ollama_patch(finding, source_text, source_path,
                                      ollama_cfg, attempt)
        return self._deterministic_patch(finding, source_text, source_path, attempt)

    def _deterministic_patch(
        self,
        finding: Finding,
        source_text: str,
        source_path: str,
        attempt: int,
    ) -> DeveloperResult:
        if finding.check_id not in SUPPORTED_AUTO_PATCH_RULES:
            return DeveloperResult(
                finding=finding,
                original_code=source_text,
                patched_code=source_text,
                diff="",
                explanation=(
                    f"This PoC cannot safely auto-patch rule '{finding.check_id}'. "
                    f"No deterministic safe transformation is defined for it.\n\n"
                    f"**Suggested remediation (manual):** {finding.message}\n\n"
                    f"Use Ollama mode for an untrusted draft, or patch manually."
                ),
                provider="unsupported",
                attempt=attempt,
            )

        patched = source_text
        if not _SQL_INJECT_PATTERN.search(patched):
            return DeveloperResult(
                finding=finding,
                original_code=source_text,
                patched_code=source_text,
                diff="",
                explanation=(
                    "The expected vulnerable SQL pattern was not found verbatim "
                    "in the source text. The file may have been modified already "
                    "or the pattern does not match. Manual inspection required."
                ),
                provider="unsupported",
                attempt=attempt,
            )

        patched = _SQL_INJECT_PATTERN.sub(
            lambda m: m.group("indent") + _SAFE_QUERY_BODY, patched
        )
        patched = _SQL_EXECUTE_PATTERN.sub(
            lambda m: m.group("indent") + _SAFE_EXECUTE_BODY, patched
        )

        diff = "".join(
            difflib.unified_diff(
                source_text.splitlines(keepends=True),
                patched.splitlines(keepends=True),
                fromfile=f"a/{source_path}",
                tofile=f"b/{source_path}",
            )
        )

        return DeveloperResult(
            finding=finding,
            original_code=source_text,
            patched_code=patched,
            diff=diff,
            explanation=DETERMINISTIC_EXPLANATION,
            provider="deterministic",
            attempt=attempt,
        )

    def _ollama_patch(
        self,
        finding: Finding,
        source_text: str,
        source_path: str,
        cfg: dict,
        attempt: int,
    ) -> DeveloperResult:
        import requests

        prompt = textwrap.dedent(f"""\
            You are a secure-code assistant. Given the vulnerable Python source below
            and the scanner finding, produce ONLY a unified diff that fixes the
            vulnerability. Do not change any other code.
            Output ONLY a JSON object with keys "patched_code" and "explanation".
            The patched_code value must be the complete corrected file content.

            Finding: {finding.message}
            Rule: {finding.check_id}
            File: {source_path}

            Source:
            ```python
            {source_text}
            ```

            Respond ONLY with a JSON object. No prose outside the JSON.
        """)

        try:
            resp = requests.post(
                f"{cfg['url']}/api/generate",
                json={"model": cfg["model"], "prompt": prompt, "stream": False},
                timeout=60,
            )
            resp.raise_for_status()
            raw_text = resp.json().get("response", "")
            parsed = ResearchAgent._extract_json(raw_text)
        except Exception as exc:
            raise RuntimeError(f"Ollama developer call failed: {exc}") from exc

        patched = str(parsed.get("patched_code", ""))
        explanation = str(parsed.get("explanation", "No explanation returned."))

        if not patched.strip():
            raise RuntimeError(
                "Ollama returned an empty patched_code; no candidate was produced. "
                "Disable Ollama to use the deterministic path."
            )
        if len(patched) > MAX_LLM_PATCH_CHARS:
            raise RuntimeError(
                f"Ollama returned a candidate of {len(patched)} chars, exceeding "
                f"the {MAX_LLM_PATCH_CHARS} limit. Refusing the oversized draft."
            )

        diff = "".join(
            difflib.unified_diff(
                source_text.splitlines(keepends=True),
                patched.splitlines(keepends=True),
                fromfile=f"a/{source_path}",
                tofile=f"b/{source_path}",
            )
        )

        return DeveloperResult(
            finding=finding,
            original_code=source_text,
            patched_code=patched,
            diff=diff,
            explanation=f"⚠️ **UNTRUSTED OLLAMA DRAFT** — requires human review.\n\n{explanation}",
            provider="ollama",
            attempt=attempt,
        )



ALLOWED_PATCH_FILES = {"vulnerable_app.py"}
MAX_PATCH_CHARS = 10_000


class CriticAgent:

    def run(
        self,
        dev_result: DeveloperResult,
        source_path: str,
    ) -> CriticVerdict:
        checks: dict[str, bool] = {}
        errors: list[str] = []

        checks["non_empty"] = bool(dev_result.diff.strip())
        if not checks["non_empty"]:
            errors.append("Diff is empty — no change was produced.")

        checks["bounded_size"] = len(dev_result.diff) <= MAX_PATCH_CHARS
        if not checks["bounded_size"]:
            errors.append(
                f"Diff exceeds {MAX_PATCH_CHARS} chars "
                f"({len(dev_result.diff)} chars). Refusing oversized patch."
            )

        base = os.path.basename(source_path)
        checks["allowed_file"] = base in ALLOWED_PATCH_FILES
        if not checks["allowed_file"]:
            errors.append(
                f"File '{base}' is not in the allowed patch targets: "
                f"{ALLOWED_PATCH_FILES}. The PoC will not auto-approve patches "
                f"for arbitrary files."
            )

        try:
            ast.parse(dev_result.patched_code)
            checks["ast_parse"] = True
        except SyntaxError as exc:
            checks["ast_parse"] = False
            errors.append(f"Patched code has syntax error: {exc}")

        test_out, test_ok = self._run_tests()
        checks["unit_tests"] = test_ok
        if not test_ok:
            errors.append("Project unit tests failed — see test output below.")

        passed = all(checks.values())
        status = (
            "✅ All checks passed. Candidate is ready for human review."
            if passed
            else "❌ One or more checks failed. See errors for details."
        )

        return CriticVerdict(
            passed=passed,
            checks=checks,
            errors=errors,
            status_explanation=status,
            test_output=test_out,
        )

    @staticmethod
    def _run_tests() -> tuple[str, bool]:
        test_file = Path(__file__).parent / "test_app.py"
        if not test_file.exists():
            return "test_app.py not found — skipped.", False

        child_env = dict(os.environ)
        child_env["DSO_POC_CRITIC_CHILD"] = "1"
        try:
            result = subprocess.run(
                [sys.executable, "-m", "pytest", str(test_file), "-v", "--tb=short",
                 "--no-header", "-q"],
                capture_output=True,
                text=True,
                timeout=120,
                cwd=str(Path(__file__).parent),
                env=child_env,
            )
            output = (result.stdout + result.stderr).strip()
            passed = result.returncode == 0
            return output, passed
        except subprocess.TimeoutExpired:
            return "Tests timed out after 60 seconds.", False
        except Exception as exc:
            return f"Could not run tests: {exc}", False



def run_developer_critic_loop(
    finding: Finding,
    source_text: str,
    source_path: str,
    provider: str,
    ollama_cfg: dict | None,
) -> tuple[DeveloperResult, CriticVerdict, int]:
    dev_agent = DeveloperAgent()
    critic = CriticAgent()

    dev_result = dev_agent.run(finding, source_text, source_path,
                               provider, ollama_cfg, attempt=1)
    verdict = critic.run(dev_result, source_path)

    if verdict.passed:
        return dev_result, verdict, 0

    dev_result2 = dev_agent.run(finding, source_text, source_path,
                                provider, ollama_cfg, attempt=2)
    verdict2 = critic.run(dev_result2, source_path)
    return dev_result2, verdict2, 1



def build_audit_record(
    finding: Finding,
    planner: TaskPlan,
    research: ResearchResult,
    dev: DeveloperResult,
    verdict: CriticVerdict,
    human_decision: str,
    retry_count: int,
) -> AuditRecord:
    patch_hash = _sha256(dev.diff) if dev.diff else "no-diff"
    provider_mode = dev.provider if dev.provider in ("deterministic", "ollama") else "deterministic"
    return AuditRecord(
        timestamp=datetime.now(timezone.utc).isoformat(),
        finding_id=finding.check_id,
        finding_path=finding.path,
        finding_line=finding.line,
        agent_decisions={
            "planner": planner.reason,
            "research": f"Provider={research.provider}; "
                        f"snippet_start={research.snippet_start}",
            "developer": f"Provider={dev.provider}; attempt={dev.attempt}; "
                         f"diff_chars={len(dev.diff)}",
            "critic": verdict.status_explanation,
        },
        patch_sha256=patch_hash,
        critic_checks=verdict.checks,
        retry_count=retry_count,
        human_decision=human_decision,
        provider_mode=provider_mode,
    )


def build_markdown_report(
    finding: Finding,
    research: ResearchResult,
    dev: DeveloperResult,
    verdict: CriticVerdict,
    audit: AuditRecord,
) -> str:
    lines = [
        "# DevSecOps Agentic PoC — Patch Review Summary",
        "",
        f"**Generated:** {audit.timestamp}",
        f"**Provider mode:** {audit.provider_mode}",
        "",
        "---",
        "",
        "## Finding",
        "",
        f"| Field | Value |",
        f"|-------|-------|",
        f"| Rule | `{finding.check_id}` |",
        f"| File | `{finding.path}` |",
        f"| Line | {finding.line} |",
        f"| Severity | {finding.severity} |",
        f"| Message | {finding.message[:120]} |",
        "",
        "## Research Summary",
        "",
        research.summary,
        "",
        "## Proposed Patch",
        "",
        "```diff",
        dev.diff if dev.diff else "(no diff produced)",
        "```",
        "",
        "## Critic Validation",
        "",
        f"**Result:** {verdict.status_explanation}",
        "",
        "| Check | Passed |",
        "|-------|--------|",
        *[f"| {k} | {'✅' if v else '❌'} |" for k, v in verdict.checks.items()],
        "",
        f"**Retry count:** {audit.retry_count}",
        "",
        "## Human Decision",
        "",
        f"**Decision:** {audit.human_decision.upper()}",
        "",
        "---",
        "",
        "> ⚠️ This is a PoC demo. Scanner findings and AI-proposed fixes require human review.",
        "> Approval downloads a review artifact only; no files are modified automatically.",
    ]
    return "\n".join(lines)



def _badge(provider: str) -> str:
    if provider == "deterministic":
        return "🔵 **Deterministic**"
    if provider == "ollama":
        return "🟠 **Ollama (untrusted draft)**"
    return "⚫ **Unsupported / No patch**"


def main():
    st.set_page_config(
        page_title="DevSecOps Agentic PoC",
        page_icon="🛡️",
        layout="wide",
    )
    st.title("🛡️ DevSecOps Agentic Vulnerability Remediation PoC")
    st.caption(
        "⚠️ **Teaching/demo only.** Scanner findings and AI-proposed fixes require "
        "human review. This PoC does not guarantee exploitability, eliminate false "
        "positives, or guarantee regression-free patches."
    )

    with st.sidebar:
        st.header("⚙️ Provider Settings")
        use_ollama = st.toggle("Enable Ollama (optional)", value=False)
        ollama_url   = st.text_input("Ollama URL",   value=OLLAMA_DEFAULT_URL)
        ollama_model = st.text_input("Ollama Model", value=OLLAMA_DEFAULT_MODEL)
        ollama_cfg = (
            {"url": ollama_url, "model": ollama_model} if use_ollama else None
        )
        provider = "ollama" if use_ollama else "deterministic"

        st.divider()
        st.markdown(
            "**Provider legend:**\n"
            "- 🔵 Deterministic – rule-based, auditable\n"
            "- 🟠 Ollama – untrusted LLM draft (requires human review)\n"
        )

    st.header("1 · Input")
    mode = st.radio(
        "Choose input mode",
        ["Bundled demo (no uploads needed)", "Upload scanner report + optional source ZIP"],
        horizontal=True,
    )

    source_text: str | None = None
    source_path_hint: str | None = None

    if mode.startswith("Bundled"):
        st.info("Using bundled `sample_semgrep.json` and `vulnerable_app.py` fixtures.")
        source_text = BUNDLED_SOURCE_TEXT
        source_path_hint = "vulnerable_app.py"
        can_run = bool(BUNDLED_REPORT_TEXT)
    else:
        col1, col2 = st.columns(2)
        with col1:
            rfile = st.file_uploader("Scanner JSON report", type=["json"])
        with col2:
            zfile = st.file_uploader("Source ZIP (optional)", type=["zip"])
        can_run = rfile is not None

    if st.button("▶ Run agents", type="primary", disabled=not can_run):
        workspace: str | None = None
        try:
            if mode.startswith("Bundled"):
                report_text = BUNDLED_REPORT_TEXT
            else:
                report_text = rfile.read().decode("utf-8", errors="replace")
                if zfile is not None:
                    workspace, members = _safe_extract_zip(zfile.read())
                    st.success(f"Archive extracted safely: {len(members)} file(s).")

            wf = execute_workflow(
                report_text=report_text,
                source_text=source_text,
                source_path_hint=source_path_hint,
                workspace=workspace,
                provider=provider,
                ollama_cfg=ollama_cfg,
            )
            st.session_state["wf"] = wf
            st.session_state["wf_error"] = None
            st.session_state["decision"] = "pending"
        except ValueError as exc:
            st.session_state["wf"] = None
            st.session_state["wf_error"] = f"Input rejected: {exc}"
        except RuntimeError as exc:
            st.session_state["wf"] = None
            st.session_state["wf_error"] = (
                f"{exc}\n\nHint: disable Ollama in the sidebar to use the "
                f"deterministic demo path."
            )
        except Exception as exc:
            st.session_state["wf"] = None
            st.session_state["wf_error"] = f"Unexpected error: {exc}"

    error = st.session_state.get("wf_error")
    if error:
        st.error(error)

    wf = st.session_state.get("wf")
    if wf is not None:
        st.caption(f"Result source: {_badge(wf.provider_requested)}")
        render_workflow(wf, st.session_state.get("decision", "pending"))
    elif not error:
        st.info("Choose an input mode and click **Run agents** to start the workflow.")


@dataclass
class WorkflowResult:
    findings: list[Finding]
    plan: TaskPlan
    research: ResearchResult
    dev_result: DeveloperResult
    verdict: CriticVerdict
    retry_count: int
    effective_path: str
    provider_requested: str
    warnings: list[str] = field(default_factory=list)


def execute_workflow(
    report_text: str,
    source_text: str | None,
    source_path_hint: str | None,
    workspace: str | None,
    provider: str,
    ollama_cfg: dict | None,
) -> WorkflowResult:
    findings = parse_semgrep_report(report_text)
    plan = PlannerAgent().run(findings)
    finding = plan.selected

    if source_text is None:
        abs_path, err = _resolve_source_file(workspace, finding.path)
        if err:
            raise ValueError(err)
        source_text = Path(abs_path).read_text(encoding="utf-8", errors="replace")
        source_path_hint = finding.path
    effective_path = source_path_hint or finding.path

    warnings: list[str] = []
    try:
        research = ResearchAgent().run(
            finding, source_text, provider=provider, ollama_cfg=ollama_cfg,
        )
    except RuntimeError as exc:
        if provider != "ollama":
            raise
        warnings.append(
            f"Research (Ollama) failed: {exc} "
            f"Falling back to deterministic research."
        )
        research = ResearchAgent().run(
            finding, source_text, provider="deterministic",
        )

    dev_result, verdict, retry_count = run_developer_critic_loop(
        finding, source_text, effective_path, provider, ollama_cfg,
    )
    return WorkflowResult(
        findings=findings,
        plan=plan,
        research=research,
        dev_result=dev_result,
        verdict=verdict,
        retry_count=retry_count,
        effective_path=effective_path,
        provider_requested=provider,
        warnings=warnings,
    )


def render_workflow(wf: WorkflowResult, decision: str) -> None:
    findings = wf.findings
    plan = wf.plan
    finding = plan.selected
    research = wf.research
    dev_result = wf.dev_result
    verdict = wf.verdict
    retry_count = wf.retry_count
    effective_path = wf.effective_path

    for w in wf.warnings:
        st.warning(w)

    st.header("2 · Findings")
    rows = [
        {
            "Severity": f.severity,
            "Rule ID": f.check_id,
            "File": f.path,
            "Line": f.line,
            "Message": f.message[:100] + ("…" if len(f.message) > 100 else ""),
        }
        for f in findings
    ]
    st.dataframe(rows)

    st.header("3 · Agent Trace")
    st.markdown(f"🗂️ **Planner Agent** — ✅ done · selected `{finding.check_id}`")
    with st.expander("📋 Planner output", expanded=False):
        st.markdown(f"**Selected finding:** `{plan.selected.check_id}` — {plan.reason}")
        st.markdown("**Execution graph:**")
        for step in plan.execution_graph:
            st.markdown(f"- {step}")

    st.markdown(f"🔍 **Research Agent** — ✅ done · {_badge(research.provider)}")

    dev_icon = "✅" if verdict.passed else "❌"
    st.markdown(
        f"🛠️ **Developer Agent** — {_badge(dev_result.provider)} · "
        f"attempt {dev_result.attempt}"
    )
    st.markdown(
        f"🧪 **Critic Agent** — {dev_icon} "
        f"{'passed' if verdict.passed else 'failed'} · retries={retry_count}"
    )

    st.header("4 · Source Context")
    st.caption(
        f"File: `{effective_path}` · "
        f"Showing lines around line {finding.line} · "
        f"Provider: {_badge(research.provider)}"
    )
    st.code(research.snippet, language="python")

    with st.expander("🔍 Research summary", expanded=True):
        st.markdown(research.summary)
        st.markdown(f"**Impact:** {research.impact}")
        st.markdown(f"**Uncertainty:** {research.uncertainty}")
        if finding.cwe:
            st.markdown("**CWE (from scanner):** " + " · ".join(finding.cwe))
        if finding.references:
            ref_links = " · ".join(
                f"[ref]({r})" if r.startswith("http") else r
                for r in finding.references[:3]
            )
            st.markdown(f"**References (from scanner):** {ref_links}")

    st.header("5 · Patch Review")
    st.markdown(f"**Provider:** {_badge(dev_result.provider)}")

    with st.expander("📝 Remediation explanation", expanded=True):
        st.markdown(dev_result.explanation)

    if dev_result.diff:
        st.subheader("Unified diff")
        st.code(dev_result.diff, language="diff")
    else:
        st.warning("No diff was produced.")

    st.subheader("Critic validation")
    col1, col2 = st.columns(2)
    check_items = list(verdict.checks.items())
    mid = (len(check_items) + 1) // 2
    with col1:
        for k, v in check_items[:mid]:
            st.markdown(f"{'✅' if v else '❌'} **{k}**")
    with col2:
        for k, v in check_items[mid:]:
            st.markdown(f"{'✅' if v else '❌'} **{k}**")

    if verdict.errors:
        st.error("**Validation errors:**\n" + "\n".join(f"- {e}" for e in verdict.errors))

    st.markdown(f"**Status:** {verdict.status_explanation}")
    st.markdown(f"**Retry attempts:** {retry_count}")

    with st.expander("🧪 Unit test output", expanded=False):
        st.code(verdict.test_output, language="text")

    st.header("6 · Human Review / Governance Gate")
    st.warning(
        "⚠️ Review the diff and validation results carefully before approving. "
        "Approval only enables downloads; it does NOT modify any source file, "
        "open a pull request, or deploy anything."
    )

    approved = decision == "approved"

    decision_col1, decision_col2 = st.columns(2)
    with decision_col1:
        if st.button("✅ Approve candidate", disabled=not verdict.passed,
                     help="Only enabled when all critic checks pass."):
            st.session_state["decision"] = "approved"
            st.rerun()
    with decision_col2:
        if st.button("❌ Reject candidate"):
            st.session_state["decision"] = "rejected"
            st.rerun()

    st.markdown(f"**Current decision:** `{decision}`")

    audit = build_audit_record(
        finding, plan, research, dev_result, verdict, decision, retry_count
    )
    md_report = build_markdown_report(finding, research, dev_result, verdict, audit)

    st.header("7 · Downloads")
    st.caption(
        "Audit record contains: finding identifiers, agent decisions, patch hash, "
        "critic results, and human decision. It does NOT contain full source code or secrets."
    )
    st.caption(
        "Downloads are enabled only after the candidate is approved. No files in the "
        "original project or archive are modified."
    )

    audit_json = json.dumps(asdict(audit), indent=2)

    dl1, dl2, dl3 = st.columns(3)
    with dl1:
        st.download_button(
            "⬇️ Download .diff / .patch",
            data=dev_result.diff or "(no diff)",
            file_name="candidate.patch",
            mime="text/plain",
            disabled=(not approved),
        )
    with dl2:
        st.download_button(
            "⬇️ Download audit record (JSON)",
            data=audit_json,
            file_name="audit_record.json",
            mime="application/json",
            disabled=(not approved),
        )
    with dl3:
        st.download_button(
            "⬇️ Download summary report (Markdown)",
            data=md_report,
            file_name="summary_report.md",
            mime="text/markdown",
            disabled=(not approved),
        )

    if decision == "pending":
        st.info("Approve or reject the candidate above to enable the downloads.")
    elif approved:
        st.success("Candidate approved. Download the patch, audit record, and summary above.")
    else:
        st.error("Candidate rejected. No artifacts will be downloaded.")


if __name__ == "__main__":
    main()
