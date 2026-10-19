import ast
import io
import json
import os
import sqlite3
import sys
import zipfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))

from app import (
    BUNDLED_REPORT_TEXT,
    BUNDLED_SOURCE_TEXT,
    CriticAgent,
    CriticVerdict,
    DeveloperAgent,
    DeveloperResult,
    Finding,
    PlannerAgent,
    ResearchAgent,
    _bounded_snippet,
    _resolve_source_file,
    _safe_extract_zip,
    _sha256,
    build_audit_record,
    parse_semgrep_report,
    run_developer_critic_loop,
)

_CRITIC_CHILD = os.environ.get("DSO_POC_CRITIC_CHILD") == "1"
_nested_critic_guard = pytest.mark.skipif(
    _CRITIC_CHILD,
    reason="Skipped inside the Critic's child test run to avoid recursion.",
)



VALID_REPORT = json.dumps({
    "version": "1.0.0",
    "results": [
        {
            "check_id": "python.lang.security.audit.formatted-sql-query.formatted-sql-query",
            "path": "vulnerable_app.py",
            "start": {"line": 7, "col": 4},
            "end": {"line": 27, "col": 50},
            "extra": {
                "message": "SQL injection via string concatenation.",
                "severity": "ERROR",
                "metadata": {
                    "cwe": ["CWE-89"],
                    "owasp": ["A03:2021"],
                    "references": ["https://example.com"],
                },
            },
        }
    ],
})

SQL_FINDING = Finding(
    check_id="python.lang.security.audit.formatted-sql-query.formatted-sql-query",
    path="vulnerable_app.py",
    line=7,
    col=4,
    message="SQL injection via string concatenation.",
    severity="ERROR",
    cwe=["CWE-89"],
    owasp=[],
    references=[],
)


def _make_zip(members: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, data in members.items():
            zf.writestr(name, data)
    return buf.getvalue()



class TestParseSemgrepReport:
    def test_valid_report_returns_findings(self):
        findings = parse_semgrep_report(VALID_REPORT)
        assert len(findings) == 1
        f = findings[0]
        assert f.check_id == "python.lang.security.audit.formatted-sql-query.formatted-sql-query"
        assert f.path == "vulnerable_app.py"
        assert f.line == 7
        assert f.severity == "ERROR"
        assert "CWE-89" in f.cwe

    def test_bytes_input_accepted(self):
        findings = parse_semgrep_report(VALID_REPORT.encode())
        assert len(findings) == 1

    def test_invalid_json_raises(self):
        with pytest.raises(ValueError, match="Invalid JSON"):
            parse_semgrep_report("{not valid json")

    def test_missing_results_key_raises(self):
        with pytest.raises(ValueError, match="'results'"):
            parse_semgrep_report(json.dumps({"version": "1.0"}))

    def test_empty_results_raises(self):
        with pytest.raises(ValueError, match="no findings"):
            parse_semgrep_report(json.dumps({"results": []}))

    def test_missing_severity_becomes_unknown(self):
        report = json.dumps({
            "results": [{
                "check_id": "some-rule",
                "path": "foo.py",
                "start": {"line": 1, "col": 0},
                "extra": {"message": "test"},
            }]
        })
        findings = parse_semgrep_report(report)
        assert findings[0].severity == "UNKNOWN"

    def test_unknown_severity_string_normalised(self):
        report = json.dumps({
            "results": [{
                "check_id": "r",
                "path": "f.py",
                "start": {"line": 1},
                "extra": {"message": "m", "severity": "CRITICAL"},
            }]
        })
        findings = parse_semgrep_report(report)
        assert findings[0].severity == "UNKNOWN"

    def test_missing_line_defaults_to_zero(self):
        report = json.dumps({
            "results": [{"check_id": "r", "path": "f.py", "extra": {"message": "m"}}]
        })
        findings = parse_semgrep_report(report)
        assert findings[0].line == 0

    def test_malformed_line_value_defaults_to_zero(self):
        report = json.dumps({
            "results": [{
                "check_id": "r", "path": "f.py",
                "start": {"line": "not-a-number", "col": None},
                "extra": {"message": "m"},
            }]
        })
        findings = parse_semgrep_report(report)
        assert findings[0].line == 0
        assert findings[0].col == 0

    def test_malformed_extra_type_is_tolerated(self):
        report = json.dumps({
            "results": [{"check_id": "r", "path": "f.py", "extra": "not-a-dict"}]
        })
        findings = parse_semgrep_report(report)
        assert findings[0].message == "No message provided."
        assert findings[0].severity == "UNKNOWN"

    def test_non_string_metadata_coerced_to_strings(self):
        report = json.dumps({
            "results": [{
                "check_id": "r", "path": "f.py",
                "extra": {"metadata": {"cwe": [89, None], "references": [123]}},
            }]
        })
        findings = parse_semgrep_report(report)
        assert findings[0].cwe == ["89", "None"]
        assert findings[0].references == ["123"]

    def test_non_dict_results_skipped(self):
        report = json.dumps({"results": ["nonsense", {"check_id": "r", "path": "f.py"}]})
        findings = parse_semgrep_report(report)
        assert len(findings) == 1

    def test_all_invalid_results_raises(self):
        with pytest.raises(ValueError, match="no usable findings"):
            parse_semgrep_report(json.dumps({"results": ["a", "b"]}))

    def test_non_list_results_raises(self):
        with pytest.raises(ValueError):
            parse_semgrep_report(json.dumps({"results": "not a list"}))

    def test_non_dict_top_level_raises(self):
        with pytest.raises(ValueError):
            parse_semgrep_report(json.dumps([1, 2, 3]))


class TestBundledFixtureConsistency:
    def test_report_line_matches_vulnerable_source_line(self):
        findings = parse_semgrep_report(BUNDLED_REPORT_TEXT)
        finding = findings[0]
        assert finding.line == 7
        source_lines = BUNDLED_SOURCE_TEXT.splitlines()
        assert "+ username +" in source_lines[finding.line - 1]



class TestPlannerAgent:
    def test_selects_highest_severity(self):
        findings = [
            Finding("r1", "a.py", 1, 0, "msg", "INFO"),
            Finding("r2", "b.py", 2, 0, "msg", "ERROR"),
            Finding("r3", "c.py", 3, 0, "msg", "WARNING"),
        ]
        plan = PlannerAgent().run(findings)
        assert plan.selected.severity == "ERROR"

    def test_execution_graph_has_five_steps(self):
        plan = PlannerAgent().run([SQL_FINDING])
        assert len(plan.execution_graph) == 5

    def test_empty_findings_raises(self):
        with pytest.raises(ValueError, match="No findings"):
            PlannerAgent().run([])

    def test_unknown_severity_ranked_last(self):
        findings = [
            Finding("r1", "a.py", 1, 0, "msg", "UNKNOWN"),
            Finding("r2", "b.py", 2, 0, "msg", "WARNING"),
        ]
        plan = PlannerAgent().run(findings)
        assert plan.selected.severity == "WARNING"



class TestResearchAgent:
    def test_deterministic_research_returns_result(self):
        r = ResearchAgent().run(SQL_FINDING, BUNDLED_SOURCE_TEXT)
        assert r.provider == "deterministic"
        assert "SQL" in r.summary or "sql" in r.summary.lower()
        assert r.snippet

    def test_snippet_centred_on_reported_line(self):
        r = ResearchAgent().run(SQL_FINDING, BUNDLED_SOURCE_TEXT)
        assert r.snippet_start <= SQL_FINDING.line

    def test_unknown_rule_returns_no_bundled_analysis(self):
        f = Finding("unknown-rule", "foo.py", 5, 0, "some message", "WARNING")
        r = ResearchAgent().run(f, "x = 1\n")
        assert "not in the bundled knowledge base" in r.summary



class TestDeveloperAgentDeterministic:
    def test_patch_produces_diff(self):
        dev = DeveloperAgent()
        result = dev.run(SQL_FINDING, BUNDLED_SOURCE_TEXT, "vulnerable_app.py")
        assert result.diff.strip()
        assert result.provider == "deterministic"

    def test_patch_removes_concatenation(self):
        dev = DeveloperAgent()
        result = dev.run(SQL_FINDING, BUNDLED_SOURCE_TEXT, "vulnerable_app.py")
        assert "+ username +" not in result.patched_code

    def test_diff_headers_are_well_formed(self):
        dev = DeveloperAgent()
        result = dev.run(SQL_FINDING, BUNDLED_SOURCE_TEXT, "vulnerable_app.py")
        lines = result.diff.splitlines()
        assert lines[0] == "--- a/vulnerable_app.py"
        assert lines[1] == "+++ b/vulnerable_app.py"
        assert lines[2].startswith("@@")

    def test_patch_changes_only_the_two_unsafe_lines(self):
        dev = DeveloperAgent()
        result = dev.run(SQL_FINDING, BUNDLED_SOURCE_TEXT, "vulnerable_app.py")
        assert 'query = "SELECT * FROM users WHERE username = ?"\n' in result.patched_code
        assert "+ username +" not in result.patched_code
        assert "cursor.execute(query, (username,))\n" in result.patched_code

    def test_patched_code_is_semantically_parameterized(self, tmp_path):
        db = str(tmp_path / "users.db")
        conn = sqlite3.connect(db)
        conn.execute("CREATE TABLE users (username TEXT)")
        conn.executemany("INSERT INTO users VALUES (?)", [("alice",), ("bob",)])
        conn.commit()
        conn.close()

        result = DeveloperAgent().run(SQL_FINDING, BUNDLED_SOURCE_TEXT, "vulnerable_app.py")
        namespace: dict = {}
        exec(compile(result.patched_code, "patched_vulnerable_app.py", "exec"), namespace)

        get_user = namespace["get_user_by_name"]
        assert len(get_user(db, "alice")) == 1
        assert get_user(db, "' OR '1'='1") == []

    def test_patch_uses_parameterized_query(self):
        dev = DeveloperAgent()
        result = dev.run(SQL_FINDING, BUNDLED_SOURCE_TEXT, "vulnerable_app.py")
        assert "cursor.execute(query, (username,))" in result.patched_code

    def test_patched_code_is_valid_python(self):
        dev = DeveloperAgent()
        result = dev.run(SQL_FINDING, BUNDLED_SOURCE_TEXT, "vulnerable_app.py")
        ast.parse(result.patched_code)

    def test_only_vulnerable_function_patched(self):
        dev = DeveloperAgent()
        result = dev.run(SQL_FINDING, BUNDLED_SOURCE_TEXT, "vulnerable_app.py")
        assert "get_user_by_name_safe" in result.patched_code

    def test_unsupported_rule_returns_unsupported(self):
        f = Finding("unknown-rule", "foo.py", 1, 0, "msg", "ERROR")
        result = DeveloperAgent().run(f, "x = 1\n", "foo.py")
        assert result.provider == "unsupported"
        assert not result.diff



@_nested_critic_guard
class TestCriticAgent:
    def _good_dev_result(self):
        dev = DeveloperAgent()
        return dev.run(SQL_FINDING, BUNDLED_SOURCE_TEXT, "vulnerable_app.py")

    def test_valid_candidate_passes(self):
        dr = self._good_dev_result()
        verdict = CriticAgent().run(dr, "vulnerable_app.py")
        assert verdict.checks["non_empty"]
        assert verdict.checks["bounded_size"]
        assert verdict.checks["allowed_file"]
        assert verdict.checks["ast_parse"]

    def test_empty_diff_fails_non_empty_check(self):
        dr = DeveloperResult(
            finding=SQL_FINDING,
            original_code="x=1",
            patched_code="x=1",
            diff="",
            explanation="nothing",
            provider="deterministic",
            attempt=1,
        )
        verdict = CriticAgent().run(dr, "vulnerable_app.py")
        assert not verdict.checks["non_empty"]
        assert not verdict.passed

    def test_oversized_diff_fails(self):
        big_diff = "+" + "x" * 11_000
        dr = DeveloperResult(
            finding=SQL_FINDING,
            original_code="x=1",
            patched_code="x=1",
            diff=big_diff,
            explanation="big",
            provider="deterministic",
            attempt=1,
        )
        verdict = CriticAgent().run(dr, "vulnerable_app.py")
        assert not verdict.checks["bounded_size"]

    def test_disallowed_file_fails(self):
        dr = self._good_dev_result()
        verdict = CriticAgent().run(dr, "../../etc/passwd")
        assert not verdict.checks["allowed_file"]
        assert not verdict.passed

    def test_syntax_error_in_patch_fails(self):
        dr = DeveloperResult(
            finding=SQL_FINDING,
            original_code="x=1",
            patched_code="def broken(:\n    pass\n",
            diff="+broken",
            explanation="broken",
            provider="deterministic",
            attempt=1,
        )
        verdict = CriticAgent().run(dr, "vulnerable_app.py")
        assert not verdict.checks["ast_parse"]



@_nested_critic_guard
class TestFeedbackLoop:
    def test_good_path_zero_retries(self):
        dr, verdict, retries = run_developer_critic_loop(
            SQL_FINDING, BUNDLED_SOURCE_TEXT, "vulnerable_app.py",
            "deterministic", None,
        )
        assert retries == 0
        assert verdict.passed

    def test_unsupported_rule_retries_once(self):
        f = Finding("unknown-rule", "foo.py", 1, 0, "msg", "ERROR")
        _, verdict, retries = run_developer_critic_loop(
            f, "x = 1\n", "vulnerable_app.py",
            "deterministic", None,
        )
        assert retries == 1
        assert not verdict.passed



class TestSafeExtractZip:
    def test_normal_zip_extracts_ok(self):
        z = _make_zip({"subdir/file.py": b"print('hello')"})
        ws, members = _safe_extract_zip(z)
        assert len(members) == 1
        extracted = Path(ws) / members[0]
        assert extracted.exists()

    def test_path_traversal_rejected(self):
        z = _make_zip({"../evil.py": b"evil"})
        with pytest.raises(ValueError, match="traversal"):
            _safe_extract_zip(z)

    def test_nested_traversal_rejected(self):
        z = _make_zip({"a/b/../../../../evil.py": b"evil"})
        with pytest.raises(ValueError, match="traversal"):
            _safe_extract_zip(z)

    def test_absolute_posix_path_rejected(self):
        z = _make_zip({"/etc/passwd": b"root:x:0:0"})
        with pytest.raises(ValueError, match="Absolute path"):
            _safe_extract_zip(z)

    def test_windows_drive_path_rejected(self):
        z = _make_zip({"C:/Windows/system32/evil.py": b"evil"})
        with pytest.raises(ValueError, match="Absolute path"):
            _safe_extract_zip(z)

    def test_backslash_traversal_rejected(self):
        z = _make_zip({"..\\..\\evil.py": b"evil"})
        with pytest.raises(ValueError, match="traversal"):
            _safe_extract_zip(z)

    def test_symlink_member_rejected(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            info = zipfile.ZipInfo("link.py")
            info.external_attr = (0o120777 << 16)
            zf.writestr(info, "/etc/passwd")
        with pytest.raises(ValueError, match="Symlink"):
            _safe_extract_zip(buf.getvalue())

    def test_invalid_zip_rejected(self):
        with pytest.raises(ValueError, match="valid ZIP"):
            _safe_extract_zip(b"this is definitely not a zip file")

    def test_too_many_members_rejected(self):
        members_dict = {f"file_{i}.py": b"x" for i in range(201)}
        z = _make_zip(members_dict)
        with pytest.raises(ValueError, match="members"):
            _safe_extract_zip(z)

    def test_oversized_archive_rejected(self):
        huge = b"A" * (51 * 1024 * 1024)
        z = _make_zip({"big.bin": huge})
        with pytest.raises(ValueError, match="MB"):
            _safe_extract_zip(z)

    def test_empty_zip_ok(self):
        z = _make_zip({})
        ws, members = _safe_extract_zip(z)
        assert members == []



class TestResolveSourceFile:
    def test_finds_file_inside_workspace(self, tmp_path):
        (tmp_path / "sub").mkdir()
        (tmp_path / "sub" / "vulnerable_app.py").write_text("x = 1\n", encoding="utf-8")
        path, err = _resolve_source_file(str(tmp_path), "sub/vulnerable_app.py")
        assert err is None
        assert path is not None and Path(path).is_file()

    def test_path_outside_workspace_rejected(self, tmp_path):
        path, err = _resolve_source_file(str(tmp_path), "../../etc/passwd")
        assert path is None
        assert err and "escapes the workspace" in err

    def test_missing_file_reports_error(self, tmp_path):
        path, err = _resolve_source_file(str(tmp_path), "does/not/exist.py")
        assert path is None
        assert err and "not found" in err

    def test_no_workspace_no_bundled_reports_error(self):
        path, err = _resolve_source_file(None, "foo.py")
        assert path is None
        assert err is not None



class TestBoundedSnippet:
    def test_snippet_contains_target_line(self):
        lines = [f"line {i}" for i in range(1, 41)]
        snippet, start = _bounded_snippet(lines, 20, context=5)
        assert "line 20" in snippet

    def test_snippet_start_lte_target(self):
        lines = [f"line {i}" for i in range(1, 41)]
        _, start = _bounded_snippet(lines, 15, context=5)
        assert start <= 15

    def test_clamps_to_file_bounds(self):
        lines = ["only line"]
        snippet, start = _bounded_snippet(lines, 1, context=10)
        assert start == 1
        assert "only line" in snippet

    def test_high_line_number_clamped(self):
        lines = [f"l{i}" for i in range(5)]
        snippet, start = _bounded_snippet(lines, 999, context=2)
        assert start >= 1



@_nested_critic_guard
class TestAuditRecord:
    def test_audit_record_contains_expected_keys(self):
        dev = DeveloperAgent()
        dr = dev.run(SQL_FINDING, BUNDLED_SOURCE_TEXT, "vulnerable_app.py")
        planner = PlannerAgent()
        plan = planner.run([SQL_FINDING])
        research = ResearchAgent().run(SQL_FINDING, BUNDLED_SOURCE_TEXT)
        verdict = CriticAgent().run(dr, "vulnerable_app.py")

        record = build_audit_record(
            SQL_FINDING, plan, research, dr, verdict, "approved", 0
        )
        assert record.finding_id == SQL_FINDING.check_id
        assert record.human_decision == "approved"
        assert record.patch_sha256 == _sha256(dr.diff)
        assert isinstance(record.critic_checks, dict)

    def test_no_diff_audit_hash_is_placeholder(self):
        f = Finding("unknown", "foo.py", 1, 0, "m", "ERROR")
        dr = DeveloperResult(f, "x=1", "x=1", "", "no patch", "unsupported", 1)
        plan = PlannerAgent().run([f])
        research = ResearchAgent().run(f, "x=1\n")
        verdict = CriticAgent().run(dr, "vulnerable_app.py")

        record = build_audit_record(f, plan, research, dr, verdict, "rejected", 1)
        assert record.patch_sha256 == "no-diff"

    def test_unsupported_developer_normalises_provider_mode(self):
        f = Finding("unknown", "foo.py", 1, 0, "m", "ERROR")
        dr = DeveloperResult(f, "x=1", "x=1", "", "no patch", "unsupported", 1)
        plan = PlannerAgent().run([f])
        research = ResearchAgent().run(f, "x=1\n")
        verdict = CriticVerdict(
            passed=False, checks={"non_empty": False}, errors=["empty"],
            status_explanation="failed", test_output="",
        )
        record = build_audit_record(f, plan, research, dr, verdict, "rejected", 1)
        assert record.provider_mode == "deterministic"



def test_sha256_deterministic():
    assert _sha256("hello") == _sha256("hello")
    assert _sha256("hello") != _sha256("world")
