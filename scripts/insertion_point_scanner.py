"""Static analysis scanner for guardrail stub insertion points.

Scans Python source files for data-transfer patterns (LLM calls, DB reads,
outbound HTTP calls, file operations, MCP tool calls) and returns candidate
locations where a guardrail stub HTTP call should be added.

Used by the insert_guardrail_stubs MCP tool.
"""
from __future__ import annotations

import hashlib
import logging
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

_logger = logging.getLogger(__name__)


def _compute_companion_hops(file_path: str, project_root: "str | None") -> int:
    """Number of directory levels `file_path` sits below `project_root` — used
    to compute the `../` prefix reaching <project_root>/lineaje/gr_client.py
    from wherever a stub actually lands. Returns 0 when project_root is not
    given, or file_path isn't under it (best-effort: assume root)."""
    if not project_root:
        return 0
    try:
        rel = Path(file_path).resolve().relative_to(Path(project_root).resolve())
    except ValueError:
        return 0
    return len(rel.parts) - 1


def _module_prefix_insert_index(lines: list[str]) -> int:
    """0-indexed position to insert a new top-level block at — after any
    shebang/encoding comment AND after a leading module docstring, if present.

    Only the very first statement in a Python file is recognized as the
    module's `__doc__` — inserting code above an existing docstring silently
    demotes it to a dead string-literal expression statement (confirmed live:
    a real customer-shaped file with a module docstring lost it entirely when
    the import-hint block was inserted at line 0 without this check). Falls
    back to shebang/encoding-only detection if the source doesn't parse as
    Python (e.g. a JS/TS file) — never raises."""
    idx = 0
    for i, ln in enumerate(lines[:5]):
        if ln.startswith("#!") or ln.strip().startswith("# -*-"):
            idx = i + 1
        if ln.startswith("package "):
            idx = max(idx, i + 1)
    try:
        tree = _ast.parse("".join(lines))
        first = tree.body[0] if tree.body else None
        if (
            isinstance(first, _ast.Expr)
            and isinstance(getattr(first, "value", None), _ast.Constant)
            and isinstance(first.value.value, str)
        ):
            idx = max(idx, first.end_lineno)
    except SyntaxError:
        pass
    return idx


def safe_prefix_insert_index(lines: list[str]) -> int:
    """Like _module_prefix_insert_index(), but also walks past any leading
    `from __future__ import` line(s) — those must be the first statement(s)
    in a Python file (inserting anything above one is a real SyntaxError),
    and _module_prefix_insert_index() alone only knows about shebang/encoding
    comments and a module docstring, not future imports.

    Independent Code Review finding P1-1 (2026-08): a naive "insert at line 0
    unless shebang" placement can land a loader/import block above a module
    docstring (silently demoting it to a dead string-literal statement) or
    above a `from __future__ import` line. This is the shared fix for that —
    every write path that prepends a top-level block should call this
    instead of hand-rolling the same walk, so a future fix here applies
    everywhere at once instead of drifting between duplicated copies (see
    docs/CODE_REVIEW_ADDENDUM_2026-08-10.md, "converge the two write paths").
    """
    insert_at = _module_prefix_insert_index(lines)
    while insert_at < len(lines) and lines[insert_at].lstrip().startswith("from __future__ import"):
        insert_at += 1
    return insert_at


def validate_python_source(new_content: str, abs_path: str) -> "str | None":
    """Whole-file compile() check for a stub-insertion candidate write.
    Returns None if the resulting file is still valid, or the SyntaxError
    message otherwise.

    Deliberately compile(), not ast.parse() — ast.parse() does NOT enforce
    future-import placement (confirmed: it silently accepts a `from
    __future__ import` that isn't the first statement), so it would miss
    exactly the defect class safe_prefix_insert_index() exists to prevent.
    compile() enforces the real interpreter rule. Shared by every write path
    that mutates Python source (see safe_prefix_insert_index()'s docstring)
    so a corrupting candidate — e.g. the known multi-line-call insert_after
    bug, where a stub lands mid-statement — is rejected everywhere, not just
    in whichever path happened to add the check first.
    """
    try:
        compile(new_content, abs_path, "exec")
        return None
    except SyntaxError as exc:
        return str(exc)


@dataclass
class InsertionCandidate:
    file: str
    line: int                   # 1-based
    insertion_point: str        # "agent_to_llm", "db_read", etc.
    pattern_matched: str        # the regex pattern that fired
    context_line: str           # the actual source line (stripped)
    suggested_variable: str     # best-guess variable to wrap
    description: str            # human-readable explanation
    proposed_stub: str          # the stub call line to insert
    safe_to_insert: bool = True          # False when variable fell back to "data" (extraction failed)
    skip_reason: str = ""               # human-readable reason when safe_to_insert is False
    policy_ids: list[str] = field(default_factory=list)  # policies that apply to this insertion point
    policy_reasons: list[dict] = field(default_factory=list)  # [{policy_id, name}, ...] — structured version of policy_ids
    insert_after: bool = False  # True → stub goes AFTER the matched line (lhs/result patterns)
                                # False → stub goes BEFORE the matched line (arg1/input patterns)
    variable_to_use_in_call: str = ""
    # Always empty. Historically set to "_gr_{variable}" for arg1/input patterns, requiring
    # the coding agent to separately rewrite the protected call to use the scoped copy —
    # a second edit that could be skipped, silently defeating masking. The stub now
    # reassigns the original variable in place (both for input and output patterns), so the
    # very next line always sees the checked/masked value with no follow-up edit required.
    # Kept in the schema for compatibility with existing consumers of stub_insertions.
    companion_hops: int = 0  # directory levels below project root — see _compute_companion_hops()
    # How certain the classifier itself is about this being a real AI-relevant
    # boundary, independent of whether any violation evidence exists for it:
    #   "high"   — unambiguous, SDK-qualified pattern (.chat.completions.create, .fetchall, ...)
    #   "medium" — generic method name gated by a receiver-name hint (.invoke + "llm" in receiver)
    #   "low"    — framework-agnostic structural signal only (await + generic HTTP verb,
    #              any receiver) — see _ast_classify_generic_network_call
    # Only the AST path (_scan_file_ast) currently sets this meaningfully; every other
    # path (regex, tree-sitter, annotations) defaults to "medium" — unscored, not
    # asserted as low-confidence, just not yet computed for those paths.
    confidence: str = "medium"
    # ── Site identity (Phase 6a — design-doc VI.2 Instrumentation IR) ────────
    # Filled in post-hoc by scan_file()'s wrapper, not by any of the individual
    # scan paths above — see _derive_site_id/_canonical_phase_and_boundary.
    # Left at their defaults ("" / {}) if a caller constructs InsertionCandidate
    # directly rather than through scan_file()/scan_project().
    site_id: str = ""             # "site:sha256:<hex>" — stable per (file, symbol, insertion_point, pattern)
    boundary: dict = field(default_factory=dict)   # best-effort {"source": ..., "sink": ...}
    phase: str = ""                # canonical VI.2 phase, derived from insertion_point
    # Representative payload for the scan-time "enforcement proof" (Part VI.5,
    # guardrail_stub_insertion.py's _verify_enforcement) to send to /enforce —
    # NOT the same thing as context_line. context_line is the single source
    # line at the insertion point (often just `return html`), and even the
    # full multi-line source window around it is still just SOURCE CODE
    # (e.g. `record['ssn']`), never an actual PII-shaped VALUE — gr_service's
    # PII routine detects PII by value pattern (Presidio NER + regex over
    # real SSN/card/email/phone shapes), so probing with source text can
    # never trip it regardless of what the runtime value would have been.
    # _scan_pii_ui_exposure populates this with a synthetic, value-shaped
    # canary instead (see _synthetic_pii_probe) so the proof actually
    # exercises the policy. Left "" for any path with no such canary
    # available (annotation/AST/regex scans), in which case
    # _verify_enforcement falls back to context_line as before.
    sample_text: str = ""
    # 1-based end line of the matched statement (node.end_lineno). For
    # insert_after=True on a multi-line call (`response = await client.post(`
    # spanning 15 lines), the stub must land AFTER this line — not after
    # `line` (the opening). 0 means "unknown, treat as `line`".
    stmt_end_line: int = 0
    # When the data payload is an inline expression (messages=[{...}], not a
    # Name), we hoist it to `suggested_variable` immediately before the call
    # and rewrite the original expression to that name. Empty = no hoist.
    hoist_source: str = ""
    hoist_start_line: int = 0   # 1-based, expression span in the original file
    hoist_start_col: int = 0    # 0-based
    hoist_end_line: int = 0
    hoist_end_col: int = 0


# Insertion points where the stub must go AFTER the matched line because the
# variable being scanned is the RESULT of that line (not the input to it).
# agent_to_llm / mcp_call / data_outbound / risky_operation → BEFORE (scanning what goes out)
# llm_to_agent / db_read / api_call / file_upload → AFTER (scanning what comes back)
_LHS_INSERTION_POINTS = frozenset({"llm_to_agent", "db_read", "api_call", "file_upload"})

# ── Annotation-based scanner constants ───────────────────────────────────────
# Developer-annotated guardrail boundaries take highest priority over pattern
# matches.  Any supported language can carry these comments; no grammar needed.
#
# Annotation format (place on the line immediately before the target, or inline):
#   // @gr:insertion_point=<ip> [variable=<var>] [insert_after=true|false]
#    # @gr:insertion_point=<ip> [variable=<var>] [insert_after=true|false]
#
# Fields:
#   insertion_point= (required) — must match a known insertion point name
#   variable=        (optional) — variable to wrap; extracted from target line if omitted
#   insert_after=    (optional) — overrides the default (true for lhs points, false otherwise)
#
# Dynamic behaviour: annotations survive framework refactors because they track
# the developer's INTENT ("this is where LLM output enters agent logic"), not a
# specific call pattern.  The scanner still generates the full stub automatically
# from the annotation + surrounding code — no manual stub writing needed.

_GR_ANNOTATION_RE = re.compile(
    r"@gr:insertion_point=([A-Za-z_][A-Za-z0-9_]*)"
    r"(?:\s+variable=([A-Za-z_][A-Za-z0-9_]*))?"
    r"(?:\s+insert_after=(true|false))?",
    re.IGNORECASE,
)

# A line is "comment-only" if its only non-whitespace content is a comment marker.
_COMMENT_ONLY_RE = re.compile(r"^\s*(?://|#|/\*|\*)")

# All known insertion point names — used for validation warning; unknown names
# are still processed so new points can be added without a scanner update.
_KNOWN_INSERTION_POINTS = frozenset({
    "agent_to_llm", "llm_to_agent", "agent_to_agent",
    "db_read", "api_call", "file_upload",
    "mcp_call", "data_outbound", "risky_operation",
    "tool_call", "tool_result",
    "agent_to_ui", "ui_to_agent", "llm_to_ui", "ui_to_llm",
    # "llm_to_user"/"user_to_llm" (not "*_ui") is the pair actually used
    # throughout _POLICY_INSERTION_POINTS (e.g. AI_DAT_SEC_012 lists
    # "llm_to_user", never "agent_to_ui") — previously missing from this
    # set entirely despite being the names every policy mapping uses.
    "llm_to_user", "user_to_llm",
    # Finer-grained "who produced/received this" edges for the PII-in-UI
    # detector (_scan_pii_ui_exposure / _guess_interaction_type) — same
    # user_interface sink as llm_to_user/agent_to_ui, but distinguishing an
    # agent/LLM-authored reply (agent_to_user) from a plain data-fetch-and-
    # render function with no agent/LLM in the loop at all (tool_to_user),
    # plus their reverse-direction counterparts for symmetry.
    "agent_to_user", "user_to_agent", "tool_to_user", "user_to_tool",
    # Rendered HTML document/string reaching the UI — source=html in
    # candidate_when (AI_DAT_SEC_012), distinct from a non-HTML tool JSON
    # body (tool_to_user) and from an agent-authored chat reply
    # (agent_to_user). See _guess_interaction_type.
    "html_to_user",
    # Schema-v2 canonical phase name used as guardrail.insertion_point
    # (AI_DAT_SEC_012). Same user_interface hop as html_to_user / *_to_user;
    # scan_violation_targeted refines it to the concrete edge.
    "data_egress",
    # Schema-v2 phase + insertion_point for AI_DAT_SEC_010 ("Do not log PII").
    # Distinct from data_egress: sink=log, not user_interface.
    "log_emit",
})


# ── Pattern registry ──────────────────────────────────────────────────────────
# Each entry: (insertion_point, regex, variable_hint, description)
# variable_hint is used to guess the variable name from the matched line.
# Hint "lhs"  → extract left-hand side of the assignment (the result variable)
# Hint "arg1" → extract first positional argument (the data being sent)

_PATTERNS: list[tuple[str, str, str, str]] = [
    # ── agent_to_llm ─────────────────────────────────────────────────────────
    (
        "agent_to_llm",
        r"\.chat\.completions\.create\s*\(",
        "arg1",
        "OpenAI / compatible chat completion — scan messages before sending to LLM",
    ),
    (
        "agent_to_llm",
        r"\.messages\.create\s*\(",
        "arg1",
        "Anthropic messages.create — scan messages before sending to LLM",
    ),
    (
        "agent_to_llm",
        r"\bllm\.invoke\s*\(",
        "arg1",
        "LangChain LLM invoke — scan input before sending to LLM",
    ),
    (
        "agent_to_llm",
        r"\bllm\.predict\s*\(",
        "arg1",
        "LangChain LLM predict — scan input before sending to LLM",
    ),
    (
        "agent_to_llm",
        r"\bchain\.run\s*\(",
        "arg1",
        "LangChain chain.run — scan input before sending to LLM chain",
    ),
    (
        "agent_to_llm",
        r"\bchain\.invoke\s*\(",
        "arg1",
        "LangChain chain.invoke — scan input before sending to LLM chain",
    ),
    (
        "agent_to_llm",
        r"\bmodel\.generate\s*\(",
        "arg1",
        "Model generate call — scan prompt before sending to model",
    ),
    (
        "agent_to_llm",
        r"\bgenerate_content\s*\(",
        "arg1",
        "Gemini generate_content — scan content before sending to LLM",
    ),
    (
        "agent_to_llm",
        r"\.complete\s*\(",
        "arg1",
        "LLM .complete() call — scan prompt before sending to model",
    ),
    (
        "agent_to_llm",
        r"\.completions\.create\s*\(",
        "arg1",
        "OpenAI completions.create (non-chat) — scan prompt before sending to LLM",
    ),
    # ── agent_to_llm — Java ───────────────────────────────────────────────────
    (
        "agent_to_llm",
        r"openAiClient\.chat\s*\(\)",
        "arg1",
        "OpenAI Java SDK chat() — scan messages before sending to LLM",
    ),
    (
        "agent_to_llm",
        r"ChatCompletionRequest\.builder\s*\(\)",
        "lhs",
        "OpenAI Java ChatCompletionRequest — scan request before sending to LLM",
    ),
    (
        "agent_to_llm",
        r"anthropicClient\.messages\s*\(\)",
        "arg1",
        "Anthropic Java SDK messages() — scan messages before sending to LLM",
    ),
    # ── agent_to_llm — Go ────────────────────────────────────────────────────
    (
        "agent_to_llm",
        r"\.Chat\.Completions\.New\s*\(",
        "arg1",
        "OpenAI Go SDK Chat.Completions.New — scan params before sending to LLM",
    ),
    (
        "agent_to_llm",
        r"\.Messages\.New\s*\(",
        "arg1",
        "Anthropic Go SDK Messages.New — scan params before sending to LLM",
    ),
    (
        "db_read",
        r"\bdb\.Query\s*\(",
        "lhs",
        "Go database/sql Query — scan rows for sensitive data before use",
    ),
    (
        "db_read",
        r"\bdb\.QueryRow\s*\(",
        "lhs",
        "Go database/sql QueryRow — scan row for sensitive data before use",
    ),
    # ── agent_to_llm — generic .chat() wrappers ──────────────────────────────
    (
        "agent_to_llm",
        r"await\s+\w*\.chat\s*\(",
        "arg1",
        "LLM client .chat() call — scan messages before sending to LLM",
    ),
    (
        "agent_to_llm",
        r"\bllm_client\.chat\s*\(",
        "arg1",
        "LLM client .chat() call — scan messages before sending to LLM",
    ),
    (
        "agent_to_llm",
        r"\bclient\.chat\s*\(",
        "arg1",
        "LLM client .chat() call — scan messages before sending to LLM",
    ),
    # ── llm_to_agent ─────────────────────────────────────────────────────────
    (
        "llm_to_agent",
        r"\.choices\s*\[\s*0\s*\]\s*\.\s*message",
        "lhs",
        "OpenAI response extraction — scan LLM output before using in agent logic",
    ),
    (
        "llm_to_agent",
        r"response\.content\b",
        "lhs",
        "Anthropic / LangChain response.content — scan LLM output before use",
    ),
    # ── db_read ───────────────────────────────────────────────────────────────
    (
        "db_read",
        r"\bcursor\.fetchall\s*\(",
        "lhs",
        "DB fetchall — scan rows for sensitive data before passing to agent",
    ),
    (
        "db_read",
        r"\bcursor\.fetchone\s*\(",
        "lhs",
        "DB fetchone — scan row for sensitive data before passing to agent",
    ),
    (
        "db_read",
        r"\.query\s*\(.*\)\s*\.all\s*\(",
        "lhs",
        "SQLAlchemy query.all() — scan ORM results for sensitive data",
    ),
    (
        "db_read",
        r"\.query\s*\(.*\)\s*\.first\s*\(",
        "lhs",
        "SQLAlchemy query.first() — scan ORM result for sensitive data",
    ),
    (
        "db_read",
        r"session\.execute\s*\(",
        "lhs",
        "SQLAlchemy session.execute — scan query result for sensitive data",
    ),
    (
        "db_read",
        r"collection\.find\s*\(",
        "lhs",
        "MongoDB collection.find — scan documents for sensitive data",
    ),
    (
        "db_read",
        r"collection\.find_one\s*\(",
        "lhs",
        "MongoDB find_one — scan document for sensitive data",
    ),
    (
        "db_read",
        r"\bdb\.execute\s*\(",
        "lhs",
        "DB execute — scan query result for sensitive data",
    ),
    # ── db_read — Java ────────────────────────────────────────────────────────
    (
        "db_read",
        r"\brs\.next\s*\(\)",
        "lhs",
        "JDBC ResultSet.next() — scan row before passing to agent logic",
    ),
    (
        "db_read",
        r"stmt\.executeQuery\s*\(",
        "lhs",
        "JDBC executeQuery — scan result set for sensitive data",
    ),
    (
        "db_read",
        r"entityManager\.createQuery\s*\(",
        "lhs",
        "JPA createQuery — scan results for sensitive data before use",
    ),
    (
        "db_read",
        r"\.findAll\s*\(\)",
        "lhs",
        "Spring Data findAll() — scan repository results for sensitive data",
    ),
    # ── api_call ──────────────────────────────────────────────────────────────
    (
        "api_call",
        r"\brequests\.get\s*\(",
        "lhs",
        "requests.get — scan inbound API response for sensitive data",
    ),
    (
        "api_call",
        r"\brequests\.post\s*\(",
        "lhs",
        "requests.post — scan inbound API response / check outbound payload",
    ),
    (
        "api_call",
        r"\bhttpx\.get\s*\(",
        "lhs",
        "httpx.get — scan API response for sensitive data",
    ),
    (
        "api_call",
        r"\bhttpx\.post\s*\(",
        "lhs",
        "httpx.post — scan outbound body and inbound response",
    ),
    (
        "api_call",
        r"await.*\.get\s*\(",
        "lhs",
        "Async HTTP GET — scan API response for sensitive data",
    ),
    (
        "api_call",
        r"await.*\.post\s*\(",
        "lhs",
        "Async HTTP POST — scan outbound payload and response",
    ),
    # ── file_upload ───────────────────────────────────────────────────────────
    (
        "file_upload",
        r"\bopen\s*\([^)]+['\"](?:rb|r)\b",
        "lhs",
        "File read in binary/text mode — scan file content before processing",
    ),
    (
        "file_upload",
        r"s3\.upload_file\s*\(",
        "arg1",
        "S3 upload — scan file content before upload to object storage",
    ),
    (
        "file_upload",
        r"s3\.put_object\s*\(",
        "arg1",
        "S3 put_object — scan object body before upload",
    ),
    # ── mcp_call ──────────────────────────────────────────────────────────────
    (
        "mcp_call",
        r"\.call_tool\s*\(",
        "arg1",
        "MCP call_tool — scan tool arguments before dispatching to MCP server",
    ),
    (
        "mcp_call",
        r"mcp\.call\s*\(",
        "arg1",
        "MCP tool call — scan arguments before dispatching",
    ),
    # ── data_outbound ─────────────────────────────────────────────────────────
    (
        "data_outbound",
        r"json\.dumps\s*\(",
        "arg1",
        "JSON serialisation — scan payload before serialising for transmission",
    ),
    (
        "data_outbound",
        r"\.send\s*\([^)]*data\b",
        "arg1",
        "Socket/stream send — scan data before outbound transmission",
    ),
    # ── security_decision — Python ────────────────────────────────────────────
    (
        "security_decision",
        r"\bauthorize\s*\(",
        "arg1",
        "authorize() call — scan decision context before acting on authorization result",
    ),
    (
        "security_decision",
        r"\bcheck_permission\s*\(",
        "arg1",
        "check_permission() — scan input before making access-control decision",
    ),
    (
        "security_decision",
        r"\bis_allowed\s*\(",
        "arg1",
        "is_allowed() — scan context before evaluating allow/deny decision",
    ),
    (
        "security_decision",
        r"\bhas_permission\s*\(",
        "arg1",
        "has_permission() — scan context before permission check",
    ),
    (
        "security_decision",
        r"\bverify_access\s*\(",
        "arg1",
        "verify_access() — scan request before access verification",
    ),
    # ── security_decision — Java ──────────────────────────────────────────────
    (
        "security_decision",
        r"@PreAuthorize\b",
        "arg1",
        "Spring @PreAuthorize — scan method context at security decision boundary",
    ),
    (
        "security_decision",
        r"SecurityContextHolder\.getContext\s*\(\)",
        "lhs",
        "Spring Security context — scan before reading authentication from context",
    ),
    # ── risky_operation — Python ──────────────────────────────────────────────
    (
        "risky_operation",
        r"\bos\.(?:remove|unlink|rmdir|system)\s*\(",
        "arg1",
        "os filesystem/system call — scan path/command before destructive operation",
    ),
    (
        "risky_operation",
        r"\bsubprocess\.(?:run|call|Popen|check_output)\s*\(",
        "arg1",
        "subprocess call — scan command before executing OS-level operation",
    ),
    (
        "risky_operation",
        r"\bshutil\.rmtree\s*\(",
        "arg1",
        "shutil.rmtree — scan path before recursive directory deletion",
    ),
    (
        "risky_operation",
        r"\bexec\s*\(",
        "arg1",
        "exec() call — scan code string before dynamic execution",
    ),
    (
        "risky_operation",
        r"\beval\s*\(",
        "arg1",
        "eval() call — scan expression before dynamic evaluation",
    ),
    # ── risky_operation — Java ────────────────────────────────────────────────
    (
        "risky_operation",
        r"Runtime\.getRuntime\s*\(\)\s*\.exec\s*\(",
        "arg1",
        "Runtime.exec() — scan command before OS-level execution (Java)",
    ),
    (
        "risky_operation",
        r"Files\.delete\s*\(",
        "arg1",
        "Files.delete() — scan path before file deletion (Java NIO)",
    ),
    (
        "risky_operation",
        r"ProcessBuilder\s*\(",
        "arg1",
        "ProcessBuilder — scan command list before subprocess launch (Java)",
    ),
    # ── llm_to_user — Python web/UI frameworks ───────────────────────────────
    # sink=user_interface: the actual boundary AI_DAT_SEC_012 ("Mask PII on
    # user interfaces") targets. These are call-shaped, unlike the
    # PII-in-a-returned-string shape handled separately by
    # _scan_pii_ui_exposure (which also uses "llm_to_user").
    (
        "llm_to_user",
        r"\bjsonify\s*\(",
        "arg1",
        "Flask jsonify — scan response body before sending to the UI",
    ),
    (
        "llm_to_user",
        r"\bmake_response\s*\(",
        "arg1",
        "Flask make_response — scan response body before sending to the UI",
    ),
    (
        "llm_to_user",
        r"\brender_template\w*\s*\(",
        "arg1",
        "Flask render_template(_string) — scan template context before rendering to the UI",
    ),
    (
        "llm_to_user",
        r"\bHttpResponse\s*\(",
        "arg1",
        "Django HttpResponse — scan response body before sending to the UI",
    ),
    (
        "llm_to_user",
        r"\bJsonResponse\s*\(",
        "arg1",
        "Django JsonResponse — scan response body before sending to the UI",
    ),
    (
        "llm_to_user",
        r"\bJSONResponse\s*\(",
        "arg1",
        "FastAPI/Starlette JSONResponse — scan response body before sending to the UI",
    ),
    (
        "llm_to_user",
        r"\w*[Tt]emplates\.TemplateResponse\s*\(",
        "arg1",
        "FastAPI Jinja2Templates.TemplateResponse — scan template context before rendering to the UI",
    ),
    (
        "llm_to_user",
        r"\bst\.(?:write|markdown|text)\s*\(",
        "arg1",
        "Streamlit write/markdown/text — scan content before rendering to the UI",
    ),
    # ── llm_to_user — JS/TS (Node/Express/Next) ──────────────────────────────
    (
        "llm_to_user",
        r"\bres\.send\s*\(",
        "arg1",
        "Express/Node res.send — scan response body before sending to the UI",
    ),
    (
        "llm_to_user",
        r"\bres\.json\s*\(",
        "arg1",
        "Express/Node res.json — scan response body before sending to the UI",
    ),
    (
        "llm_to_user",
        r"\bres\.render\s*\(",
        "arg1",
        "Express res.render — scan template context before rendering to the UI",
    ),
    (
        "llm_to_user",
        r"\bresponse\.write\s*\(",
        "arg1",
        "Node http.ServerResponse.write — scan response body before sending to the UI",
    ),
    (
        "llm_to_user",
        r"\bNextResponse\.json\s*\(",
        "arg1",
        "Next.js NextResponse.json — scan response body before sending to the UI",
    ),
    # ── llm_to_user — Java (Spring/Servlet) ──────────────────────────────────
    (
        "llm_to_user",
        r"\bResponseEntity\.\w+\s*\(",
        "arg1",
        "Spring ResponseEntity — scan response body before sending to the UI",
    ),
    (
        "llm_to_user",
        r"\.getWriter\(\)\.(?:write|print)\w*\s*\(",
        "arg1",
        "Servlet response writer — scan response body before sending to the UI",
    ),
    # ── llm_to_user — Go (net/http, gin) ──────────────────────────────────────
    (
        "llm_to_user",
        r"\bw\.Write\s*\(",
        "arg1",
        "net/http ResponseWriter.Write — scan response body before sending to the UI",
    ),
    (
        "llm_to_user",
        r"\bfmt\.Fprintf?\s*\(\s*w\b",
        "arg1",
        "fmt.Fprint(f) to a ResponseWriter — scan response body before sending to the UI",
    ),
    (
        "llm_to_user",
        r"json\.NewEncoder\s*\(\s*w\s*\)\.Encode\s*\(",
        "arg1",
        "encoding/json Encoder to a ResponseWriter — scan response body before sending to the UI",
    ),
    (
        "llm_to_user",
        r"\bc\.JSON\s*\(",
        "arg1",
        "Gin c.JSON — scan response body before sending to the UI",
    ),
    (
        "llm_to_user",
        r"\bc\.String\s*\(",
        "arg1",
        "Gin c.String — scan response body before sending to the UI",
    ),
    # ── data_egress — bare-name function return ──────────────────────────────
    # Insert BEFORE `return <data>` so any routine can mask/block the payload
    # that is about to leave the function. Trivial sentinels (None/True/self)
    # are rejected in _extract_variable, not here — the regex only needs to
    # see the `return <identifier>` shape. Delegating `return foo()` /
    # `return await ...` stay excluded (they are not a bare name).
    (
        "data_egress",
        r"^\s*return\s+[A-Za-z_][A-Za-z0-9_]*\s*;?\s*$",
        "return",
        "Function return of a data variable — scan payload before returning",
    ),
    # ── log_emit — log / print / console sinks (AI_DAT_SEC_010) ─────────────
    # Keep in sync with _LOGGING_SINK_RE below. UI-response writers that
    # happen to share a Print* name (fmt.Fprintf(w, ...)) are dropped in
    # the regex loop when _UI_SINK_CALL_RE also matches the line.
    (
        "log_emit",
        r"\bprint\s*\("
        r"|\bconsole\.(?:log|debug|info|warn|error|trace)\s*\("
        r"|\blogger\.\w+\s*\("
        r"|\blogging\.\w+\s*\("
        r"|\blog\.\w+\s*\("
        r"|\bSystem\.(?:out|err)\.print\w*"
        r"|\bfmt\.Print(?:ln|f)?\s*\(",
        "arg1",
        "Log/print sink — scan payload before writing to logs",
    ),
]

_COMPILED: list[tuple[str, re.Pattern, str, str]] = [
    (ip, re.compile(pat), hint, desc)
    for ip, pat, hint, desc in _PATTERNS
]

# Real false-positive found scanning a LangGraph project: the broad "await
# ...get(/post(" api_call patterns above have no receiver-hint gate (unlike
# the AST classifier's DB/AI receiver-hint checks), so `while s := await
# output_queue.get():` — an asyncio.Queue read, extremely common in
# LangGraph's streaming/queue-relay code — was misclassified as an async
# HTTP GET. These two specific patterns can't tell an HTTP client receiver
# (session, client, resp, api, ...) from a non-HTTP one just from a raw-line
# regex, so instead of guessing an allow-list (which would create false
# NEGATIVES for legitimately-named clients), the receiver is checked against
# a denylist of known non-HTTP async primitives right after the broad match.
_ASYNC_HTTP_PATTERNS_NEEDING_RECEIVER_GATE = frozenset({
    r"await.*\.get\s*\(",
    r"await.*\.post\s*\(",
})
_ASYNC_NON_HTTP_RECEIVER_HINTS = frozenset({
    "queue", "cache", "redis", "lock", "semaphore", "pool", "store",
})
_ASYNC_RECEIVER_RE = re.compile(r"await\s+([\w.\[\]'\"]+)\.(?:get|post)\s*\(")


def _async_call_receiver(raw_line: str) -> str:
    """Extract the last dotted segment of the receiver immediately before
    .get(/.post( in an `await <receiver>.get(/post(...)` line — e.g.
    "output_queue" from "await output_queue.get()", or "_session" from
    "await self._session.get(url)". Returns "" if the shape doesn't match
    (caller then treats the match as a real hit — unchanged behavior)."""
    m = _ASYNC_RECEIVER_RE.search(raw_line)
    if not m:
        return ""
    return m.group(1).rsplit(".", 1)[-1]


def _is_non_http_async_receiver(receiver: str) -> bool:
    r = receiver.lower()
    return any(h in r for h in _ASYNC_NON_HTTP_RECEIVER_HINTS)

# File extensions we'll scan
_SCANNABLE_EXTENSIONS = {".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".go"}

# Max file size to scan (bytes) — skip giant generated files
_MAX_FILE_BYTES = 512_000


# Names that are a control-flow sentinel, not a data payload. A stub on
# `return None` / `return self` would wrap nothing a policy can inspect.
_TRIVIAL_RETURN_NAMES = frozenset({
    "None", "True", "False", "self", "cls",
    "null", "undefined", "nil", "this", "true", "false",
})

# Bare-name data return: `return html` / `return agentReply;` — used both
# to find data_egress sites and to let those lines through the regex-path
# skip that otherwise ignores every `return `-prefixed wrapper.
_DATA_RETURN_RE = re.compile(r"^\s*return\s+([A-Za-z_][A-Za-z0-9_]*)\s*;?\s*$")


def _is_data_return_line(stripped_line: str) -> bool:
    """True for `return <identifier>` where the name is a real payload."""
    m = _DATA_RETURN_RE.match(stripped_line)
    return bool(m and m.group(1) not in _TRIVIAL_RETURN_NAMES)


def _looks_like_complete_statement(stripped_line: str) -> bool:
    """True when stripped_line is plausibly a complete, standalone statement
    (balanced brackets, no trailing continuation marker) rather than a
    fragment nested inside an unclosed multi-line call from an earlier line.

    Coarse on purpose — this only gates whether the "lhs" backward-lookback
    in _extract_variable is even worth trying, not a real parser. A line
    with more closing than opening brackets, or one ending in a trailing
    comma/open-bracket/backslash, is treated as "not complete" (a
    continuation fragment) so the backward scan still runs for genuine
    multi-line assignments like `result = fn(\\n    arg,\\n)`.
    """
    if stripped_line.endswith((",", "(", "[", "{", "\\")):
        return False
    opens = stripped_line.count("(") + stripped_line.count("[") + stripped_line.count("{")
    closes = stripped_line.count(")") + stripped_line.count("]") + stripped_line.count("}")
    return opens == closes


def _extract_variable(
    line: str,
    hint: str,
    context_lines: list[str] | None = None,
    following_lines: list[str] | None = None,
) -> str:
    """Best-effort extraction of the variable name to wrap.

    Falls back to scanning surrounding lines when the matched line alone does
    not yield a variable — handles multiline calls and list-comprehension bodies.
    """
    stripped = line.strip()

    if hint == "lhs":
        # `result = ...` → "result"
        m = re.match(r"^([a-zA-Z_][a-zA-Z0-9_]*(?:\s*,\s*[a-zA-Z_][a-zA-Z0-9_]*)*)\s*=\s*(?!={1})", stripped)
        if m:
            return m.group(1).strip()
        # Multiline expression: the matched token may be inside `result = [\n   ...pattern...\n]`.
        # Walk up to 5 preceding lines to find the enclosing assignment —
        # but ONLY when the matched line itself looks like a continuation
        # fragment (unbalanced brackets, or ends with a trailing comma/open
        # bracket/backslash), not a complete standalone statement. Real bug
        # found scanning a LangGraph project: `st.chat_message("ai").write
        # (response.content)` is a complete, single-line, fully-balanced
        # statement with no assignment anywhere nearby — but the unconditional
        # backward scan walked up to a wholly unrelated `thread_id=thread_id,`
        # KEYWORD ARGUMENT (not even an assignment) inside a different call
        # several lines above, and returned "thread_id" as if it were the
        # answer. A wrong guess here is worse than an honest failure.
        if context_lines and not _looks_like_complete_statement(stripped):
            for ctx in reversed(context_lines[-5:]):
                m = re.match(
                    r"^([a-zA-Z_][a-zA-Z0-9_]*(?:\s*,\s*[a-zA-Z_][a-zA-Z0-9_]*)*)\s*=\s*(?!={1})",
                    ctx.strip(),
                )
                if m:
                    return m.group(1).strip()
        # Targeted same-line fallback: the "lhs" patterns for llm_to_agent
        # are literal attribute-access regexes (e.g. r"response\.content\b",
        # r"\.choices\[0\]\.message"), not assignments — the receiver of
        # that SAME-LINE access is the thing to check (e.g. "response" in
        # `response.content`). Extracted directly from the matched line
        # itself, not guessed from nearby unrelated context, so this doesn't
        # reintroduce the wrong-guess class of bug the checks above exist to
        # prevent — it's confirming what the classify rule already matched,
        # not searching for something new.
        m = re.search(r"\b([a-zA-Z_][a-zA-Z0-9_]*)\.(?:content|text|message)\b", stripped)
        if m:
            return m.group(1)

    if hint == "return":
        # `return html` / `return agentReply;` — the identifier being returned.
        m = _DATA_RETURN_RE.match(stripped)
        if m and m.group(1) not in _TRIVIAL_RETURN_NAMES:
            return m.group(1)

    if hint == "arg1":
        # First positional arg on the same line: `fn(var,` or `fn(var)`
        m = re.search(r"\(\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*[,)]", stripped)
        if m:
            return m.group(1)
        # Multiline call: scan following lines for keyword arg `messages=var`,
        # `prompt=var`, `content=var`, etc.
        if following_lines:
            _KW_RE = re.compile(
                r"^(?:messages?|prompt|inputs?|query|content|text|data|payload|request|user_input|user_message|user_query)\s*=\s*([a-zA-Z_][a-zA-Z0-9_]*)\b"
            )
            for fl in following_lines[:10]:
                fl_s = fl.strip()
                m = _KW_RE.match(fl_s)
                if m:
                    return m.group(1)
                # End of the call — stop looking
                if fl_s.startswith(")"):
                    break

    # No final "nearest assignment" fallback: an earlier version scanned up
    # to 20 preceding lines for the most recently assigned variable that
    # "looked like data" — completely disconnected from the actual matched
    # call. Real bugs found scanning a LangGraph project: it picked
    # `stored_message_fingerprints` and `thread_id` for calls that had
    # nothing to do with either name. A wrong guess here is worse than an
    # honest failure — if the wrong variable happens to also pass the
    # definite-assignment check, the result is a stub that silently guards
    # the WRONG variable while reporting safe_to_insert=True, which is a
    # false sense of security, not a working guardrail. Returning "" here
    # (falls through to safe_to_insert=False, "could not extract variable")
    # is the honest answer whenever the targeted hint-based extraction above
    # didn't find a real match.
    return ""


def _is_async_context(lines: list[str], lineno: int) -> bool:
    """Return True if the line at lineno sits inside an `async def` function body."""
    for i in range(lineno - 2, -1, -1):
        stripped = lines[i].strip()
        if re.match(r"async\s+def\s+", stripped):
            return True
        if re.match(r"def\s+", stripped):
            return False
        if re.match(r"class\s+", stripped):
            return False
    return False


# ── AST-based scanner for Python files ────────────────────────────────────────
# Uses Python's built-in `ast` module to avoid the main failure modes of regex:
#   - False positives from string literals and comments
#   - Wrong indentation on multi-line calls (col_offset is exact)
#   - Missing safety checks for lambdas / comprehensions / decorators
#   - Keyword argument extraction via AST nodes (no guessing from raw text)
#
# Specific API patterns (e.g. .messages.create) match any receiver name.
# Generic method names (.invoke, .predict) additionally require the receiver
# to contain an AI-hinting name so we don't flag unrelated .invoke() calls.

import ast as _ast

# Specific patterns — safe to match regardless of receiver name
_AST_SPECIFIC: list[tuple[str, str]] = [
    (".chat.completions.create",   "agent_to_llm"),
    (".messages.create",           "agent_to_llm"),
    (".generate_content",          "agent_to_llm"),
    (".completions.create",        "agent_to_llm"),
    (".fetchall",                  "db_read"),
    (".fetchone",                  "db_read"),
    # .execute intentionally excluded — too generic (matches tool.execute, event.execute,
    # prepared.execute, etc.).  Moved to _AST_DB_SPECIFIC with a DB-receiver gate.
    # data_outbound: JSON serialisation before external transmission
    ("json.dumps",                 "data_outbound"),
    ("json.encode",                "data_outbound"),
]

# Generic patterns — only fire when the immediate receiver contains an AI hint
_AST_GENERIC: list[tuple[str, str]] = [
    (".invoke",   "agent_to_llm"),
    (".predict",  "agent_to_llm"),
    (".run",      "agent_to_llm"),
    (".complete", "agent_to_llm"),
    (".generate", "agent_to_llm"),
    (".chat",     "agent_to_llm"),
]

# DB-specific patterns — only fire when the immediate receiver contains a DB-hinting name.
# Prevents false positives on tool.execute(), event.execute(), prepared.execute(), etc.
_AST_DB_SPECIFIC: list[tuple[str, str]] = [
    (".execute",  "db_read"),
]

_AST_AI_RECEIVER_HINTS = frozenset({
    "llm", "chat", "model", "agent", "chain", "pipeline",
    "gpt", "claude", "gemini", "openai", "anthropic",
})

_AST_DB_RECEIVER_HINTS = frozenset({
    "db", "cur", "cursor", "conn", "connection", "session",
    "engine", "database", "repo", "repository", "store",
})

# Keyword arg names that carry the actual data payload
_AST_DATA_KWARGS = frozenset({
    "messages", "prompt", "input", "inputs", "query", "content",
    "text", "data", "payload", "request", "user_input", "user_message", "user_query",
})

# Contexts where inserting a statement immediately before the call would break the code
_AST_UNSAFE_PARENTS = (
    _ast.Lambda,
    _ast.ListComp, _ast.SetComp, _ast.DictComp, _ast.GeneratorExp,
)


def _ast_build_parent_map(tree: _ast.AST) -> dict[int, _ast.AST]:
    parents: dict[int, _ast.AST] = {}
    for node in _ast.walk(tree):
        for child in _ast.iter_child_nodes(node):
            parents[id(child)] = node
    return parents


def _ast_attr_chain(node: _ast.expr) -> str:
    """Reconstruct the dotted attribute chain from a Call's func node."""
    if isinstance(node, _ast.Attribute):
        return f"{_ast_attr_chain(node.value)}.{node.attr}"
    if isinstance(node, _ast.Name):
        return node.id
    if isinstance(node, _ast.Call):
        return _ast_attr_chain(node.func)
    return ""


def _ast_classify(func: _ast.expr) -> "tuple[str, str] | None":
    """Return (insertion_point, confidence) for a known AI API call, else None.

    confidence: "high" for an SDK-qualified pattern that matches regardless of
    receiver name; "medium" for a generic method name that only fired because
    the receiver's own name happened to contain an AI/DB hint word.
    """
    chain = _ast_attr_chain(func).lower()
    for suffix, ip in _AST_SPECIFIC:
        if chain.endswith(suffix):
            return ip, "high"
    for suffix, ip in _AST_GENERIC:
        if chain.endswith(suffix):
            parts = chain[: -len(suffix)].rsplit(".", 1)
            receiver = parts[-1] if parts else ""
            if any(h in receiver for h in _AST_AI_RECEIVER_HINTS):
                return ip, "medium"
    for suffix, ip in _AST_DB_SPECIFIC:
        if chain.endswith(suffix):
            parts = chain[: -len(suffix)].rsplit(".", 1)
            receiver = parts[-1] if parts else ""
            if any(h in receiver for h in _AST_DB_RECEIVER_HINTS):
                return ip, "medium"
    return None


# ── Generic, framework-agnostic network-call detection ─────────────────────────
# Deliberately NOT tied to any AI SDK/agent framework name (LangChain, AutoGen,
# Google ADK, Copilot Studio, or any other) — every one of those eventually makes
# an HTTP call under the hood regardless of which framework it is, so detecting
# the HTTP call itself catches all of them without a per-framework detector, and
# without needing to know a variable's name or a receiver's "AI-ness" at all.
#
# requests/urllib are hardcoded here, but that's a fundamentally different kind
# of hardcoding than an AI SDK class/method table: it's the small, stable set of
# ways to make a SYNCHRONOUS HTTP call in Python (stdlib + the one dominant sync
# library) — it doesn't grow every time a new AI framework ships, unlike
# per-vendor SDK tables.
_AST_SYNC_HTTP_CALLS: list[tuple[str, str]] = [
    (".get",     "api_call"),
    (".post",    "api_call"),
    (".put",     "api_call"),
    (".patch",   "api_call"),
    (".delete",  "api_call"),
    (".request", "api_call"),
    ("urlopen",  "api_call"),
]
_AST_SYNC_HTTP_RECEIVERS = frozenset({"requests", "urllib.request", "httplib"})

# For an awaited call, the receiver is deliberately NOT checked at all — this is
# what makes this half framework-agnostic in the strongest sense. `await` is the
# load-bearing signal: no builtin/stdlib container method is awaitable (dict.get,
# list.get don't exist as awaitables), so gating on await instead of on receiver
# name/type rules out the obvious false positives without needing to know
# anything about what the receiver actually is.
_AST_ASYNC_HTTP_VERBS = frozenset({"get", "post", "put", "patch", "delete", "request", "send"})


def _ast_classify_generic_network_call(node: "_ast.Call", parent_map: dict) -> "tuple[str, str] | None":
    """Detect an outbound network call by HOW it's shaped, not WHO makes it.
    Returns (insertion_point, confidence) or None.

    Two cases:
    1. `requests.get(...)` / `urllib.request.urlopen(...)` etc. — sync,
       module-qualified to a known small set of HTTP libraries. "medium"
       confidence: we know for certain this is a real HTTP call, just not
       whether it's specifically AI-related.
    2. `await <anything>.post(...)` — the receiver can be any name, any type;
       `await` on a generic HTTP-verb method name is the signal, not the
       receiver's identity. Catches an in-house or unfamiliar SDK's client
       the same way it catches httpx/aiohttp, with no per-SDK knowledge.
       "low" confidence: weakest signal in this scanner — we don't even know
       the receiver is an HTTP client, only that *something* was awaited
       with a verb-shaped method name.

    Called as a fallback from _ast_classify's caller — only tried when the
    named-pattern tables (_AST_SPECIFIC/_AST_GENERIC/_AST_DB_SPECIFIC) find
    nothing, since there's no overlap in method names to arbitrate.
    """
    chain_orig = _ast_attr_chain(node.func)
    chain = chain_orig.lower()
    # Original-case last segment: HTTP methods are lowercase (`request`,
    # `urlopen`). PascalCase `Request` is urllib.request.Request — a
    # constructor, not an HTTP call. Matching is case-insensitive below
    # (`chain.endswith(".request")`), so without this guard
    # `urllib.request.Request(...)` is classified as api_call and the stub
    # wraps the Request object. json.dumps then raises "Object of type
    # Request is not JSON serializable" and the runtime fail-opens.
    last_orig = chain_orig.rsplit(".", 1)[-1] if chain_orig else ""
    for suffix, ip in _AST_SYNC_HTTP_CALLS:
        if chain.endswith(suffix):
            method = suffix.lstrip(".")
            if last_orig != method and last_orig.lower() == method:
                continue
            receiver = chain[: -len(suffix)].rstrip(".")
            if not receiver or any(receiver == r or receiver.endswith("." + r) for r in _AST_SYNC_HTTP_RECEIVERS):
                return ip, "medium"

    if isinstance(node.func, _ast.Attribute):
        method = node.func.attr.lower()
        if method in _AST_ASYNC_HTTP_VERBS and isinstance(parent_map.get(id(node)), _ast.Await):
            # Reuse the regex path's own denylist (queue/cache/redis/lock/...) instead
            # of a second, potentially-inconsistent gate — this is exactly the false
            # positive class documented above _ASYNC_NON_HTTP_RECEIVER_HINTS (asyncio.Queue,
            # caches, etc.), found first on the regex path; the AST path needs the same
            # guard for the same reason, on receivers regex can't see at all (e.g. `self.x`).
            receiver_chain = _ast_attr_chain(node.func.value)
            receiver = receiver_chain.rsplit(".", 1)[-1] if receiver_chain else ""
            if receiver and _is_non_http_async_receiver(receiver):
                return None
            return ip, "low"

    return None


# UI-response sinks (Flask/Django/FastAPI/Streamlit) — classified in the AST
# path so keyword args like `email=email` / `f1_driver=f1_driver` on
# `render_template_string(...)` are extracted from ast.keyword nodes instead
# of the regex/_scan_pii_ui_exposure arg1 heuristic (which only sees the first
# positional arg, usually an ALL_CAPS template constant).
_AST_UI_SINK_BASE_NAMES = frozenset({
    "jsonify", "make_response", "HttpResponse", "JsonResponse", "JSONResponse",
    "TemplateResponse",
})
_AST_UI_SINK_RENDER_PREFIX = "render_template"
_AST_UI_SINK_STREAMLIT_METHODS = frozenset({"write", "markdown", "text"})
_AST_CHAINLIT_RECEIVERS = frozenset({"cl", "chainlit"})
_AST_CHAINLIT_UI_CTORS = frozenset({"Text", "Pdf", "File", "Image", "Audio", "Video"})
_AST_CHAINLIT_UI_METHODS = frozenset({"stream_token"})
_UI_SINK_INSERTION_POINTS = frozenset({
    "llm_to_user", "agent_to_user", "tool_to_user", "html_to_user",
})
# Positional args that look like template identifiers, not data payloads.
_AST_TEMPLATE_CONST_NAME_RE = re.compile(r"^[A-Z][A-Z0-9_]*$")
# Keyword names that carry a template reference, never the PII payload.
_AST_TEMPLATE_KW_NAMES = frozenset({"template", "template_name", "name", "filename"})
# Non-PII context kwargs on render calls — lower priority than PII-shaped names.
_AST_UI_CONTEXT_KW_SCORES: dict[str, int] = {
    "email": 3, "content": 3, "user": 2, "profile": 2, "driver": 2, "record": 2,
    "context": 2, "data": 2, "payload": 2,
}


_AST_LOG_METHODS = frozenset({
    "debug", "info", "warning", "warn", "error", "critical",
    "exception", "log", "trace",
})
_AST_LOG_RECEIVERS = frozenset({"logger", "logging", "log"})


def _ast_classify_log_sink(func: "_ast.expr") -> "str | None":
    """Return log_emit when `func` is a print/logger/logging/log call."""
    chain = _ast_attr_chain(func)
    if not chain:
        return None
    if chain == "print":
        return "log_emit"
    base = chain.rsplit(".", 1)[-1]
    receiver = chain.rsplit(".", 1)[0].rsplit(".", 1)[-1] if "." in chain else ""
    if base in _AST_LOG_METHODS and (
        receiver in _AST_LOG_RECEIVERS
        or receiver.endswith("logger")
        or receiver.endswith("_log")
    ):
        return "log_emit"
    return None


def _ast_classify_ui_sink(func: _ast.expr) -> "str | None":
    """Return llm_to_user when `func` is a known UI-response sink call."""
    chain = _ast_attr_chain(func)
    if not chain:
        return None
    base = chain.rsplit(".", 1)[-1]
    if base.startswith(_AST_UI_SINK_RENDER_PREFIX):
        return "llm_to_user"
    if base in _AST_UI_SINK_BASE_NAMES or chain.endswith(".TemplateResponse"):
        return "llm_to_user"
    if base in _AST_UI_SINK_STREAMLIT_METHODS:
        receiver = chain.rsplit(".", 1)[0].rsplit(".", 1)[-1]
        if receiver == "st" or chain.startswith("st."):
            return "llm_to_user"
    if base in _AST_CHAINLIT_UI_METHODS:
        return "llm_to_user"
    if base in _AST_CHAINLIT_UI_CTORS:
        receiver = chain.rsplit(".", 1)[0].rsplit(".", 1)[-1] if "." in chain else ""
        if receiver in _AST_CHAINLIT_RECEIVERS:
            return "llm_to_user"
    return None


def _ast_with_open_targets(tree: _ast.AST) -> set[str]:
    """Names bound by ``with open(...) as f`` / ``with Path.open() as f``."""
    names: set[str] = set()
    for node in _ast.walk(tree):
        if not isinstance(node, (_ast.With, _ast.AsyncWith)):
            continue
        for item in node.items:
            ctx = item.context_expr
            if not isinstance(ctx, _ast.Call):
                continue
            chain = _ast_attr_chain(ctx.func)
            if chain != "open" and not chain.endswith(".open"):
                continue
            target = item.optional_vars
            if isinstance(target, _ast.Name):
                names.add(target.id)
    return names


def _ast_classify_file_read(node: _ast.Call, open_handles: set[str]) -> "tuple[str, str] | None":
    """``text = f.read()`` after ``with open(...) as f`` is file_upload, not an HTTP body."""
    if not isinstance(node.func, _ast.Attribute) or node.func.attr != "read":
        return None
    if not isinstance(node.func.value, _ast.Name):
        return None
    if node.func.value.id not in open_handles:
        return None
    return "file_upload", "high"


def _python_site_already_guarded(source_lines: list[str], lineno: int, var: str = "") -> bool:
    """True when THIS statement already has a stub immediately after (or wrapping ``var``).

    A ±15-line marker window is too wide: an ``AskFileMessage.send()`` stub ~10
    lines above ``text = f.read()`` would hide the file-body site that actually
    carries PII into RAG/UI.
    """
    n = len(source_lines)
    if lineno < 1 or lineno > n:
        return False
    line = source_lines[lineno - 1]
    if any(
        m in line
        for m in (
            "_gr_client.check(", "_gr_client.enforce(", "gr_check(", "_gr_decision",
            "_lineaje_load_gr_client", "SiteDescriptor(",
            "_gr_req", "_gr_resp", "GR_SERVICE_URL", '"insertion_point"',
        )
    ):
        return True

    def _next_code(start_1: int) -> int | None:
        i = start_1
        while i <= n:
            stripped = source_lines[i - 1].strip()
            if stripped and not stripped.startswith("#"):
                return i
            i += 1
        return None

    nxt = _next_code(lineno + 1)
    if nxt is not None:
        stripped = source_lines[nxt - 1].strip()
        if stripped == "try:" or stripped.endswith("try:"):
            block = "\n".join(source_lines[nxt - 1: min(n, nxt + 18)])
            if any(m in block for m in ("_gr_client.check(", "_gr_client.enforce(", "gr_check(", "_gr_req")):
                return True

    if var and var != "data":
        start = max(0, lineno - 16)
        end = min(n, lineno + 16)
        window = "\n".join(source_lines[start:end])
        needles = (
            f"{var} = _gr_decision.payload",
            f"{var} = _gr_client.enforce(",
            f"gr_check({var},",
            f"_gr_client.check(_gr_site, {var}",
            f'"data": {var}',
        )
        return any(n in window for n in needles)
    return False


def _ast_is_template_constant_name(name: str) -> bool:
    """True for ALL_CAPS template identifiers like HTML_TEMPLATE."""
    return bool(_AST_TEMPLATE_CONST_NAME_RE.match(name))


def _ast_score_ui_sink_kwarg(kw_name: str, var_name: str) -> int:
    """Higher = more likely the PII/data payload this stub should wrap."""
    if kw_name in _AST_TEMPLATE_KW_NAMES:
        return -1
    if _ast_is_template_constant_name(var_name):
        return 0
    norm = _normalize_ident(kw_name)
    if any(hint in norm for hint in _PII_HINT_NORMS):
        return 4
    if norm in _AST_UI_CONTEXT_KW_SCORES:
        return _AST_UI_CONTEXT_KW_SCORES[norm]
    if any(token in norm for token in _AST_UI_CONTEXT_KW_SCORES):
        return 2
    return 1


def _ast_extract_ui_sink_var(call: _ast.Call) -> str:
    """Extract the variable to guard on a UI-response call.

    Unlike generic `_ast_extract_var` (first positional Name wins), template
    renderers usually pass the template as arg0 and PII in keyword args —
    `render_template_string(HTML_TEMPLATE, email=email)` must resolve to
    `email`, not `HTML_TEMPLATE`.
    """
    scored: list[tuple[int, str]] = []
    for kw in call.keywords:
        if not kw.arg or not isinstance(kw.value, _ast.Name):
            continue
        score = _ast_score_ui_sink_kwarg(kw.arg, kw.value.id)
        if score >= 0:
            scored.append((score, kw.value.id))
    if scored:
        scored.sort(key=lambda t: (-t[0], t[1]))
        best_score = scored[0][0]
        best = [var for s, var in scored if s == best_score]
        if len(best) == 1:
            return best[0]
        return ""

    for arg in call.args:
        if isinstance(arg, _ast.Name):
            if not _ast_is_template_constant_name(arg.id):
                return arg.id
        elif isinstance(arg, _ast.Constant):
            continue
        break
    return ""


@dataclass
class MiddlewareCandidate:
    """A detected create_agent(...) call — remediation shape is 'rewrite one
    keyword argument of an existing call', not 'insert a line before/after
    one', so this is a separate dataclass from InsertionCandidate rather than
    forcing an unrelated shape into it."""
    file: str
    line: int          # 1-based, node.lineno of the create_agent(...) call
    end_line: int       # 1-based, node.end_lineno (multi-line calls span several)
    kwarg_state: str    # "absent" | "literal_list" | "other"
    assigned_var: str   # "" if the call result isn't assigned to a simple Name
    instruction: str = ""  # human-readable fallback, set when kwarg_state == "other"


def _create_agent_local_names(tree: _ast.Module) -> set[str]:
    """Local names bound to create_agent via `from langchain.agents import
    create_agent [as X]`. Always includes the literal name "create_agent"
    as a defensive default even without a traced import — matches
    _is_create_agent_call's module-attribute fallback."""
    names: set[str] = {"create_agent"}
    for node in _ast.walk(tree):
        if isinstance(node, _ast.ImportFrom):
            for alias in node.names:
                if alias.name == "create_agent":
                    names.add(alias.asname or alias.name)
    return names


def _is_create_agent_call(node: _ast.Call, local_names: set[str]) -> bool:
    """True for create_agent(...), an aliased import's call, or the
    module-attribute form (langchain.agents.create_agent(...))."""
    chain = _ast_attr_chain(node.func)
    return chain in local_names or chain.endswith(".create_agent")


def _detect_create_agent_calls(
    tree: _ast.Module,
    parent_map: dict[int, _ast.AST],
) -> list["MiddlewareCandidate"]:
    """Find every create_agent(...) call, classify its middleware= kwarg,
    and record the variable it's assigned to (if any) for the suppression
    pass in _scan_file_ast to consume."""
    local_names = _create_agent_local_names(tree)
    results: list[MiddlewareCandidate] = []

    for node in _ast.walk(tree):
        if not isinstance(node, _ast.Call):
            continue
        if not _is_create_agent_call(node, local_names):
            continue

        mw_kwarg = next((kw for kw in node.keywords if kw.arg == "middleware"), None)
        if mw_kwarg is None:
            kwarg_state = "absent"
            instruction = ""
        elif isinstance(mw_kwarg.value, _ast.List):
            kwarg_state = "literal_list"
            instruction = ""
        else:
            kwarg_state = "other"
            instruction = (
                f"manually add GuardrailMiddleware() to the middleware list "
                f"passed to create_agent() at line {node.lineno}"
            )

        assigned_var = ""
        parent = parent_map.get(id(node))
        if isinstance(parent, _ast.Assign) and len(parent.targets) == 1:
            target = parent.targets[0]
            if isinstance(target, _ast.Name):
                assigned_var = target.id

        results.append(MiddlewareCandidate(
            file="",  # filled in by the caller (scan_file), which knows the path
            line=node.lineno,
            end_line=node.end_lineno,
            kwarg_state=kwarg_state,
            assigned_var=assigned_var,
            instruction=instruction,
        ))

    return results


def _needs_comma_prefix(text_before_insertion_point: str) -> bool:
    """False when the text already ends with a trailing comma or an
    opening bracket with nothing after it (empty call/list) — inserting
    another leading comma there would produce ",," or "(," and break the
    syntax. Verified against multi-line, black-formatter-style trailing
    commas during implementation."""
    stripped = text_before_insertion_point.rstrip()
    return not (stripped.endswith(",") or stripped.endswith("(") or stripped.endswith("["))


def _rewrite_create_agent_absent(source: str, node: "_ast.Call") -> str:
    """Insert middleware=[GuardrailMiddleware()] into a create_agent(...)
    call that has no middleware= kwarg. Uses ast.get_source_segment()
    (not raw col_offset math) to get the call's exact literal text, then
    a line-range-scoped string replace — this avoids any risk of the
    replace touching a different, textually-identical call elsewhere in
    the file, and sidesteps any col_offset/encoding edge cases entirely."""
    lines = source.splitlines(keepends=True)
    span_start, span_end = node.lineno - 1, node.end_lineno  # 0-based slice
    segment = "".join(lines[span_start:span_end])
    old_call_text = _ast.get_source_segment(source, node)
    if old_call_text is None or old_call_text not in segment:
        raise ValueError("could not locate create_agent(...) call's exact source text")

    idx = old_call_text.rfind(")")
    before = old_call_text[:idx]
    prefix = ", " if _needs_comma_prefix(before) else ""
    new_call_text = before + f"{prefix}middleware=[GuardrailMiddleware()]" + old_call_text[idx:]

    new_segment = segment.replace(old_call_text, new_call_text, 1)
    lines[span_start:span_end] = [new_segment]
    return "".join(lines)


def _rewrite_create_agent_literal_list(
    source: str,
    node: "_ast.Call",
    mw_kwarg: "_ast.keyword",
) -> str:
    """Append GuardrailMiddleware() to an existing middleware=[...] literal
    list. Same line-scoped ast.get_source_segment() approach as
    _rewrite_create_agent_absent."""
    lines = source.splitlines(keepends=True)
    span_start, span_end = node.lineno - 1, node.end_lineno
    segment = "".join(lines[span_start:span_end])
    list_node = mw_kwarg.value
    old_list_text = _ast.get_source_segment(source, list_node)
    if old_list_text is None or old_list_text not in segment:
        raise ValueError("could not locate middleware=[...] list's exact source text")

    idx = old_list_text.rfind("]")
    before = old_list_text[:idx]
    prefix = ", " if _needs_comma_prefix(before) else ""
    new_list_text = before + f"{prefix}GuardrailMiddleware()" + old_list_text[idx:]

    new_segment = segment.replace(old_list_text, new_list_text, 1)
    lines[span_start:span_end] = [new_segment]
    return "".join(lines)


def _ast_extract_var(
    call: _ast.Call,
    is_lhs: bool = False,
    parent_map: "dict[int, _ast.AST] | None" = None,
) -> str:
    """Extract the variable name that holds the data being sent.

    is_lhs=True (for _LHS_INSERTION_POINTS — llm_to_agent/db_read/api_call/
    file_upload): the useful variable is what the call's RESULT is assigned
    to, not one of its arguments — `row = cursor.fetchone()` and
    `row = conn.execute("SELECT ...").fetchone()` both take zero or
    string-literal-only arguments, so argument-based extraction always
    failed for these regardless of how cleanly the code was written. Checked
    first and returned immediately (falling through to argument-based
    extraction below would be wrong here — the arguments aren't the value
    being protected, the return value is).

    Returns '' when no safe variable can be determined (caller marks safe_to_insert=False).
    """
    if is_lhs:
        parent = parent_map.get(id(call)) if parent_map is not None else None
        # `response = await session.get(url)` — the Call's direct parent is the
        # Await node, not the Assign; unwrap it before checking for Assign/
        # AnnAssign, or every awaited LHS-pattern call (async DB drivers,
        # AsyncOpenAI, any awaited api_call/db_read/file_upload/llm_to_agent)
        # fails extraction even though the assignment is right there.
        if isinstance(parent, _ast.Await) and parent_map is not None:
            parent = parent_map.get(id(parent))
        if isinstance(parent, _ast.Assign) and len(parent.targets) == 1:
            target = parent.targets[0]
            if isinstance(target, _ast.Name):
                return target.id
        elif isinstance(parent, _ast.AnnAssign) and isinstance(parent.target, _ast.Name):
            if parent.value is not None:  # `x: int` with no value isn't an assignment yet
                return parent.target.id
        return ""

    # Priority 1: keyword arg with a well-known data-like name and a plain Name value
    for kw in call.keywords:
        if kw.arg and kw.arg in _AST_DATA_KWARGS and isinstance(kw.value, _ast.Name):
            return kw.value.id
    # Priority 2: first positional arg that is a plain Name
    for arg in call.args:
        if isinstance(arg, _ast.Name):
            return arg.id
    # No "any keyword arg whose value is a plain Name" fallback here on purpose --
    # confirmed live on a real repo (PolicyProbe): self.llm_client.chat(messages=[...],
    # model=DEEPSEEK_MODEL) has no Name-valued messages/data kwarg (messages is an
    # inline list literal) but DOES have a Name-valued model= kwarg, and an unscoped
    # "any Name-valued kwarg" fallback grabbed DEEPSEEK_MODEL -- guarding the model
    # identifier string instead of the actual outgoing prompt. That's a false
    # positive that looks like a successful stub in the report but protects
    # nothing. Inline data kwargs are hoisted by _ast_hoist_inline_payload
    # instead of guessing an unrelated Name.
    return ""


def _fresh_hoist_name(source: str, base: str, lineno: int) -> str:
    """`_lineaje_messages`, or `_lineaje_messages_<line>` if that name is already used."""
    ident = "".join(ch if ch.isalnum() or ch == "_" else "_" for ch in base) or "payload"
    name = f"_lineaje_{ident}"
    if re.search(rf"\b{re.escape(name)}\b", source):
        return f"{name}_{lineno}"
    return name


def _replace_source_span(
    lines: list[str],
    start_line: int,
    start_col: int,
    end_line: int,
    end_col: int,
    replacement: str,
) -> None:
    """Replace a 1-based-line / 0-based-col AST span in a keepends line list."""
    if start_line < 1 or end_line < 1 or start_line > len(lines) or end_line > len(lines):
        return
    sidx, eidx = start_line - 1, end_line - 1

    def _nl(s: str) -> tuple[str, str]:
        if s.endswith("\r\n"):
            return s[:-2], "\r\n"
        if s.endswith("\n"):
            return s[:-1], "\n"
        return s, ""

    if sidx == eidx:
        body, nl = _nl(lines[sidx])
        lines[sidx] = body[:start_col] + replacement + body[end_col:] + nl
        return
    first_body, _ = _nl(lines[sidx])
    last_body, last_nl = _nl(lines[eidx])
    lines[sidx] = first_body[:start_col] + replacement + last_body[end_col:] + last_nl
    del lines[sidx + 1: eidx + 1]


def _ast_hoist_inline_payload(call: _ast.Call, source: str) -> "tuple[str, dict] | None":
    """Hoist an inline data-payload expression (list/dict/call/f-string/...) to a temp.

    PolicyProbe's `await self.llm_client.chat(messages=[{...}, {...}])` has no
    Name-valued data kwarg — the payload IS the list literal. Hoisting it to
    `_lineaje_messages` lets the stub wrap a real variable instead of declining.
    """
    def _plan_for(node: _ast.AST, base: str) -> "tuple[str, dict] | None":
        if isinstance(node, _ast.Name):
            return None
        if isinstance(node, _ast.Constant) and node.value is None:
            return None
        segment = _ast.get_source_segment(source, node)
        if not segment or not getattr(node, "lineno", None):
            return None
        end_lineno = getattr(node, "end_lineno", None) or node.lineno
        end_col = getattr(node, "end_col_offset", None)
        if end_col is None:
            end_col = node.col_offset + len(segment.splitlines()[-1])
        var = _fresh_hoist_name(source, base, call.lineno)
        return var, {
            "hoist_source": segment,
            "start_line": node.lineno,
            "start_col": node.col_offset,
            "end_line": end_lineno,
            "end_col": end_col,
        }

    for kw in call.keywords:
        if not (kw.arg and kw.arg in _AST_DATA_KWARGS):
            continue
        plan = _plan_for(kw.value, kw.arg)
        if plan:
            return plan
    for arg in call.args:
        if isinstance(arg, _ast.Starred):
            continue
        plan = _plan_for(arg, "payload")
        if plan:
            return plan
        break
    return None


def _ast_stmt_col(call: _ast.Call, parent_map: dict[int, _ast.AST]) -> int:
    """Col_offset of the enclosing statement — this is the correct stub indent.

    A Call inside `result = client.messages.create(...)` sits at col 15 while
    the Assign statement starts at col 4.  We want 4 spaces of indent for the stub.
    """
    _STMT_TYPES = (
        _ast.Assign, _ast.AugAssign, _ast.AnnAssign, _ast.Expr,
        _ast.Return, _ast.Delete, _ast.Assert, _ast.Raise,
        _ast.If, _ast.While, _ast.For, _ast.AsyncFor,
        _ast.With, _ast.AsyncWith,
    )
    current = parent_map.get(id(call))
    while current is not None:
        if isinstance(current, _STMT_TYPES):
            return current.col_offset
        if isinstance(current, (_ast.FunctionDef, _ast.AsyncFunctionDef, _ast.ClassDef)):
            break
        current = parent_map.get(id(current))
    return call.col_offset


def _ast_is_unsafe(call: _ast.Call, parent_map: dict[int, _ast.AST]) -> bool:
    """True if this call lives inside a lambda or comprehension — stub would break syntax."""
    current = parent_map.get(id(call))
    while current is not None:
        if isinstance(current, _AST_UNSAFE_PARENTS):
            return True
        current = parent_map.get(id(current))
    return False


def _ast_is_in_decorator(call: _ast.Call, parent_map: dict[int, _ast.AST]) -> bool:
    """True if this call is part of a decorator — stub before the decorated def would break it."""
    current = parent_map.get(id(call))
    while current is not None:
        if isinstance(current, (_ast.FunctionDef, _ast.AsyncFunctionDef, _ast.ClassDef)):
            # If we hit a function/class def before reaching a statement, we're in the decorator
            parent_of_def = parent_map.get(id(current))
            if parent_of_def is not None and isinstance(parent_of_def, _ast.Module):
                # top-level def — decorator is on the same logical line
                pass
            break
        current = parent_map.get(id(current))
    return False  # conservative — don't skip unless we're sure


def _ast_in_async_def(call: _ast.Call, parent_map: dict[int, _ast.AST]) -> bool:
    current = parent_map.get(id(call))
    while current is not None:
        if isinstance(current, _ast.AsyncFunctionDef):
            return True
        if isinstance(current, _ast.FunctionDef):
            return False
        current = parent_map.get(id(current))
    return False


# ── SSE/streaming-yield-in-a-loop detection (buffer-then-check remediation) ──
# Design decision (discussed at length, not silently assumed): unlike every
# other fix in this module, "buffer everything, check once, emit once" is a
# CONTROL-FLOW REWRITE, not a simple insertion — it moves existing yield
# statements out of a loop, not just adds a new line near one. Silently
# auto-editing a customer's working streaming response handler carries a
# real risk of subtly breaking it (wrong nesting, a dropped `continue`, a
# reordered chunk type). So this produces an INSTRUCTION-ONLY remediation
# action with a concrete, tailored before/after rewrite built from the
# actual detected code — same philosophy as create_agent's kwarg_state=
# "other" case — rather than an auto-applied edit.

_STREAM_LOOP_TYPES = (_ast.While, _ast.For, _ast.AsyncFor)


def _ast_find_enclosing(
    node: _ast.AST,
    parent_map: dict[int, _ast.AST],
    types: tuple,
    stop_types: tuple = (_ast.FunctionDef, _ast.AsyncFunctionDef),
) -> "_ast.AST | None":
    """Walk up from `node` via parent_map, returning the innermost ancestor
    matching `types`. Stops (returns None) if a `stop_types` boundary is
    crossed first without a match — e.g. never treats an OUTER function's
    loop as enclosing a line in an inner one."""
    current = parent_map.get(id(node))
    while current is not None:
        if isinstance(current, types):
            return current
        if isinstance(current, stop_types):
            return None
        current = parent_map.get(id(current))
    return None


def _ast_is_yield_expr_stmt(stmt: _ast.AST) -> "_ast.Yield | None":
    """Return the Yield node if `stmt` is a bare `yield <expr>` expression
    statement (not `x = yield ...`, not `yield from ...`), else None."""
    if isinstance(stmt, _ast.Expr) and isinstance(stmt.value, _ast.Yield):
        return stmt.value
    return None


@dataclass
class StreamBufferCandidate:
    """A yield-in-a-loop data_outbound site whose payload is an inline
    literal (no plain variable — extraction already failed upstream).
    Grouped by enclosing FUNCTION (not innermost loop) — a streaming
    generator commonly nests a per-message loop inside its main read loop
    (e.g. `while queue.get(): ... for message in batch: yield ...`), and a
    human fixing this thinks of it as ONE streaming response to buffer, not
    two unrelated loops to fix separately."""
    file: str
    function_name: str
    loop_lines: list[int]
    yield_lines: list[int]
    instruction: str


def _detect_streaming_buffer_candidates(file_path: str, source: str) -> list[StreamBufferCandidate]:
    """Find data_outbound yield-in-a-loop sites where the payload has no
    plain variable, and group them by enclosing generator function so one
    tailored instruction covers the whole streaming response.

    Reuses the same "json.dumps(...) with a non-Name first argument" shape
    already classified data_outbound elsewhere in this module — this is a
    second pass over that same shape, adding loop/function containment
    context to produce a much more actionable remediation than the generic
    "could not extract variable" message.
    """
    try:
        tree = _ast.parse(source)
    except SyntaxError:
        return []

    parent_map = _ast_build_parent_map(tree)
    # function_node id -> (func_node, {loop lines}, [yield lines])
    groups: dict[int, tuple[_ast.AST, set, list]] = {}

    for node in _ast.walk(tree):
        if not isinstance(node, _ast.Call):
            continue
        if _ast_attr_chain(node.func) not in ("json.dumps", "json.encode"):
            continue
        # Same "arg1 extraction" shape used elsewhere: only interesting when
        # the first argument is NOT a plain Name (a real variable would
        # already be safely insertable via the normal per-call-site stub).
        if node.args and isinstance(node.args[0], _ast.Name):
            continue

        yield_node = _ast_find_enclosing(node, parent_map, (_ast.Yield,))
        if yield_node is None:
            continue
        yield_stmt = parent_map.get(id(yield_node))
        if not (isinstance(yield_stmt, _ast.Expr) and yield_stmt.value is yield_node):
            continue

        loop_node = _ast_find_enclosing(yield_stmt, parent_map, _STREAM_LOOP_TYPES)
        func_node = _ast_find_enclosing(
            yield_stmt, parent_map, (_ast.FunctionDef, _ast.AsyncFunctionDef), stop_types=()
        )
        if loop_node is None or func_node is None:
            continue

        entry = groups.setdefault(id(func_node), (func_node, set(), []))
        entry[1].add(loop_node.lineno)
        entry[2].append(yield_stmt.lineno)

    results: list[StreamBufferCandidate] = []
    for func_node, loop_lines_set, yield_lines in groups.values():
        loop_lines = sorted(loop_lines_set)
        yield_lines = sorted(set(yield_lines))
        instruction = (
            f"Streaming response detected in `{func_node.name}()` (loop(s) at "
            f"line(s) {', '.join(str(l) for l in loop_lines)}): {len(yield_lines)} "
            f"yield site(s) at line(s) {', '.join(str(l) for l in yield_lines)} "
            f"send an inline payload with no named variable, so a guardrail "
            f"check can't be inserted there without restructuring the loop. "
            f"Recommended fix — buffer the streamed output, run ONE guardrail "
            f"check on the complete result, then emit it (see this session's "
            f"design discussion on the token-vs-message-level check trade-off "
            f"before choosing this over a per-chunk check):\n\n"
            f"    _gr_buffered = []\n"
            f"    <replace each `yield f\"data: {{...}}\\n\\n\"` in "
            f"`{func_node.name}()` with `_gr_buffered.append(...)` of the "
            f"same payload dict>\n"
            f"    _gr_checked = gr_check(_gr_buffered, \"agent\", \"external\")\n"
            f"    for _gr_chunk in _gr_checked:\n"
            f"        yield f\"data: {{json.dumps(_gr_chunk)}}\\n\\n\"\n"
        )
        results.append(StreamBufferCandidate(
            file=file_path,
            function_name=func_node.name,
            loop_lines=loop_lines,
            yield_lines=yield_lines,
            instruction=instruction,
        ))

    results.sort(key=lambda r: r.loop_lines[0])
    return results


def _scan_file_ast(
    file_path: str,
    source: str,
    lineaje_pat: str,
    insertion_point_types: list[str] | None,
    policy_map: dict[str, list[dict]] | None,
    companion_hops: int = 0,
    rel_file: str | None = None,
) -> "tuple[list[InsertionCandidate], list[MiddlewareCandidate], set[tuple[str, int]]] | None":
    """AST-based scanner for Python files.

    Returns a (list[InsertionCandidate], list[MiddlewareCandidate],
    unsafe_keys) tuple (same InsertionCandidate interface as the regex path,
    plus create_agent() middleware candidates detected in the same pass).
    Returns None on SyntaxError — caller falls back to regex.

    unsafe_keys is {(insertion_point, line), ...} for calls this scanner
    examined and rejected via _ast_is_unsafe (lambda body / comprehension —
    a stub there would be a syntax error, not just an unclear variable name).
    scan_file's regex-supplement merge must exclude these lines too, or the
    regex path — which has no unsafe-context awareness of its own — silently
    re-adds a bogus candidate for the exact line the AST path just rejected.

    Key improvements over regex:
    - col_offset gives exact statement-level indent (no guessing from raw line)
    - Keyword args extracted directly from AST nodes
    - Skips lambdas/comprehensions where a stub insertion would be a syntax error
    - Fires on the opening line of multi-line calls (regex can fire on the wrong line)
    - No false positives from strings or comments
    """
    try:
        tree = _ast.parse(source, filename=file_path)
    except SyntaxError:
        return None  # caller falls back to regex

    source_lines = source.splitlines()
    parent_map = _ast_build_parent_map(tree)
    open_handles = _ast_with_open_targets(tree)

    middleware_candidates = _detect_create_agent_calls(tree, parent_map)
    for mc in middleware_candidates:
        mc.file = file_path
    suppressed_vars = {mc.assigned_var for mc in middleware_candidates if mc.assigned_var}

    _STUB_MARKERS = (
        "gr_check(", "grCheck(", "GRBlockedError",
        "GR_SERVICE_URL", "LINEAJE_PAT", "GR_BEARER_TOKEN",
        "_gr_req", "_gr_resp", "_gr_call", '"insertion_point"',
        # Current VIII.5/VIII.6 stub shape (SiteDescriptor + .check()) — the
        # markers above only recognize the retired gr_check()-shaped stub, so
        # a re-scan of an already-instrumented file never saw its own
        # existing stub as a guard and could emit a second, duplicate
        # candidate right next to it.
        "_lineaje_load_gr_client", "_gr_client.check(", "_gr_client.enforce(", "_gr_decision", "SiteDescriptor(",
    )

    def _already_guarded(lineno: int, var: str = "") -> bool:
        return _python_site_already_guarded(source_lines, lineno, var)

    candidates: list[InsertionCandidate] = []
    seen_lines: set[int] = set()
    unsafe_keys: set[tuple[str, int]] = set()

    for node in _ast.walk(tree):
        if not isinstance(node, _ast.Call):
            continue

        lineno = node.lineno
        if lineno in seen_lines:
            continue

        _classified = _ast_classify(node.func)
        if _classified is None:
            # Fallback: framework-agnostic network-call shape (see its own
            # docstring) — tried only when the named-pattern tables find
            # nothing, so an AI SDK we don't have a table entry for is still
            # caught via its underlying HTTP call, not missed entirely.
            _classified = _ast_classify_generic_network_call(node, parent_map)
        if _classified is None:
            _classified = _ast_classify_file_read(node, open_handles)
        _ui_sink = _ast_classify_ui_sink(node.func) if _classified is None else None
        _log_sink = (
            _ast_classify_log_sink(node.func)
            if _classified is None and _ui_sink is None else None
        )
        if _classified is None and _ui_sink is None and _log_sink is None:
            continue
        if _classified is not None:
            ip, confidence = _classified
        elif _ui_sink is not None:
            ip, confidence = _ui_sink, "high"
        else:
            ip, confidence = _log_sink, "high"
        if _ast_is_unsafe(node, parent_map):
            unsafe_keys.add((ip, lineno))
            continue
        # Suppression: skip calls/attribute access on a variable already
        # known to hold a create_agent()-built agent — its traffic is
        # covered by GuardrailMiddleware instead of a per-call-site stub.
        if suppressed_vars:
            _receiver = _ast_attr_chain(node.func).split(".", 1)[0]
            if _receiver in suppressed_vars:
                continue

        _ia = ip in _LHS_INSERTION_POINTS
        hoist_meta: dict = {}
        if _ui_sink:
            var = _ast_extract_ui_sink_var(node)
            if not var:
                hoisted = _ast_hoist_inline_payload(node, source)
                if hoisted:
                    var, hoist_meta = hoisted
            _func_name = _enclosing_symbol(source_lines, lineno)
            _window = "\n".join(source_lines[max(0, lineno - 10): min(len(source_lines), lineno + 5)])
            ip = _guess_interaction_type(_func_name, var or "data", _window)
        else:
            var = _ast_extract_var(node, is_lhs=_ia, parent_map=parent_map)
            if not var and not _ia:
                hoisted = _ast_hoist_inline_payload(node, source)
                if hoisted:
                    var, hoist_meta = hoisted
        if _already_guarded(lineno, var):
            seen_lines.add(lineno)
            continue
        if insertion_point_types is not None and ip not in insertion_point_types:
            continue

        seen_lines.add(lineno)
        if var:
            safe = True
            skip_reason = ""
        else:
            var = "data"
            safe = False
            skip_reason = (
                "Variable could not be determined from AST — review the call and set "
                "the correct variable name before inserting."
            )

        indent = " " * _ast_stmt_col(node, parent_map)
        is_async = _ast_in_async_def(node, parent_map)
        context_line = source_lines[lineno - 1] if lineno <= len(source_lines) else ""
        policy_reasons = list(policy_map.get(ip, [])) if policy_map else []
        policy_ids = [pr["policy_id"] for pr in policy_reasons]
        # Site identity (follow-up to Phase 6a): this is the AST path — the
        # one that actually fires for SDK-qualified calls like .fetchall()/
        # .chat.completions.create(), i.e. the common case, not the regex
        # supplement. pattern_matched below must match what the
        # InsertionCandidate itself records for this same site, or the
        # embedded stub's site_id and the candidate's own site_id field
        # would silently diverge.
        _ast_pattern_matched = f"ast:{_ast_attr_chain(node.func)}"
        _ast_symbol = _enclosing_symbol(source_lines, lineno)
        _ast_site_id = _derive_site_id(rel_file or file_path, _ast_symbol, ip, _ast_pattern_matched)
        stub_line = _make_stub_line(
            var, ip, lineaje_pat, indent, ".py", is_async=is_async, insert_after=_ia,
            candidate_policy_ids=policy_ids, site_id=_ast_site_id,
        )
        if hoist_meta:
            stub_line = f"{indent}{var} = {hoist_meta['hoist_source']}\n" + stub_line

        # Validation gate: trial insertion + ast.parse() + scope check.
        # Only run when variable was successfully extracted (safe=True).
        if safe:
            if hoist_meta:
                _valid, _reason = _validate_hoist_stub_insertion(
                    source, stub_line, lineno, var, hoist_meta, _import_hint(".py"),
                )
            else:
                _valid, _reason = _validate_stub_insertion(
                    source, stub_line, lineno, _import_hint(".py"), var,
                    insert_after=_ia, stmt_end_line=node.end_lineno,
                )
            if not _valid:
                safe = False
                skip_reason = _reason

        candidates.append(InsertionCandidate(
            file=file_path,
            line=lineno,
            insertion_point=ip,
            pattern_matched=_ast_pattern_matched,
            context_line=context_line,
            suggested_variable=var,
            description=(
                f"AST-confirmed {ip} at line {lineno}, col {node.col_offset}"
                + (" [async]" if is_async else "")
            ),
            proposed_stub=stub_line,
            safe_to_insert=safe,
            skip_reason=skip_reason,
            policy_ids=policy_ids,
            policy_reasons=policy_reasons,
            insert_after=_ia,
            variable_to_use_in_call="",
            companion_hops=companion_hops,
            site_id=_ast_site_id,
            confidence=confidence,
            stmt_end_line=node.end_lineno or lineno,
            hoist_source=hoist_meta.get("hoist_source", ""),
            hoist_start_line=hoist_meta.get("start_line", 0),
            hoist_start_col=hoist_meta.get("start_col", 0),
            hoist_end_line=hoist_meta.get("end_line", 0),
            hoist_end_col=hoist_meta.get("end_col", 0),
        ))

    # Bare-name `return <data>` — insert BEFORE the return so every routine
    # can inspect the payload leaving the function. Call-shaped returns
    # (`return jsonify(x)`) are already handled above via the Call walk.
    _UI_WILDCARD_IPS = frozenset({
        "data_egress", "llm_to_user",
        "html_to_user", "agent_to_user", "tool_to_user",
    })
    for node in _ast.walk(tree):
        if not isinstance(node, _ast.Return):
            continue
        lineno = node.lineno
        if lineno in seen_lines:
            continue
        var = _ast_return_name(node)
        if not var or var in _TRIVIAL_RETURN_NAMES:
            continue
        if _ast_is_unsafe(node, parent_map):
            unsafe_keys.add(("data_egress", lineno))
            continue
        if _already_guarded(lineno):
            continue
        _func_name = _enclosing_symbol(source_lines, lineno)
        _window = "\n".join(source_lines[max(0, lineno - 10): min(len(source_lines), lineno + 5)])
        ip = _refine_ui_insertion_point("data_egress", _func_name, var, _window)
        if insertion_point_types is not None:
            allowed = set(insertion_point_types)
            if allowed & _UI_WILDCARD_IPS:
                allowed.update(_UI_WILDCARD_IPS)
            if ip not in allowed:
                continue
        seen_lines.add(lineno)
        indent = " " * getattr(node, "col_offset", 0)
        is_async = _ast_in_async_def(node, parent_map)
        context_line = source_lines[lineno - 1] if lineno <= len(source_lines) else ""
        policy_reasons = list(policy_map.get(ip, [])) if policy_map else []
        if not policy_reasons and policy_map:
            policy_reasons = list(policy_map.get("data_egress", []))
        policy_ids = [pr["policy_id"] for pr in policy_reasons]
        _ast_pattern_matched = "ast:return"
        _ast_symbol = _func_name
        _ast_site_id = _derive_site_id(rel_file or file_path, _ast_symbol, ip, _ast_pattern_matched)
        stub_line = _make_stub_line(
            var, ip, lineaje_pat, indent, ".py", is_async=is_async, insert_after=False,
            candidate_policy_ids=policy_ids, site_id=_ast_site_id,
        )
        safe, skip_reason = True, ""
        _valid, _reason = _validate_stub_insertion(
            source, stub_line, lineno, _import_hint(".py"), var,
            insert_after=False, stmt_end_line=node.end_lineno,
        )
        if not _valid:
            safe, skip_reason = False, _reason
        candidates.append(InsertionCandidate(
            file=file_path,
            line=lineno,
            insertion_point=ip,
            pattern_matched=_ast_pattern_matched,
            context_line=context_line,
            suggested_variable=var,
            description=(
                f"AST-confirmed function return of '{var}' at line {lineno} "
                f"({ip}) — scan payload before returning"
            ),
            proposed_stub=stub_line,
            safe_to_insert=safe,
            skip_reason=skip_reason,
            policy_ids=policy_ids,
            policy_reasons=policy_reasons,
            insert_after=False,
            variable_to_use_in_call="",
            companion_hops=companion_hops,
            site_id=_ast_site_id,
            confidence="high",
            stmt_end_line=node.end_lineno or lineno,
        ))

    return candidates, middleware_candidates, unsafe_keys


def _ast_covering_stmt(tree: "_ast.AST", line: int) -> "_ast.stmt | None":
    """Innermost executable statement whose [lineno, end_lineno] covers `line`.

    Used when a violation is cited inside a multiline f-string / HTML
    literal — there is no ast.Call on that line, but the enclosing Assign
    or Return is a real insertion site. Skips FunctionDef/ClassDef so we
    never treat the whole function body as the site.
    """
    best: "_ast.stmt | None" = None
    best_span: "int | None" = None
    for n in _ast.walk(tree):
        if not isinstance(n, _ast.stmt):
            continue
        if isinstance(n, (_ast.FunctionDef, _ast.AsyncFunctionDef, _ast.ClassDef, _ast.Module)):
            continue
        start = getattr(n, "lineno", None)
        if start is None:
            continue
        end = getattr(n, "end_lineno", None) or start
        if start <= line <= end:
            span = end - start
            if best is None or span < best_span:
                best, best_span = n, span
    return best


def _ast_assign_target_name(stmt: "_ast.stmt") -> str:
    if isinstance(stmt, _ast.Assign) and len(stmt.targets) == 1 and isinstance(stmt.targets[0], _ast.Name):
        return stmt.targets[0].id
    if isinstance(stmt, _ast.AnnAssign) and isinstance(stmt.target, _ast.Name):
        return stmt.target.id
    return ""


def _ast_is_stringy(node: "_ast.AST | None") -> bool:
    """True for f-strings, string literals, concatenations, or parenthesized string tuples."""
    if node is None:
        return False
    if isinstance(node, _ast.JoinedStr):
        return True
    if isinstance(node, _ast.Constant) and isinstance(node.value, str):
        return True
    if isinstance(node, _ast.BinOp) and isinstance(node.op, _ast.Add):
        return _ast_is_stringy(node.left) or _ast_is_stringy(node.right)
    if isinstance(node, _ast.Tuple):
        return any(_ast_is_stringy(elt) for elt in node.elts)
    return False


def _ast_return_name(node: "_ast.Return") -> str:
    if isinstance(getattr(node, "value", None), _ast.Name):
        return node.value.id
    return ""


def _ast_enclosing_function(node: "_ast.AST", parent_map: dict[int, "_ast.AST"]) -> "_ast.AST | None":
    current = parent_map.get(id(node))
    while current is not None:
        if isinstance(current, (_ast.FunctionDef, _ast.AsyncFunctionDef)):
            return current
        current = parent_map.get(id(current))
    return None


def _ast_find_return_of_name(fn: "_ast.AST | None", name: str) -> "_ast.Return | None":
    if fn is None or not name:
        return None
    for n in _ast.walk(fn):
        if isinstance(n, _ast.Return) and _ast_return_name(n) == name:
            return n
    return None


def _refine_ui_insertion_point(insertion_point: str, func_name: str, var: str, window: str) -> str:
    """Map a phase-level IP (data_egress / llm_to_user) to the concrete UI edge."""
    if insertion_point not in {"data_egress", "llm_to_user"}:
        return insertion_point
    return _guess_interaction_type(func_name, var, window)


def scan_violation_targeted(
    file_path: str,
    line: int,
    insertion_point: str,
    policy_reasons: "list[dict]",
    lineaje_pat: str = "",
    companion_hops: int = 0,
) -> "InsertionCandidate | None":
    """Attempt a stub insertion at an EXACT violation location. Python-only.

    _scan_file_ast only stubs calls whose shape matches a known SDK pattern
    (_ast_classify) — a violation can be found on a line the classifier
    doesn't recognize (e.g. a bare `logger.info(pii)` for a PII policy). This
    targets that exact line directly using the insertion_point type the
    caller already resolved from the violated policy (see
    fetch_insertion_point_map), instead of re-classifying the call shape.

    Also accepts non-call AST sites that are real UI egress: a bare
    ``return html``, or a line *inside* a multiline f-string / HTML
    assignment — those relocate to the ``return <name>`` in the same
    function (AI_DAT_SEC_012's insertion prompt: never insert on markup
    inside a string; insert at the return/render).

    Returns None (never raises) when the file isn't Python, has a SyntaxError,
    no insertable Call/Return/string-Assign covers `line`, the site is in an
    unsafe context (lambda/comprehension), no variable can be extracted, or
    the trial insertion doesn't validate. Every failure just means "no
    targeted stub here" — the caller falls back to reporting the violation
    as uncovered.
    """
    path = Path(file_path)
    if path.suffix.lower() != ".py":
        return None
    try:
        source = path.read_text(errors="replace")
        tree = _ast.parse(source, filename=file_path)
    except (OSError, SyntaxError):
        return None

    source_lines = source.splitlines()
    parent_map = _ast_build_parent_map(tree)
    _targeted_policy_ids = [pr["policy_id"] for pr in policy_reasons]

    def _emit(
        *,
        var: str,
        insert_line: int,
        insert_after: bool,
        stmt_end: int,
        indent_from: _ast.AST,
        hoist_meta: dict,
        ip: str,
    ) -> "InsertionCandidate | None":
        if not var:
            return None
        if _ast_is_unsafe(indent_from, parent_map):
            return None
        if isinstance(indent_from, (_ast.Return, _ast.Assign, _ast.AnnAssign, _ast.Expr)):
            indent = " " * getattr(indent_from, "col_offset", 0)
        else:
            indent = " " * _ast_stmt_col(indent_from, parent_map)
        is_async = _ast_in_async_def(indent_from, parent_map)
        context_line = source_lines[insert_line - 1] if insert_line <= len(source_lines) else ""
        _symbol = _enclosing_symbol(source_lines, insert_line)
        _phase, _boundary = _canonical_phase_and_boundary(ip)
        _site_id = _derive_site_id(file_path, _symbol, ip, "violation-targeted")
        stub_line = _make_stub_line(
            var, ip, lineaje_pat, indent, ".py", is_async=is_async, insert_after=insert_after,
            candidate_policy_ids=_targeted_policy_ids, site_id=_site_id,
        )
        if hoist_meta:
            stub_line = f"{indent}{var} = {hoist_meta['hoist_source']}\n" + stub_line
            valid, _reason = _validate_hoist_stub_insertion(
                source, stub_line, insert_line, var, hoist_meta, _import_hint(".py"),
            )
        else:
            valid, _reason = _validate_stub_insertion(
                source, stub_line, insert_line, _import_hint(".py"), var,
                insert_after=insert_after, stmt_end_line=stmt_end,
            )
        if not valid:
            return None
        return InsertionCandidate(
            file=file_path,
            line=insert_line,
            insertion_point=ip,
            pattern_matched="violation-targeted",
            context_line=context_line,
            suggested_variable=var,
            description=(
                f"Violation-targeted {ip} at line {insert_line} "
                f"(policy-driven — not caught by pattern matching)"
            ),
            proposed_stub=stub_line,
            safe_to_insert=True,
            skip_reason="",
            policy_ids=_targeted_policy_ids,
            policy_reasons=policy_reasons,
            insert_after=insert_after,
            variable_to_use_in_call="",
            companion_hops=companion_hops,
            site_id=_site_id,
            boundary=_boundary,
            phase=_phase,
            stmt_end_line=stmt_end or insert_line,
            hoist_source=hoist_meta.get("hoist_source", ""),
            hoist_start_line=hoist_meta.get("start_line", 0),
            hoist_start_col=hoist_meta.get("start_col", 0),
            hoist_end_line=hoist_meta.get("end_line", 0),
            hoist_end_col=hoist_meta.get("end_col", 0),
        )

    call_node = next(
        (n for n in _ast.walk(tree) if isinstance(n, _ast.Call) and n.lineno == line),
        None,
    )
    if call_node is not None and not _ast_is_unsafe(call_node, parent_map):
        ia = insertion_point in _LHS_INSERTION_POINTS
        hoist_meta: dict = {}
        if _ast_classify_ui_sink(call_node.func):
            var = _ast_extract_ui_sink_var(call_node)
        else:
            var = _ast_extract_var(call_node, is_lhs=ia, parent_map=parent_map)
            if not var and not ia:
                hoisted = _ast_hoist_inline_payload(call_node, source)
                if hoisted:
                    var, hoist_meta = hoisted
        if var:
            return _emit(
                var=var, insert_line=line, insert_after=ia,
                stmt_end=call_node.end_lineno or line, indent_from=call_node,
                hoist_meta=hoist_meta, ip=insertion_point,
            )

    # Non-call AST: Return / string Assign / line inside a multiline f-string.
    covering = _ast_covering_stmt(tree, line)
    if covering is None or _ast_is_unsafe(covering, parent_map):
        return None

    insert_node: _ast.AST | None = None
    var = ""
    ia = False
    if isinstance(covering, _ast.Return):
        var = _ast_return_name(covering)
        insert_node = covering
    elif isinstance(covering, (_ast.Assign, _ast.AnnAssign)):
        var = _ast_assign_target_name(covering)
        value = covering.value
        if var and _ast_is_stringy(value):
            ret = _ast_find_return_of_name(
                _ast_enclosing_function(covering, parent_map), var,
            )
            if ret is not None:
                insert_node = ret
            else:
                insert_node = covering
                ia = True
    if insert_node is None or not var:
        return None

    insert_line = getattr(insert_node, "lineno", line)
    window_start = max(0, insert_line - 1)
    window = "\n".join(source_lines[window_start: window_start + 30])
    ip = _refine_ui_insertion_point(
        insertion_point, _enclosing_symbol(source_lines, insert_line), var, window,
    )
    return _emit(
        var=var, insert_line=insert_line, insert_after=ia,
        stmt_end=getattr(insert_node, "end_lineno", None) or insert_line,
        indent_from=insert_node, hoist_meta={}, ip=ip,
    )


# ── Tree-sitter AST scanner for JS / TS / Java ────────────────────────────────
# Requires: pip install tree-sitter tree-sitter-javascript tree-sitter-typescript tree-sitter-java
#
# Gracefully degrades to the regex path if any grammar package is missing.
# Same safety guarantees as the Python AST scanner:
#   - Skips arrow-function bodies without a block (would be a syntax error)
#   - Skips template literals / ternary expressions / lambda bodies (Java)
#   - start_point gives exact statement-level column offset
#   - Fires on the first line of multi-line calls
#   - No false positives from string literals or comments


def _ts_build_parent_map(root: Any) -> dict[tuple, Any]:
    """Build (start_byte, end_byte) → parent for every node in a tree-sitter tree.

    tree-sitter Python nodes are created fresh on each property access, so id()
    is not stable across traversals.  (start_byte, end_byte) is unique per node
    within a single parsed tree and is always a stable integer pair.
    """
    parent_map: dict[tuple, Any] = {}
    stack = [(root, None)]
    while stack:
        node, parent = stack.pop()
        if parent is not None:
            parent_map[(node.start_byte, node.end_byte)] = parent
        for child in reversed(node.children):
            stack.append((child, node))
    return parent_map


def _ts_parent(node: Any, parent_map: dict[tuple, Any]) -> "Any | None":
    """Return the parent node for a tree-sitter node, or None if it is the root."""
    return parent_map.get((node.start_byte, node.end_byte))


def _ts_attr_chain_js(node: Any) -> str:
    """Reconstruct the dotted attribute chain from a JS/TS call_expression or member_expression."""
    if node.type == "member_expression":
        obj = node.child_by_field_name("object")
        prop = node.child_by_field_name("property")
        if obj and prop:
            return f"{_ts_attr_chain_js(obj)}.{prop.text.decode('utf-8', errors='replace')}"
    elif node.type == "call_expression":
        func = node.child_by_field_name("function")
        if func:
            return _ts_attr_chain_js(func)
    elif node.type in ("identifier", "property_identifier"):
        return node.text.decode("utf-8", errors="replace")
    return ""


def _ts_attr_chain_java(node: Any) -> str:
    """Reconstruct the dotted method chain from a Java method_invocation or field_access."""
    if node.type == "method_invocation":
        obj = node.child_by_field_name("object")
        name = node.child_by_field_name("name")
        if obj and name:
            return f"{_ts_attr_chain_java(obj)}.{name.text.decode('utf-8', errors='replace')}"
        if name:
            return name.text.decode("utf-8", errors="replace")
    elif node.type == "field_access":
        obj = node.child_by_field_name("object")
        field = node.child_by_field_name("field")
        if obj and field:
            return f"{_ts_attr_chain_java(obj)}.{field.text.decode('utf-8', errors='replace')}"
    elif node.type == "identifier":
        return node.text.decode("utf-8", errors="replace")
    return ""


def _ts_classify(chain: str) -> "str | None":
    """Return insertion_point for a known AI API call chain, else None."""
    chain_lc = chain.lower()
    for suffix, ip in _AST_SPECIFIC:
        if chain_lc.endswith(suffix):
            return ip
    for suffix, ip in _AST_GENERIC:
        if chain_lc.endswith(suffix):
            parts = chain_lc[: -len(suffix)].rsplit(".", 1)
            receiver = parts[-1] if parts else ""
            if any(h in receiver for h in _AST_AI_RECEIVER_HINTS):
                return ip
    for suffix, ip in _AST_DB_SPECIFIC:
        if chain_lc.endswith(suffix):
            parts = chain_lc[: -len(suffix)].rsplit(".", 1)
            receiver = parts[-1] if parts else ""
            if any(h in receiver for h in _AST_DB_RECEIVER_HINTS):
                return ip
    return None


# JS/TS contexts where inserting a statement BEFORE the call would break the code
_TS_JS_UNSAFE_TYPES = frozenset({
    "template_substitution",   # `${llm.invoke(x)}` — inside template literal
    "ternary_expression",       # cond ? llm.invoke(a) : b
})

# Java contexts where inserting a statement before the call would break the code
_TS_JAVA_UNSAFE_TYPES = frozenset({
    "lambda_expression",
    "method_reference",
})


def _ts_is_unsafe_js(node: Any, parent_map: dict[tuple, Any]) -> bool:
    """True if this JS/TS call is inside a context that would break if we inserted a statement."""
    current = _ts_parent(node, parent_map)
    while current is not None:
        if current.type in _TS_JS_UNSAFE_TYPES:
            return True
        if current.type == "arrow_function":
            # Arrow function WITHOUT a block body: x => expr — inserting before the call
            # would produce invalid syntax (you can't have statements inside an expression body).
            # Arrow function WITH a block body: x => { stmt; stmt; } — perfectly safe.
            body = current.child_by_field_name("body")
            if body is None:
                # No named "body" field — try last non-arrow child as body
                non_arrow = [c for c in current.children if c.type != "=>"]
                body = non_arrow[-1] if non_arrow else None
            return body is None or body.type != "statement_block"
        if current.type in ("function_declaration", "function", "method_definition",
                             "generator_function", "generator_function_declaration"):
            break
        current = _ts_parent(current, parent_map)
    return False


def _ts_is_unsafe_java(node: Any, parent_map: dict[tuple, Any]) -> bool:
    current = _ts_parent(node, parent_map)
    while current is not None:
        if current.type in _TS_JAVA_UNSAFE_TYPES:
            return True
        if current.type in ("method_declaration", "constructor_declaration"):
            break
        current = _ts_parent(current, parent_map)
    return False


def _ts_stmt_col_js(node: Any, parent_map: dict[tuple, Any]) -> int:
    """Column of the enclosing JS/TS statement — the correct indent for the stub."""
    _JS_STMT = frozenset({
        "expression_statement", "lexical_declaration", "variable_declaration",
        "return_statement",
    })
    current = _ts_parent(node, parent_map)
    while current is not None:
        if current.type in _JS_STMT:
            return current.start_point[1]
        if current.type in ("function_declaration", "function", "method_definition",
                             "arrow_function", "class_declaration"):
            break
        current = _ts_parent(current, parent_map)
    return node.start_point[1]


def _ts_stmt_col_java(node: Any, parent_map: dict[tuple, Any]) -> int:
    """Column of the enclosing Java statement — the correct indent for the stub."""
    _JAVA_STMT = frozenset({
        "expression_statement", "local_variable_declaration", "return_statement",
    })
    current = _ts_parent(node, parent_map)
    while current is not None:
        if current.type in _JAVA_STMT:
            return current.start_point[1]
        if current.type in ("method_declaration", "constructor_declaration"):
            break
        current = _ts_parent(current, parent_map)
    return node.start_point[1]


def _ts_is_async_js(node: Any, parent_map: dict[tuple, Any]) -> bool:
    """True if this JS/TS call is inside an async function/method."""
    current = _ts_parent(node, parent_map)
    while current is not None:
        if current.type in ("function_declaration", "function", "method_definition",
                             "arrow_function", "generator_function"):
            if current.children and current.children[0].text == b"async":
                return True
            return False
        current = _ts_parent(current, parent_map)
    return False


def _ts_extract_var_js(call_node: Any) -> str:
    """Extract the data variable from a JS/TS call_expression arguments list."""
    args = call_node.child_by_field_name("arguments")
    if not args:
        return ""
    for child in args.children:
        if child.type == "identifier":
            return child.text.decode("utf-8", errors="replace")
        # Handle object literal shorthand: { messages } or { messages: msgs }
        if child.type == "object":
            for prop in child.children:
                if prop.type == "pair":
                    key = prop.child_by_field_name("key")
                    val = prop.child_by_field_name("value")
                    if key and key.text.decode().lower() in _AST_DATA_KWARGS:
                        if val and val.type == "identifier":
                            return val.text.decode("utf-8", errors="replace")
                elif prop.type == "shorthand_property_identifier":
                    name = prop.text.decode("utf-8", errors="replace")
                    if name.lower() in _AST_DATA_KWARGS:
                        return name
    return ""


def _ts_extract_var_java(call_node: Any) -> str:
    """Extract the data variable from a Java method_invocation argument_list."""
    args = call_node.child_by_field_name("arguments")
    if not args:
        return ""
    for child in args.children:
        if child.type == "identifier":
            return child.text.decode("utf-8", errors="replace")
    return ""


# Maps file extension → (lang_name, is_java)
def _ts_attr_chain_go(node: Any) -> str:
    """Reconstruct the dotted method chain from a Go selector_expression or call_expression."""
    if node.type == "selector_expression":
        operand = node.child_by_field_name("operand")
        field = node.child_by_field_name("field")
        if operand and field:
            return f"{_ts_attr_chain_go(operand)}.{field.text.decode('utf-8', errors='replace')}"
    elif node.type == "call_expression":
        func = node.child_by_field_name("function")
        if func:
            return _ts_attr_chain_go(func)
    elif node.type == "identifier":
        return node.text.decode("utf-8", errors="replace")
    return ""


# Go contexts where inserting a statement BEFORE a call would break the code
_TS_GO_UNSAFE_TYPES = frozenset({
    "composite_literal",   # SomeType{Field: call()} — can't insert before
    "keyed_element",        # Field: call() inside a composite literal
})


def _ts_is_unsafe_go(node: Any, parent_map: dict[tuple, Any]) -> bool:
    current = _ts_parent(node, parent_map)
    while current is not None:
        if current.type in _TS_GO_UNSAFE_TYPES:
            return True
        if current.type in ("function_declaration", "method_declaration",
                             "func_literal", "go_statement"):
            break
        current = _ts_parent(current, parent_map)
    return False


def _ts_stmt_col_go(node: Any, parent_map: dict[tuple, Any]) -> int:
    """Column of the enclosing Go statement — the correct indent for the stub."""
    _GO_STMT = frozenset({
        "expression_statement", "short_var_declaration",
        "assignment_statement", "return_statement",
    })
    current = _ts_parent(node, parent_map)
    while current is not None:
        if current.type in _GO_STMT:
            return current.start_point[1]
        if current.type in ("function_declaration", "method_declaration", "func_literal"):
            break
        current = _ts_parent(current, parent_map)
    return node.start_point[1]


def _ts_extract_var_go(call_node: Any) -> str:
    """Extract the first meaningful identifier argument from a Go call_expression."""
    args = call_node.child_by_field_name("arguments")
    if not args:
        return ""
    for child in args.children:
        if child.type == "identifier":
            name = child.text.decode("utf-8", errors="replace")
            # Skip context.Background() / ctx — not the data variable
            if name not in ("ctx", "context", "nil"):
                return name
    return ""


# ── createAgent() detection for JS/TS (LangChain.js middleware insertion) ────
# Mirrors _create_agent_local_names / _is_create_agent_call / _detect_create_
# agent_calls for Python, but walks a tree-sitter tree instead of Python ast.
# Node shapes verified against a real parse with tree_sitter_typescript:
#   import_statement -> import_clause -> named_imports -> import_specifier
#     -> identifier [as identifier]           (aliased local name, if any)
#   import_statement.source is a `string` node wrapping a `string_fragment`
#   call_expression.arguments -> `arguments` node whose children include the
#     config `object` node (createAgent takes exactly one object argument)
#   object -> `pair` nodes, each with key/value fields
#   variable_declarator has name/value fields (const agent = createAgent(...))


def _ts_string_literal_value(node: Any) -> str:
    """Unquoted text of a tree-sitter `string` node, or "" if not a plain string."""
    for child in node.children:
        if child.type == "string_fragment":
            return child.text.decode("utf-8", errors="replace")
    return ""


def _ts_createagent_local_names(root_node: Any) -> set[str]:
    """Local names bound to createAgent via `import { createAgent [as X] }
    from "langchain"`. Always includes the literal name "createAgent" as a
    defensive default, matching _ts_is_create_agent_call's namespace-member
    fallback (agents.createAgent(...))."""
    names: set[str] = {"createAgent"}
    stack = [root_node]
    while stack:
        node = stack.pop()
        stack.extend(node.children)
        if node.type != "import_statement":
            continue
        source_node = node.child_by_field_name("source")
        if source_node is None or _ts_string_literal_value(source_node) != "langchain":
            continue
        clause = next((c for c in node.children if c.type == "import_clause"), None)
        if clause is None:
            continue
        named = next((c for c in clause.children if c.type == "named_imports"), None)
        if named is None:
            continue
        for spec in named.children:
            if spec.type != "import_specifier":
                continue
            idents = [g for g in spec.children if g.type == "identifier"]
            if not idents or idents[0].text.decode("utf-8", errors="replace") != "createAgent":
                continue
            local = idents[-1].text.decode("utf-8", errors="replace")
            names.add(local)
    return names


def _ts_is_create_agent_call(node: Any, local_names: set[str]) -> bool:
    """True for createAgent(...), an aliased import's call, or the
    namespace-member form (agents.createAgent(...))."""
    chain = _ts_attr_chain_js(node)
    return chain in local_names or chain.endswith(".createAgent")


def _ts_find_object_arg(call_node: Any) -> "Any | None":
    """First `object` node among a call_expression's arguments, or None —
    createAgent's sole argument is a config object; anything else (no args,
    a variable, a spread) means there is no literal shape to safely edit."""
    args_node = call_node.child_by_field_name("arguments")
    if args_node is None:
        return None
    for child in args_node.children:
        if child.type == "object":
            return child
    return None


def _ts_call_has_any_args(call_node: Any) -> bool:
    args_node = call_node.child_by_field_name("arguments")
    if args_node is None:
        return False
    return any(c.type not in ("(", ")", ",") for c in args_node.children)


def _ts_middleware_pair(obj_node: Any) -> "Any | None":
    """The `pair` node keyed "middleware" inside a config object, or None."""
    for child in obj_node.children:
        if child.type != "pair":
            continue
        key = child.child_by_field_name("key")
        if key is not None and key.text.decode("utf-8", errors="replace") == "middleware":
            return child
    return None


def _ts_detect_create_agent_calls(
    root_node: Any,
    parent_map: dict[tuple, Any],
    file_path: str = "",
) -> list["MiddlewareCandidate"]:
    """Find every createAgent(...) call, classify its middleware property,
    and record the variable it's assigned to (if any) — JS/TS analogue of
    _detect_create_agent_calls. kwarg_state has the same three values:
    "absent" (safe to insert a new middleware array), "literal_list" (safe
    to append to an existing array), "other" (dynamic/unknown shape — never
    auto-rewritten, instruction-only remediation instead)."""
    local_names = _ts_createagent_local_names(root_node)
    results: list[MiddlewareCandidate] = []

    stack = [root_node]
    while stack:
        node = stack.pop()
        stack.extend(node.children)
        if node.type != "call_expression":
            continue
        if not _ts_is_create_agent_call(node, local_names):
            continue

        lineno = node.start_point[0] + 1
        obj_node = _ts_find_object_arg(node)
        if obj_node is None:
            if _ts_call_has_any_args(node):
                kwarg_state = "other"
                instruction = (
                    f"manually add GuardrailMiddleware to the middleware array "
                    f"passed to createAgent() at line {lineno}"
                )
            else:
                kwarg_state = "absent"
                instruction = ""
        else:
            mw_pair = _ts_middleware_pair(obj_node)
            if mw_pair is None:
                kwarg_state = "absent"
                instruction = ""
            else:
                value = mw_pair.child_by_field_name("value")
                if value is not None and value.type == "array":
                    kwarg_state = "literal_list"
                    instruction = ""
                else:
                    kwarg_state = "other"
                    instruction = (
                        f"manually add GuardrailMiddleware to the middleware array "
                        f"passed to createAgent() at line {lineno}"
                    )

        assigned_var = ""
        parent = _ts_parent(node, parent_map)
        if parent is not None and parent.type == "variable_declarator":
            name_node = parent.child_by_field_name("name")
            if name_node is not None and name_node.type == "identifier":
                assigned_var = name_node.text.decode("utf-8", errors="replace")

        results.append(MiddlewareCandidate(
            file=file_path,
            line=lineno,
            end_line=node.end_point[0] + 1,
            kwarg_state=kwarg_state,
            assigned_var=assigned_var,
            instruction=instruction,
        ))

    return results


def _ts_needs_comma_prefix(text_before_insertion_point: str) -> bool:
    """JS/TS analogue of _needs_comma_prefix — False when the text already
    ends with a trailing comma or an opening bracket/brace with nothing
    after it (empty object/array), so inserting another leading comma there
    would produce ",," or "{," / "[," and break the syntax."""
    stripped = text_before_insertion_point.rstrip()
    return not (stripped.endswith(",") or stripped.endswith("{") or stripped.endswith("["))


def _ts_rewrite_create_agent_absent(source: str, call_node: Any) -> str:
    """Insert `middleware: [GuardrailMiddleware]` into a createAgent(...)
    call whose config object has no middleware property — or which has no
    config object argument at all (createAgent() with zero arguments; any
    other non-object argument shape is classified "other" upstream and
    never reaches this function). JS/TS analogue of
    _rewrite_create_agent_absent: byte-offset text splicing instead of
    ast.get_source_segment, same rationale (robust against multiple
    textually-identical calls elsewhere in the file — the tree-sitter node's
    own byte offsets pin the exact occurrence, not a string search)."""
    source_bytes = source.encode("utf-8")
    obj_node = _ts_find_object_arg(call_node)

    if obj_node is not None:
        idx = obj_node.end_byte - 1  # byte position of the closing "}"
        before = source_bytes[obj_node.start_byte:idx].decode("utf-8", errors="replace")
        prefix = ", " if _ts_needs_comma_prefix(before) else ""
        insertion = f"{prefix}middleware: [GuardrailMiddleware]".encode("utf-8")
        new_bytes = source_bytes[:idx] + insertion + source_bytes[idx:]
        return new_bytes.decode("utf-8", errors="replace")

    args_node = call_node.child_by_field_name("arguments")
    open_idx = args_node.start_byte + 1  # just after the call's "("
    insertion = b"{ middleware: [GuardrailMiddleware] }"
    new_bytes = source_bytes[:open_idx] + insertion + source_bytes[open_idx:]
    return new_bytes.decode("utf-8", errors="replace")


def _ts_rewrite_create_agent_literal_list(source: str, call_node: Any) -> str:
    """Append GuardrailMiddleware to an existing middleware: [...] array
    literal on a createAgent(...) call. JS/TS analogue of
    _rewrite_create_agent_literal_list — same byte-splice approach as
    _ts_rewrite_create_agent_absent."""
    obj_node = _ts_find_object_arg(call_node)
    mw_pair = _ts_middleware_pair(obj_node) if obj_node is not None else None
    array_node = mw_pair.child_by_field_name("value") if mw_pair is not None else None
    if array_node is None or array_node.type != "array":
        raise ValueError("createAgent(...) call has no middleware: [...] array literal to extend")

    source_bytes = source.encode("utf-8")
    idx = array_node.end_byte - 1  # byte position of the closing "]"
    before = source_bytes[array_node.start_byte:idx].decode("utf-8", errors="replace")
    prefix = ", " if _ts_needs_comma_prefix(before) else ""
    insertion = f"{prefix}GuardrailMiddleware".encode("utf-8")
    new_bytes = source_bytes[:idx] + insertion + source_bytes[idx:]
    return new_bytes.decode("utf-8", errors="replace")


_TS_LANG_MAP: dict[str, tuple[str, bool]] = {
    ".js":   ("javascript", False),
    ".jsx":  ("jsx",        False),
    ".ts":   ("typescript", False),
    ".tsx":  ("tsx",        False),
    ".java": ("java",       True),
    ".go":   ("go",         False),
}


def _ts_load_language(lang_name: str) -> "Any | None":
    """Load the tree-sitter Language for the given lang_name.

    Returns None if the grammar package is not installed.
    """
    try:
        from tree_sitter import Language
        if lang_name in ("javascript", "jsx"):
            import tree_sitter_javascript as _g
            return Language(_g.language())
        if lang_name in ("typescript",):
            import tree_sitter_typescript as _g
            return Language(_g.language_typescript())
        if lang_name == "tsx":
            import tree_sitter_typescript as _g
            return Language(_g.language_tsx())
        if lang_name == "java":
            import tree_sitter_java as _g
            return Language(_g.language())
        if lang_name == "go":
            import tree_sitter_go as _g
            return Language(_g.language())
    except (ImportError, AttributeError, TypeError):
        return None
    return None


# ── JS/TS definite-assignment analysis (tree-sitter port of _da_* below) ────
# Same algorithm and function shapes as the Python _da_* family (see
# _is_definitely_assigned / _da_analyze_block and neighbors) — ported to
# tree-sitter's CST instead of Python's ast module so JS/TS auto-writes get
# the same "is this variable bound on EVERY control-flow path reaching the
# insertion point" guarantee Python already has, instead of the previous
# "a name was found nearby" heuristic. Node types and field names verified
# against the actual installed tree-sitter-javascript and tree-sitter-typescript
# grammars (both differ subtly — e.g. typescript wraps function parameters in
# required_parameter/optional_parameter with a "pattern" field; plain
# javascript does not — handled generically below).

_TSDA_EXIT_TYPES = frozenset({"return_statement", "throw_statement", "continue_statement", "break_statement"})
_TSDA_COMPOUND_TYPES = frozenset({
    "if_statement", "try_statement", "for_statement", "for_in_statement", "while_statement", "do_statement",
})
# Same function-boundary type set already relied on elsewhere in this file
# (see _ts_is_unsafe_js / _ts_is_async_js) — kept identical for consistency.
_TSDA_FUNCTION_TYPES = frozenset({
    "function_declaration", "function", "method_definition", "arrow_function",
    "generator_function", "generator_function_declaration",
})


def _tsda_stmt_range(node) -> tuple[int, int]:
    return node.start_point[0] + 1, node.end_point[0] + 1


def _tsda_add_target(node, names: set) -> None:
    """Add every name bound by a JS/TS binding pattern (identifier, object/array
    destructuring, rest, default value) to `names`. Mirrors _da_add_target."""
    if node is None:
        return
    t = node.type
    if t == "identifier":
        names.add(node.text.decode("utf-8", errors="replace"))
    elif t == "shorthand_property_identifier_pattern":
        names.add(node.text.decode("utf-8", errors="replace"))
    elif t == "object_pattern":
        for c in node.children:
            if not c.is_named:
                continue
            if c.type == "shorthand_property_identifier_pattern":
                names.add(c.text.decode("utf-8", errors="replace"))
            elif c.type == "pair_pattern":
                val = c.child_by_field_name("value")
                _tsda_add_target(val, names)
            elif c.type in ("object_assignment_pattern", "rest_pattern"):
                _tsda_add_target(c, names)
    elif t == "array_pattern":
        for c in node.children:
            if c.is_named:
                _tsda_add_target(c, names)
    elif t == "rest_pattern":
        for c in node.children:
            if c.is_named:
                _tsda_add_target(c, names)
    elif t in ("object_assignment_pattern", "assignment_pattern"):
        # Destructuring/parameter default: `{b = 1}` or `[a = 1]` or `(x = 1)`
        # — the bound name is the left side, regardless of the default value.
        _tsda_add_target(node.child_by_field_name("left"), names)


def _tsda_assign_targets_in_subtree(node, names: set) -> None:
    """Names bound by any assignment_expression anywhere within `node` (an
    arbitrary expression, e.g. an if/while condition or a declarator's
    initializer) — bound as soon as that expression is evaluated, regardless
    of which branch runs afterward. Mirrors _da_named_expr_targets (JS has no
    walrus operator, but `if ((data = foo()))`-style assignment-in-condition
    is the equivalent idiom). Does not stop at nested function boundaries —
    matches the Python original's same imprecision for parity, not a
    deliberate design choice."""
    if node is None:
        return
    stack = [node]
    while stack:
        n = stack.pop()
        if n.type == "assignment_expression":
            _tsda_add_target(n.child_by_field_name("left"), names)
        stack.extend(n.children)


def _tsda_simple_assign_targets(stmt) -> set:
    """Names unconditionally bound by a single simple (non-compound) JS/TS
    statement. Mirrors _da_simple_assign_targets."""
    names: set = set()
    t = stmt.type
    if t in ("lexical_declaration", "variable_declaration"):
        for c in stmt.children:
            if c.type == "variable_declarator":
                value = c.child_by_field_name("value")
                if value is not None:
                    # Only a declarator WITH an initializer counts as an
                    # assignment — `let data;` alone does not bind a value,
                    # same as Python's AnnAssign requiring stmt.value is not
                    # None. Getting this wrong makes every later declared-
                    # but-uninitialized variable trivially "assigned" from
                    # its declaration line on, defeating the whole check.
                    _tsda_add_target(c.child_by_field_name("name"), names)
                    _tsda_assign_targets_in_subtree(value, names)
    elif t == "expression_statement":
        for c in stmt.children:
            if c.type == "assignment_expression":
                _tsda_assign_targets_in_subtree(c, names)
    elif t == "import_statement":
        for c in stmt.children:
            if c.type != "import_clause":
                continue
            for ic in c.children:
                if ic.type == "identifier":
                    # bare default import: `import foo from "mod"`
                    names.add(ic.text.decode("utf-8", errors="replace"))
                elif ic.type == "namespace_import":
                    ids = [x for x in ic.children if x.type == "identifier"]
                    if ids:
                        names.add(ids[-1].text.decode("utf-8", errors="replace"))
                elif ic.type == "named_imports":
                    for spec in ic.children:
                        if spec.type != "import_specifier":
                            continue
                        ids = [x for x in spec.children if x.type == "identifier"]
                        if ids:
                            # `{ a }` -> one identifier (local = a);
                            # `{ b as c }` -> two identifiers, local is the last.
                            names.add(ids[-1].text.decode("utf-8", errors="replace"))
    elif t == "class_declaration":
        name_node = stmt.child_by_field_name("name")
        if name_node is not None:
            names.add(name_node.text.decode("utf-8", errors="replace"))
    return names


def _tsda_func_param_names(fn_node) -> set:
    """Mirrors _da_func_param_names. Handles both grammar shapes: plain
    javascript/jsx puts the pattern directly as a formal_parameters child;
    typescript/tsx wraps it in required_parameter/optional_parameter with a
    "pattern" field."""
    names: set = set()
    params = fn_node.child_by_field_name("parameters")
    if params is None:
        return names
    for c in params.children:
        if not c.is_named:
            continue
        pattern = c
        if c.type in ("required_parameter", "optional_parameter"):
            pattern = c.child_by_field_name("pattern") or c
        if pattern.type in ("assignment_pattern", "object_assignment_pattern"):
            _tsda_add_target(pattern.child_by_field_name("left"), names)
        else:
            _tsda_add_target(pattern, names)
    return names


def _tsda_block_stmts(block_node) -> list:
    """Named (non-punctuation) children of a statement_block — the actual
    statement list, filtered generically via is_named so this holds across
    grammar variants without listing every punctuation token by name."""
    if block_node is None:
        return []
    return [c for c in block_node.children if c.is_named]


def _tsda_analyze_if(stmt, name: str) -> tuple[str, bool]:
    """Analyze a complete if/else-if/.../else chain as a single unit — used
    when the whole statement executes before the target line. Mirrors
    _da_analyze_if."""
    test_names: set = set()
    _tsda_assign_targets_in_subtree(stmt.child_by_field_name("condition"), test_names)

    body_status, body_assigned = _tsda_analyze_block(
        _tsda_block_stmts(stmt.child_by_field_name("consequence")), name, None
    )
    alt = stmt.child_by_field_name("alternative")  # else_clause, or None
    if alt is not None:
        alt_body = next((c for c in alt.children if c.is_named), None)
        if alt_body is not None and alt_body.type == "if_statement":
            else_status, else_assigned = _tsda_analyze_if(alt_body, name)
        else:
            else_status, else_assigned = _tsda_analyze_block(_tsda_block_stmts(alt_body), name, None)
    else:
        else_status, else_assigned = "fell_through", False

    body_assigned = body_assigned or (name in test_names)
    else_assigned = else_assigned or (name in test_names)

    if body_status == "exited" and else_status == "exited":
        return "exited", False
    if body_status == "exited":
        return "fell_through", else_assigned
    if else_status == "exited":
        return "fell_through", body_assigned
    return "fell_through", (body_assigned and else_assigned)


def _tsda_analyze_try(stmt, name: str) -> tuple[str, bool]:
    """Mirrors _da_analyze_try."""
    body_status, body_assigned = _tsda_analyze_block(_tsda_block_stmts(stmt.child_by_field_name("body")), name, None)

    handler = stmt.child_by_field_name("handler")  # catch_clause, or None
    handler_results = []
    if handler is not None:
        param = handler.child_by_field_name("parameter")
        seed = set()
        if param is not None:
            _tsda_add_target(param, seed)
        handler_results.append(
            _tsda_analyze_block(_tsda_block_stmts(handler.child_by_field_name("body")), name, None, seed=seed or None)
        )

    non_exited_assigned = []
    all_exited = True
    if body_status != "exited":
        all_exited = False
        non_exited_assigned.append(body_assigned)
    for h_status, h_assigned in handler_results:
        if h_status != "exited":
            all_exited = False
            non_exited_assigned.append(h_assigned)

    finalizer = stmt.child_by_field_name("finalizer")  # finally_clause, or None
    if finalizer is not None:
        fin_status, fin_assigned = _tsda_analyze_block(
            _tsda_block_stmts(finalizer.child_by_field_name("body")), name, None
        )
        if fin_status == "exited":
            return "fell_through", fin_assigned
        if fin_assigned:
            return "fell_through", True

    if all_exited:
        return "exited", False
    if not non_exited_assigned:
        return "fell_through", False
    return "fell_through", all(non_exited_assigned)


def _tsda_analyze_block(stmts: list, name: str, target_lineno: "int | None", seed: "set | None" = None) -> tuple[str, bool]:
    """Process a straight-line list of JS/TS statements. Mirrors _da_analyze_block
    exactly — see its docstring for the (status, assigned) contract."""
    assigned = bool(seed and name in seed)
    for stmt in stmts:
        s_start, s_end = _tsda_stmt_range(stmt)

        if target_lineno is not None and target_lineno <= s_start:
            return "reached", assigned

        is_compound = stmt.type in _TSDA_COMPOUND_TYPES
        if target_lineno is not None and s_start <= target_lineno <= s_end and (is_compound or target_lineno > s_start):
            if stmt.type == "if_statement":
                return _tsda_analyze_into_if(stmt, name, target_lineno, assigned)
            if stmt.type == "try_statement":
                return _tsda_analyze_into_try(stmt, name, target_lineno, assigned)
            if stmt.type in ("for_statement", "for_in_statement", "while_statement", "do_statement"):
                # 0-iteration risk: the body may never run, so a target line
                # inside it can never be "definitely assigned" from before —
                # only the loop's own iteration variable is (lenient, same as
                # Python's treatment of For/AsyncFor/While).
                loop_seed: set = set()
                if stmt.type == "for_in_statement":
                    _tsda_add_target(stmt.child_by_field_name("left"), loop_seed)
                body = stmt.child_by_field_name("body")
                status, _inner = _tsda_analyze_block(_tsda_block_stmts(body), name, target_lineno, seed=loop_seed)
                if status == "reached":
                    return "reached", name in loop_seed
                return "reached", assigned
            return "reached", assigned

        if stmt.type in _TSDA_EXIT_TYPES:
            return "exited", assigned
        if stmt.type in ("function_declaration", "generator_function_declaration"):
            fn_name = stmt.child_by_field_name("name")
            if fn_name is not None:
                assigned = assigned or (name == fn_name.text.decode("utf-8", errors="replace"))
            continue
        if stmt.type == "if_statement":
            status, new_assigned = _tsda_analyze_if(stmt, name)
            if status == "exited":
                return "exited", assigned
            assigned = assigned or new_assigned
            continue
        if stmt.type == "try_statement":
            status, new_assigned = _tsda_analyze_try(stmt, name)
            if status == "exited":
                return "exited", assigned
            assigned = assigned or new_assigned
            continue
        if stmt.type in ("for_statement", "for_in_statement", "while_statement", "do_statement"):
            continue  # body may run zero times; never contributes definite assignment
        assigned = assigned or (name in _tsda_simple_assign_targets(stmt))

    return "fell_through", assigned


def _tsda_analyze_into_if(stmt, name: str, target_lineno: int, incoming_assigned: bool) -> tuple[str, bool]:
    """Mirrors _da_analyze_into_if."""
    test_names: set = set()
    _tsda_assign_targets_in_subtree(stmt.child_by_field_name("condition"), test_names)
    seed_extra = incoming_assigned or (name in test_names)
    seed = {name} if seed_extra else None

    body_status, body_assigned = _tsda_analyze_block(
        _tsda_block_stmts(stmt.child_by_field_name("consequence")), name, target_lineno, seed=seed
    )
    if body_status == "reached":
        return "reached", body_assigned

    alt = stmt.child_by_field_name("alternative")
    if alt is not None:
        alt_body = next((c for c in alt.children if c.is_named), None)
        if alt_body is not None and alt_body.type == "if_statement":
            # else-if chain — recurse the same way Python recurses into nested If.orelse
            status, assigned2 = _tsda_analyze_into_if(alt_body, name, target_lineno, incoming_assigned)
            if status == "reached":
                return "reached", assigned2
        else:
            else_status, else_assigned = _tsda_analyze_block(
                _tsda_block_stmts(alt_body), name, target_lineno, seed=seed
            )
            if else_status == "reached":
                return "reached", else_assigned
    return "reached", incoming_assigned


def _tsda_analyze_into_try(stmt, name: str, target_lineno: int, incoming_assigned: bool) -> tuple[str, bool]:
    """Mirrors _da_analyze_into_try."""
    blocks = [(_tsda_block_stmts(stmt.child_by_field_name("body")), None)]
    handler = stmt.child_by_field_name("handler")
    if handler is not None:
        extra = set()
        param = handler.child_by_field_name("parameter")
        if param is not None:
            _tsda_add_target(param, extra)
        blocks.append((_tsda_block_stmts(handler.child_by_field_name("body")), extra or None))
    finalizer = stmt.child_by_field_name("finalizer")
    if finalizer is not None:
        blocks.append((_tsda_block_stmts(finalizer.child_by_field_name("body")), None))

    for block, extra_seed in blocks:
        seed = {name} if incoming_assigned else set()
        if extra_seed:
            seed |= extra_seed
        status, assigned = _tsda_analyze_block(block, name, target_lineno, seed=seed)
        if status == "reached":
            return "reached", assigned
    return "reached", incoming_assigned


def _tsda_find_enclosing_scope(root_node, target_lineno: int) -> tuple[list, set]:
    """Return (stmts, initial_seed_names) for the innermost function (or
    module/program) containing target_lineno. Mirrors _da_find_enclosing_scope.

    Unlike the Python port's first draft (a manual field-by-field descent
    through if/try/for bodies), this walks the WHOLE subtree collecting every
    function-like node whose [start_line, end_line] span contains
    target_lineno, then picks the one with the smallest span (most deeply
    nested = innermost). A manual container-aware descent has to enumerate
    every place a function can be embedded (variable declarator initializer,
    call argument/callback, object property value, array element, IIFE,
    default parameter value, ...) and will always miss some — e.g. it missed
    `const f = (x) => { ... }`, where the arrow function lives inside a
    variable_declarator's "value" field, not any of the if/try/for container
    fields. A full-tree scan can't miss a shape like that because it doesn't
    need to know the container at all."""
    program_stmts = _tsda_block_stmts(root_node) if root_node.type == "program" else list(root_node.children)

    best_node = None
    best_span = None
    stack = [root_node]
    while stack:
        n = stack.pop()
        if n.type in _TSDA_FUNCTION_TYPES:
            s, e = _tsda_stmt_range(n)
            if s <= target_lineno <= e:
                span = e - s
                if best_span is None or span < best_span:
                    best_span, best_node = span, n
        stack.extend(n.children)

    if best_node is None:
        return program_stmts, set()

    body = best_node.child_by_field_name("body")
    inner_stmts = _tsda_block_stmts(body) if body is not None and body.type == "statement_block" else []
    return inner_stmts, _tsda_func_param_names(best_node)


def _ts_is_definitely_assigned(root_node, name: str, before_line: int) -> bool:
    """Is `name` guaranteed bound on EVERY control-flow path reaching line
    `before_line` (exclusive), within the innermost enclosing function (or
    module scope)? Mirrors _is_definitely_assigned, ported to tree-sitter."""
    scope_stmts, seed = _tsda_find_enclosing_scope(root_node, before_line)
    _status, assigned = _tsda_analyze_block(scope_stmts, name, before_line, seed=seed)
    return assigned


def _validate_stub_insertion_ts(
    source: str,
    stub_line: str,
    insert_before_line: int,
    variable: str,
    lang_name: str,
    insert_after: bool = False,
) -> tuple[bool, str]:
    """Validate inserting stub_line before insert_before_line is safe, for
    JS/TS. Mirrors _validate_stub_insertion (see its docstring for the exact
    two-check contract); ported to tree-sitter instead of Python's ast module.

    Check 1: splice stub_line into the source and re-parse with tree-sitter —
    tree.root_node.has_error (tree-sitter's built-in error-recovery flag) is
    the direct analog of ast.parse() raising SyntaxError.
    Check 2: verify `variable` is DEFINITELY assigned on every path reaching
    the effective insertion point — checked against the ORIGINAL (pre-
    insertion) source, same as the Python version, since line numbers up to
    and including insert_before_line are unaffected by an insertion at or
    just after that line.
    """
    source_lines = source.splitlines(keepends=True)
    if source_lines and not source_lines[-1].endswith("\n"):
        source_lines[-1] += "\n"

    insert_idx = insert_before_line - 1
    if insert_idx < 0 or insert_idx > len(source_lines):
        return False, (
            f"insertion index {insert_before_line} is out of file bounds "
            f"({len(source_lines)} lines)"
        )

    trial = list(source_lines)
    stub_source_lines = [
        (l if l.endswith("\n") else l + "\n")
        for l in stub_line.splitlines()
    ]
    for i, sl in enumerate(stub_source_lines):
        trial.insert(insert_idx + i, sl)

    language = _ts_load_language(lang_name)
    if language is None:
        # Grammar unavailable at validation time (shouldn't happen — the
        # caller only reaches here after successfully parsing with this same
        # grammar — but fail safe rather than crash if it ever does).
        return True, ""
    from tree_sitter import Parser
    parser = Parser(language)

    trial_tree = parser.parse("".join(trial).encode("utf-8", errors="replace"))
    if trial_tree.root_node.has_error:
        return False, f"syntax error after stub insertion (line {insert_before_line})"

    if variable:
        original_tree = parser.parse(source.encode("utf-8", errors="replace"))
        effective_line = insert_before_line + 1 if insert_after else insert_before_line
        if not _ts_is_definitely_assigned(original_tree.root_node, variable, effective_line):
            return False, (
                f"variable '{variable}' is not assigned on every path "
                f"reaching line {insert_before_line}; it may be defined only in "
                "some branches, in a different scope, or later — review before inserting"
            )

    return True, ""


def _scan_file_treesitter(
    file_path: str,
    source: str,
    lang_name: str,
    is_java: bool,
    lineaje_pat: str,
    insertion_point_types: "list[str] | None",
    policy_map: "dict[str, list[str]] | None",
    companion_hops: int = 0,
) -> "tuple[list[InsertionCandidate], list[MiddlewareCandidate]] | None":
    """Tree-sitter AST scanner for JS / TS / Java / Go.

    Returns a (list[InsertionCandidate], list[MiddlewareCandidate]) tuple
    (same interface as the Python AST path) — the middleware list is always
    empty for Java/Go, since LangChain.js middleware detection only applies
    to JS/TS. Returns None if tree-sitter or the language grammar is not
    installed.
    """
    language = _ts_load_language(lang_name)
    if language is None:
        return None

    try:
        from tree_sitter import Parser
        parser = Parser(language)
    except Exception:
        return None

    source_bytes = source.encode("utf-8", errors="replace")
    tree = parser.parse(source_bytes)
    source_lines = source.splitlines()
    parent_map = _ts_build_parent_map(tree.root_node)

    is_go = lang_name == "go"
    is_js_ts = not is_java and not is_go
    call_node_type = "method_invocation" if is_java else "call_expression"
    file_ext = (
        ".java" if is_java else
        ".go"   if is_go   else
        ".tsx"  if lang_name == "tsx" else
        ".ts"   if lang_name == "typescript" else ".js"
    )

    middleware_candidates: list[MiddlewareCandidate] = []
    suppressed_vars: set[str] = set()
    if is_js_ts:
        middleware_candidates = _ts_detect_create_agent_calls(
            tree.root_node, parent_map, file_path=file_path
        )
        suppressed_vars = {mc.assigned_var for mc in middleware_candidates if mc.assigned_var}

    _STUB_MARKERS = (
        "gr_check(", "grCheck(", "GRBlockedError",
        "GR_SERVICE_URL", "LINEAJE_PAT", "GR_BEARER_TOKEN",
        "_gr_req", "_gr_resp", "_grUrl", "_grResp", "_grConn", '"insertion_point"',
        "_grPayload", "_grBearer",
        # Current VIII.5/VIII.6 stub shape (SiteDescriptor + .check()) — see
        # the sibling _STUB_MARKERS tuple's comment above for the gap this closes.
        "_lineaje_load_gr_client", "_gr_client.check(", "_gr_client.enforce(", "_gr_decision", "SiteDescriptor(",
    )
    _GUARD_WINDOW = 15

    def _already_guarded(lineno: int) -> bool:
        start = max(0, lineno - _GUARD_WINDOW - 1)
        end = min(len(source_lines), lineno + _GUARD_WINDOW)
        return any(
            any(m in source_lines[i] for m in _STUB_MARKERS)
            for i in range(start, end)
        )

    candidates: list[InsertionCandidate] = []
    seen_lines: set[int] = set()

    # Iterative tree walk (avoids Python recursion limit on large files)
    stack = [tree.root_node]
    while stack:
        node = stack.pop()
        # Push children first so we process in document order
        stack.extend(reversed(node.children))

        if node.type != call_node_type:
            continue

        lineno = node.start_point[0] + 1  # tree-sitter rows are 0-based
        if lineno in seen_lines:
            continue

        if is_java:
            chain = _ts_attr_chain_java(node)
        elif is_go:
            chain = _ts_attr_chain_go(node)
        else:
            chain = _ts_attr_chain_js(node)

        ip = _ts_classify(chain)
        if ip is None:
            continue
        if insertion_point_types is not None and ip not in insertion_point_types:
            continue

        if is_java:
            unsafe = _ts_is_unsafe_java(node, parent_map)
        elif is_go:
            unsafe = _ts_is_unsafe_go(node, parent_map)
        else:
            unsafe = _ts_is_unsafe_js(node, parent_map)
        if unsafe:
            continue
        if _already_guarded(lineno):
            continue
        # Suppression: skip calls on a variable already known to hold a
        # createAgent()-built agent — its traffic is covered by
        # GuardrailMiddleware instead of a per-call-site stub. Mirrors the
        # Python AST path's suppressed_vars check.
        if suppressed_vars and chain.split(".", 1)[0] in suppressed_vars:
            continue

        seen_lines.add(lineno)

        if is_java:
            var = _ts_extract_var_java(node)
        elif is_go:
            var = _ts_extract_var_go(node)
        else:
            var = _ts_extract_var_js(node)

        extraction_failed = not var
        if extraction_failed:
            var = "data"

        if is_java:
            col = _ts_stmt_col_java(node, parent_map)
        elif is_go:
            col = _ts_stmt_col_go(node, parent_map)
        else:
            col = _ts_stmt_col_js(node, parent_map)
        indent = " " * col
        is_async = False if (is_java or is_go) else _ts_is_async_js(node, parent_map)
        context_line = source_lines[lineno - 1] if lineno <= len(source_lines) else ""
        _ia = ip in _LHS_INSERTION_POINTS
        policy_reasons = list(policy_map.get(ip, [])) if policy_map else []
        policy_ids = [pr["policy_id"] for pr in policy_reasons]
        stub_line = _make_stub_line(
            var, ip, lineaje_pat, indent, file_ext, is_async=is_async, insert_after=_ia,
            candidate_policy_ids=policy_ids,
        )

        if extraction_failed:
            safe = False
            skip_reason = (
                "Variable could not be determined from AST — "
                "review and set the correct variable name before inserting."
            )
        elif is_java or is_go:
            # No AST-based validator for Java/Go yet (Phase 2 only covers
            # JS/TS) — fall back to the existing "a name was found" heuristic.
            safe = True
            skip_reason = ""
        else:
            safe, skip_reason = _validate_stub_insertion_ts(
                source, stub_line, lineno, var, lang_name, insert_after=_ia
            )

        candidates.append(InsertionCandidate(
            file=file_path,
            line=lineno,
            insertion_point=ip,
            pattern_matched=f"ast-ts:{chain[-60:]}",
            context_line=context_line,
            suggested_variable=var,
            description=f"Tree-sitter {lang_name} {ip} at line {lineno}, col {col}",
            proposed_stub=stub_line,
            safe_to_insert=safe,
            skip_reason=skip_reason,
            policy_ids=policy_ids,
            policy_reasons=policy_reasons,
            insert_after=_ia,
            variable_to_use_in_call="",
            companion_hops=companion_hops,
        ))

    return candidates, middleware_candidates


# ── Validation gate helpers ───────────────────────────────────────────────────


_EXIT_STMTS = (_ast.Return, _ast.Raise, _ast.Continue, _ast.Break)


def _da_stmt_range(stmt) -> tuple[int, int]:
    return stmt.lineno, getattr(stmt, "end_lineno", stmt.lineno)


def _da_add_target(t, names: set) -> None:
    if isinstance(t, _ast.Name):
        names.add(t.id)
    elif isinstance(t, (_ast.Tuple, _ast.List)):
        for elt in t.elts:
            _da_add_target(elt, names)
    elif isinstance(t, _ast.Starred):
        _da_add_target(t.value, names)


def _da_named_expr_targets(expr) -> set:
    """Walrus (:=) targets anywhere within `expr` — bound as soon as this
    expression is evaluated, regardless of which branch runs afterward."""
    names: set = set()
    if expr is None:
        return names
    for node in _ast.walk(expr):
        if isinstance(node, _ast.NamedExpr):
            _da_add_target(node.target, names)
    return names


def _da_simple_assign_targets(stmt) -> set:
    """Names unconditionally bound by a single simple (non-compound) statement."""
    names: set = set()
    if isinstance(stmt, _ast.Assign):
        for t in stmt.targets:
            _da_add_target(t, names)
        names |= _da_named_expr_targets(stmt.value)
    elif isinstance(stmt, _ast.AugAssign):
        _da_add_target(stmt.target, names)
    elif isinstance(stmt, _ast.AnnAssign) and stmt.value is not None:
        _da_add_target(stmt.target, names)
        names |= _da_named_expr_targets(stmt.value)
    elif isinstance(stmt, (_ast.Import, _ast.ImportFrom)):
        for alias in stmt.names:
            names.add(alias.asname or alias.name.split(".")[0])
    elif isinstance(stmt, (_ast.With, _ast.AsyncWith)):
        for item in stmt.items:
            if item.optional_vars is not None:
                _da_add_target(item.optional_vars, names)
    elif isinstance(stmt, _ast.Expr):
        names |= _da_named_expr_targets(stmt.value)
    elif isinstance(stmt, _ast.ClassDef):
        names.add(stmt.name)
    return names


def _da_func_param_names(fn) -> set:
    names: set = set()
    a = fn.args
    for arg in a.args + a.posonlyargs + a.kwonlyargs:
        names.add(arg.arg)
    if a.vararg:
        names.add(a.vararg.arg)
    if a.kwarg:
        names.add(a.kwarg.arg)
    return names


def _da_analyze_if(stmt: "_ast.If", name: str) -> tuple[str, bool]:
    """Analyze a complete if/elif/.../else chain as a single unit — used when
    the whole statement executes before the target line (not containing it)."""
    test_names = _da_named_expr_targets(stmt.test)
    body_status, body_assigned = _da_analyze_block(stmt.body, name, None)
    if stmt.orelse:
        else_status, else_assigned = _da_analyze_block(stmt.orelse, name, None)
    else:
        # No else: the "condition false" path skips the body, falling
        # through with whatever was assigned before the if.
        else_status, else_assigned = "fell_through", False

    body_assigned = body_assigned or (name in test_names)
    else_assigned = else_assigned or (name in test_names)

    if body_status == "exited" and else_status == "exited":
        return "exited", False
    if body_status == "exited":
        return "fell_through", else_assigned
    if else_status == "exited":
        return "fell_through", body_assigned
    return "fell_through", (body_assigned and else_assigned)


def _da_analyze_try(stmt: "_ast.Try", name: str) -> tuple[str, bool]:
    body_status, body_assigned = _da_analyze_block(stmt.body, name, None)
    handler_results = [
        _da_analyze_block(h.body, name, None, seed={h.name} if h.name else None)
        for h in stmt.handlers
    ]
    if stmt.orelse:
        else_status, else_assigned = _da_analyze_block(stmt.orelse, name, None)
    else:
        else_status, else_assigned = "fell_through", body_assigned

    non_exited_assigned = []
    all_exited = True
    if body_status != "exited":
        all_exited = False
        non_exited_assigned.append(else_assigned if stmt.orelse else body_assigned)
    for h_status, h_assigned in handler_results:
        if h_status != "exited":
            all_exited = False
            non_exited_assigned.append(h_assigned)

    if stmt.finalbody:
        fin_status, fin_assigned = _da_analyze_block(stmt.finalbody, name, None)
        if fin_status == "exited":
            return "fell_through", fin_assigned
        if fin_assigned:
            return "fell_through", True

    if all_exited:
        return "exited", False
    if not non_exited_assigned:
        return "fell_through", False
    return "fell_through", all(non_exited_assigned)


def _da_analyze_block(stmts, name: str, target_lineno: "int | None", seed: "set | None" = None) -> tuple[str, bool]:
    """Process a straight-line list of statements.

    target_lineno=None: process the WHOLE block unconditionally, returning
    ("exited"|"fell_through", assigned_at_end).

    target_lineno=int: stop as soon as it's reached, returning
    ("reached", assigned_so_far). If the block ends/exits first, returns
    ("fell_through"|"exited", assigned_at_end) so a parent block continues.
    """
    assigned = bool(seed and name in seed)
    for stmt in stmts:
        s_start, s_end = _da_stmt_range(stmt)

        if target_lineno is not None and target_lineno <= s_start:
            return "reached", assigned

        is_compound = isinstance(
            stmt, (_ast.If, _ast.Try, _ast.For, _ast.AsyncFor, _ast.While, _ast.With, _ast.AsyncWith)
        )
        if target_lineno is not None and s_start <= target_lineno <= s_end and (is_compound or target_lineno > s_start):
            if isinstance(stmt, _ast.If):
                return _da_analyze_into_if(stmt, name, target_lineno, assigned)
            if isinstance(stmt, _ast.Try):
                return _da_analyze_into_try(stmt, name, target_lineno, assigned)
            if isinstance(stmt, (_ast.With, _ast.AsyncWith)):
                with_names: set = set()
                for item in stmt.items:
                    if item.optional_vars is not None:
                        _da_add_target(item.optional_vars, with_names)
                status, inner_assigned = _da_analyze_block(stmt.body, name, target_lineno, seed=with_names)
                return status, assigned or inner_assigned
            if isinstance(stmt, (_ast.For, _ast.AsyncFor, _ast.While)):
                # Target is INSIDE this loop. The 0-iteration risk only
                # applies to code AFTER the loop (see the `continue` below).
                # If we reached a line in the body, this iteration ran, so:
                # the loop variable is bound, names already assigned before
                # the loop stay assigned, and body assignments that dominate
                # the target line count. Nested `for source in ...: print(source)`
                # inside `async for chunk` must not discard the inner result.
                loop_seed: set = {name} if assigned else set()
                if isinstance(stmt, (_ast.For, _ast.AsyncFor)):
                    _da_add_target(stmt.target, loop_seed)
                status, inner_assigned = _da_analyze_block(
                    stmt.body, name, target_lineno, seed=loop_seed,
                )
                if status == "reached":
                    return "reached", inner_assigned
                orelse = getattr(stmt, "orelse", None) or []
                if orelse:
                    else_status, else_assigned = _da_analyze_block(
                        orelse, name, target_lineno,
                        seed={name} if assigned else None,
                    )
                    if else_status == "reached":
                        return "reached", else_assigned
                return "reached", assigned
            return "reached", assigned

        if isinstance(stmt, _EXIT_STMTS):
            return "exited", assigned
        if isinstance(stmt, (_ast.FunctionDef, _ast.AsyncFunctionDef)):
            assigned = assigned or (name == stmt.name)
            continue
        if isinstance(stmt, _ast.If):
            status, new_assigned = _da_analyze_if(stmt, name)
            if status == "exited":
                return "exited", assigned
            assigned = assigned or new_assigned
            continue
        if isinstance(stmt, _ast.Try):
            status, new_assigned = _da_analyze_try(stmt, name)
            if status == "exited":
                return "exited", assigned
            assigned = assigned or new_assigned
            continue
        if isinstance(stmt, (_ast.With, _ast.AsyncWith)):
            status, new_assigned = _da_analyze_block(stmt.body, name, None)
            if status == "exited":
                return "exited", assigned
            assigned = assigned or new_assigned or (name in _da_simple_assign_targets(stmt))
            continue
        if isinstance(stmt, (_ast.For, _ast.AsyncFor, _ast.While)):
            continue  # body may run zero times; never contributes definite assignment
        assigned = assigned or (name in _da_simple_assign_targets(stmt))

    return "fell_through", assigned


def _da_analyze_into_if(stmt: "_ast.If", name: str, target_lineno: int, incoming_assigned: bool) -> tuple[str, bool]:
    test_names = _da_named_expr_targets(stmt.test)
    seed_extra = incoming_assigned or (name in test_names)
    body_status, body_assigned = _da_analyze_block(stmt.body, name, target_lineno, seed={name} if seed_extra else None)
    if body_status == "reached":
        return "reached", body_assigned
    if stmt.orelse:
        else_status, else_assigned = _da_analyze_block(
            stmt.orelse, name, target_lineno, seed={name} if seed_extra else None
        )
        if else_status == "reached":
            return "reached", else_assigned
    return "reached", incoming_assigned


def _da_analyze_into_try(stmt: "_ast.Try", name: str, target_lineno: int, incoming_assigned: bool) -> tuple[str, bool]:
    blocks = [(stmt.body, None)]
    for h in stmt.handlers:
        blocks.append((h.body, {h.name} if h.name else None))
    if stmt.orelse:
        blocks.append((stmt.orelse, None))
    if stmt.finalbody:
        blocks.append((stmt.finalbody, None))
    for block, extra_seed in blocks:
        seed = {name} if incoming_assigned else set()
        if extra_seed:
            seed |= extra_seed
        status, assigned = _da_analyze_block(block, name, target_lineno, seed=seed)
        if status == "reached":
            return "reached", assigned
    return "reached", incoming_assigned


def _da_find_enclosing_scope(tree: "_ast.Module", target_lineno: int) -> tuple[list, set]:
    """Return (body, initial_seed_names) for the innermost function (or
    module) containing target_lineno. Never recurses past the innermost
    enclosing function — sibling/outer functions' locals are out of scope."""
    best: tuple = (tree.body, set())
    found = False

    def visit(body, lineno) -> None:
        nonlocal best, found
        for stmt in body:
            s, e = _da_stmt_range(stmt)
            if not (s <= lineno <= e):
                continue
            found = True
            if isinstance(stmt, (_ast.FunctionDef, _ast.AsyncFunctionDef)):
                best = (stmt.body, _da_func_param_names(stmt))
                visit(stmt.body, lineno)
                return
            if isinstance(stmt, _ast.ClassDef):
                visit(stmt.body, lineno)
                return
            for field in ("body", "orelse", "finalbody"):
                nested = getattr(stmt, field, None)
                if nested:
                    visit(nested, lineno)
            for h in getattr(stmt, "handlers", []):
                visit(h.body, lineno)
            return

    visit(tree.body, target_lineno)
    if not found and target_lineno > 1:
        # No statement's range contains target_lineno anywhere in the tree —
        # this happens when the caller is asking "what's assigned right after
        # line N" (the insert_after=True effective_line = N + 1 check) and
        # line N is the very LAST line of its enclosing function. There's no
        # statement starting at N+1 to match against, so the lookup above
        # falls through with `best` left at its module-scope default, which
        # silently hides the real enclosing function's locals (e.g. a
        # parameter or an if/else that both assign the checked variable).
        # Retry one line earlier — that line is guaranteed to fall inside the
        # real scope — to find the correct enclosing function while still
        # analyzing up to the original (possibly out-of-range) target_lineno.
        # (Guarded by `found` rather than `best == (tree.body, set())` because
        # module scope is also the *legitimate* answer for plain top-level
        # statements — see test_function_name_itself.)
        visit(tree.body, target_lineno - 1)
    return best


def _is_definitely_assigned(source: str, name: str, before_line: int) -> bool:
    """Is `name` guaranteed bound on EVERY control-flow path that reaches
    line `before_line` (exclusive), within the innermost enclosing function
    (or module scope)? Replaces the old flat 'assigned anywhere earlier in
    the file' check, which produced false positives across function
    boundaries and ignored branching (if/else, try/except, loops)."""
    try:
        tree = _ast.parse(source)
    except SyntaxError:
        return False
    scope_body, seed = _da_find_enclosing_scope(tree, before_line)
    _status, assigned = _da_analyze_block(scope_body, name, before_line, seed=seed)
    if assigned or scope_body is tree.body:
        return assigned
    # Fallback: `name` might be a module-level global, not a local of the
    # innermost enclosing function — the check above only analyzes that
    # function's own body, so a genuine module-level global (read inside
    # any function, regardless of whether it's textually defined before or
    # after that function in the file — Python resolves free names via LEGB
    # at CALL time, and no function runs until the whole module has already
    # finished its own top-level execution) was incorrectly reported as
    # unassigned. Real bug found scanning a LangGraph project:
    # CHROMA_PERSIST_DIR = os.getenv(...) at module scope, read inside a
    # function defined elsewhere in the same file.
    _, module_assigned = _da_analyze_block(tree.body, name, None)
    return module_assigned


def _py_build_stmt_end_line_map(source: str) -> "dict[int, int] | None":
    """Map every source line number to the end_lineno of its innermost
    enclosing statement.

    Used by _validate_stub_insertion (via stmt_end_line) so insert_after=True
    checks the right effective line for MULTI-LINE statements — a real bug
    found scanning a LangChain project: `response = requests.post(\\n    url,\\n
    json=...,\\n)` was checked at `insert_before_line + 1` (the call's opening
    line + 1), which lands INSIDE the still-open argument list, not past the
    statement's real end — so `_is_definitely_assigned` correctly reported
    "not assigned yet" for a variable that WAS safely assigned by the time
    the statement actually completed. Confirmed directly: checking at line
    65 (opening line + 1) returned False; checking at line 69 (the real
    line after the statement ends) returned True, for the identical source.

    Returns None on SyntaxError — caller falls back to the old single-line
    assumption (insert_before_line + 1) rather than crash.
    """
    try:
        tree = _ast.parse(source)
    except SyntaxError:
        return None
    _STMT_TYPES = (
        _ast.Assign, _ast.AugAssign, _ast.AnnAssign, _ast.Expr,
        _ast.Return, _ast.Delete, _ast.Assert, _ast.Raise,
    )
    mapping: dict[int, int] = {}
    for node in _ast.walk(tree):
        if isinstance(node, _STMT_TYPES) and getattr(node, "end_lineno", None):
            for ln in range(node.lineno, node.end_lineno + 1):
                mapping[ln] = max(mapping.get(ln, node.end_lineno), node.end_lineno)
    return mapping


def _validate_stub_insertion(
    source: str,
    stub_line: str,
    insert_before_line: int,
    import_line: str,
    variable: str,
    insert_after: bool = False,
    stmt_end_line: "int | None" = None,
) -> tuple[bool, str]:
    """Validate inserting stub_line before insert_before_line is safe. Python-only.

    Check 1: Apply stub in memory, ast.parse() the result — SyntaxError → (False, reason).
    Check 2: Verify `variable` is DEFINITELY assigned on every path reaching the
    effective insertion point (branch-dominance, not just "assigned somewhere
    earlier in the file") — not guaranteed → (False, reason).

    insert_after=True means the real stub lands AFTER insert_before_line (LHS/
    result patterns) — the effective point to check assignment against is the
    line right after, so the matched line's own assignment counts.

    stmt_end_line: the enclosing statement's real end_lineno, when known
    (e.g. node.end_lineno from the AST path, or _py_build_stmt_end_line_map's
    lookup for the regex path) — required for insert_after=True to be correct
    on MULTI-LINE statements; see _py_build_stmt_end_line_map's docstring for
    the exact bug this fixes. Falls back to insert_before_line + 1 (correct
    only for single-line statements) when not provided, for backward
    compatibility with any caller that hasn't been updated yet.

    Returns (True, "") when all checks pass.
    """
    source_lines = source.splitlines(keepends=True)
    if source_lines and not source_lines[-1].endswith("\n"):
        source_lines[-1] += "\n"

    # insert_after must splice AFTER the full statement (stmt_end_line), not
    # before the opening line — otherwise a multi-line `response = client.post(`
    # trial either lands inside the argument list or accepts a candidate the
    # writer would then corrupt.
    if insert_after and stmt_end_line:
        insert_idx = stmt_end_line
    else:
        insert_idx = insert_before_line - 1
    if insert_idx < 0 or insert_idx > len(source_lines):
        return False, (
            f"insertion index {insert_before_line} is out of file bounds "
            f"({len(source_lines)} lines)"
        )

    trial = list(source_lines)
    stub_source_lines = [
        (l if l.endswith("\n") else l + "\n")
        for l in stub_line.splitlines()
    ]
    for i, sl in enumerate(stub_source_lines):
        trial.insert(insert_idx + i, sl)

    if import_line and import_line.strip() and import_line not in source:
        trial.insert(0, import_line + "\n")

    try:
        _ast.parse("".join(trial))
    except SyntaxError as e:
        return False, f"SyntaxError after stub insertion (line {e.lineno}): {e.msg}"

    # No "is this the fallback placeholder" special-case here: callers only
    # invoke this function once they've already confirmed real extraction
    # succeeded (see _scan_file_ast / scan_file's regex loop), so `variable`
    # is always a genuine name at this point — including the case where a
    # customer's code genuinely has a variable named "data". Excluding that
    # literal string here previously skipped the safety check entirely for
    # any real variable coincidentally named "data", silently marking
    # unverified stubs safe (the exact class of bug this validator exists
    # to catch).
    if variable:
        if insert_after:
            effective_line = (stmt_end_line + 1) if stmt_end_line else insert_before_line + 1
        else:
            effective_line = insert_before_line
        if not _is_definitely_assigned(source, variable, effective_line):
            return False, (
                f"variable '{variable}' is not assigned on every path "
                f"reaching line {insert_before_line}; it may be defined only in "
                "some branches, in a different scope, or later — review before inserting"
            )

    return True, ""


def _validate_hoist_stub_insertion(
    source: str,
    stub_line: str,
    insert_before_line: int,
    var: str,
    hoist: dict,
    import_line: str = "",
) -> tuple[bool, str]:
    """Trial-apply an inline-payload hoist (rewrite expression → temp, insert
    `{temp} = <expr>` + stub before the call) and ast.parse the result.

    The synthesized temp is assigned by the inserted block itself, so the
    path-assignment check used by `_validate_stub_insertion` does not apply.
    """
    lines = source.splitlines(keepends=True)
    if lines and not lines[-1].endswith("\n"):
        lines[-1] += "\n"
    _replace_source_span(
        lines,
        hoist["start_line"], hoist["start_col"],
        hoist["end_line"], hoist["end_col"],
        var,
    )
    insert_idx = insert_before_line - 1
    if insert_idx < 0 or insert_idx > len(lines):
        return False, (
            f"insertion index {insert_before_line} is out of file bounds "
            f"({len(lines)} lines)"
        )
    stub_source_lines = [
        (l if l.endswith("\n") else l + "\n")
        for l in stub_line.splitlines()
    ]
    for i, sl in enumerate(stub_source_lines):
        lines.insert(insert_idx + i, sl)
    if import_line and import_line.strip() and import_line not in source:
        lines.insert(0, import_line + "\n")
    try:
        _ast.parse("".join(lines))
    except SyntaxError as e:
        return False, f"SyntaxError after stub insertion (line {e.lineno}): {e.msg}"
    return True, ""


# insertion_point is no longer sent to the GR service — policy rubrics are
# written against source_type/destination_type directly (e.g. AI_APP_SEC_075:
# "destination_type is 'tool'"), and the server derives its internal
# insertion_point bucket (policy matching, fingerprinting) from this pair. This
# map is the single source of truth for that translation on the scanner side;
# unifai_guardrails/stub.py and gr_service/handlers/enforce.py each carry a
# reverse copy (they can't import this tool-side-only module).
_INSERTION_POINT_TO_SOURCE_DEST: dict[str, tuple[str, str]] = {
    "agent_to_llm": ("agent", "llm"),
    "llm_to_agent": ("llm", "agent"),
    "agent_to_agent": ("agent", "agent"),
    "db_read": ("database", "agent"),
    "api_call": ("api", "agent"),
    "file_upload": ("file_storage", "agent"),
    "mcp_call": ("agent", "tool"),
    "data_outbound": ("agent", "external"),
    "security_decision": ("agent", "policy_engine"),
    "risky_operation": ("agent", "system"),
    "skill_invocation": ("agent", "tool"),
    # Already-recognized insertion_point names elsewhere in this module
    # (_KNOWN_INSERTION_POINTS, _PHASE_AND_BOUNDARY_BY_INSERTION_POINT) that
    # had no wire-level (source_type, destination_type) pair at all — any
    # stub generated for one of these previously fell back silently to the
    # generic ("agent", "external") pair via _source_dest_for_insertion_point,
    # not a pair a policy rubric could actually match against.
    "tool_call": ("agent", "tool"),      # same wire pair as mcp_call — a
                                          # generic name for the same hop,
                                          # not MCP-specific (@gr: annotation
                                          # vocabulary)
    "tool_result": ("tool", "agent"),    # a tool's response flowing back to
                                          # the agent — the reverse of
                                          # tool_call/mcp_call, previously
                                          # absent entirely (no forward
                                          # mapping used "tool" as a SOURCE)
    "user_to_llm": ("user_interface", "llm"),
    "llm_to_user": ("llm", "user_interface"),
    "agent_to_ui": ("agent", "user_interface"),
    "ui_to_agent": ("user_interface", "agent"),
    "llm_to_ui": ("llm", "user_interface"),
    "ui_to_llm": ("user_interface", "llm"),
    # Finer-grained than agent_to_ui/ui_to_agent above: those two don't
    # distinguish "an agent/LLM authored this" from "a plain tool/handler
    # built this with no agent in the loop at all" — see
    # _guess_interaction_type, which _scan_pii_ui_exposure uses to pick
    # between these two on the egress side.
    "agent_to_user": ("agent", "user_interface"),
    "user_to_agent": ("user_interface", "agent"),
    "tool_to_user": ("tool", "user_interface"),
    "user_to_tool": ("user_interface", "tool"),
    "html_to_user": ("html", "user_interface"),
    "data_egress": ("agent", "user_interface"),
    "log_emit": ("agent", "log"),
}

# Reverse of the map above, for recognizing an EXISTING gr_check(var, "src", "dst")
# call and recovering its insertion_point (best-effort -- "mcp_call" and
# "skill_invocation" both map to ("agent", "tool") so that pair is ambiguous;
# first-inserted-wins in dict construction order, noted in find_existing_stub_calls).
_SOURCE_DEST_TO_INSERTION_POINT: dict[tuple[str, str], str] = {}
for _ip, _pair in _INSERTION_POINT_TO_SOURCE_DEST.items():
    _SOURCE_DEST_TO_INSERTION_POINT.setdefault(_pair, _ip)

_GR_CHECK_CALL_RE = re.compile(
    r'gr_check,?\s*\(?\s*[A-Za-z_][A-Za-z0-9_.]*\s*,\s*["\']([^"\']+)["\']\s*,\s*["\']([^"\']+)["\']\s*\)'
)


def find_existing_stub_calls(file_path: str) -> "list[dict]":
    """Scan a file for gr_check(var, "src", "dst") call sites already present in
    it -- i.e. guardrail stubs from a PRIOR insertion (this run or an earlier
    one), not candidates for a new insertion. Read-only, best-effort: returns []
    on any error. Each entry: {line, insertion_point} -- insertion_point is
    reverse-mapped from the (src, dst) pair and "unknown" if it doesn't match any
    of the known pairs (e.g. a hand-written or non-standard gr_check call)."""
    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as fh:
            lines = fh.readlines()
    except OSError:
        return []

    found: list[dict] = []
    for lineno, line in enumerate(lines, start=1):
        if "gr_check" not in line:
            continue
        m = _GR_CHECK_CALL_RE.search(line)
        if not m:
            continue
        src, dst = m.group(1), m.group(2)
        ip = _SOURCE_DEST_TO_INSERTION_POINT.get((src, dst), "unknown")
        found.append({"line": lineno, "insertion_point": ip})
    return found


def _source_dest_for_insertion_point(insertion_point: str) -> tuple[str, str]:
    """Best-effort mapping for insertion points outside the known 9 (e.g. a
    developer's custom @gr: annotation) — falls back to a generic agent-hop
    pair rather than raising, so an unrecognized name still produces a
    syntactically valid (if less specific) stub."""
    return _INSERTION_POINT_TO_SOURCE_DEST.get(insertion_point, ("agent", "external"))


def _policy_id_json_array(policy_ids: list[str]) -> str:
    """A bare `["A", "B"]` array literal — valid JSON, and valid array syntax
    in JS/TS, Go (as the element list inside `[]string{...}`), and Java (as
    the value half of a hand-built JSON string). Policy IDs are catalog
    identifiers (e.g. "AI_DAT_SEC_010"), but escaped defensively anyway rather
    than assumed safe."""
    escaped = [p.replace("\\", "\\\\").replace('"', '\\"') for p in policy_ids]
    return "[" + ", ".join(f'"{p}"' for p in escaped) + "]"


def _make_stub_line(
    variable: str,
    insertion_point: str,
    lineaje_pat: str,
    indent: str,
    file_ext: str = ".py",
    is_async: bool = False,
    insert_after: bool = False,
    candidate_policy_ids: list[str] | None = None,
    site_id: str | None = None,
) -> str:
    """Return a language-appropriate guardrail stub call (stdlib only, no external deps).

    Both insert_after=False (input/arg1 patterns — stub goes BEFORE the call) and
    insert_after=True (output/lhs patterns — stub goes AFTER the call) reassign
    `variable` in place. For input patterns the call being protected is the very
    next line, so it automatically receives the checked/masked value with no
    follow-up edit needed — a prior scoped-copy (`_gr_{variable}`) design required
    a second edit to point the real call at the copy, which could be skipped and
    silently defeat masking. For output patterns this was already the behavior:
    all downstream code should see the checked/masked result (e.g., DB rows after
    a fetchall should be masked for every consumer).

    candidate_policy_ids: policy IDs this insertion_point is content-mapped to
    AND has a real registered enforcement routine behind (see
    hardcoded_insertion_point_map()) — NOT the tenant's live enabled-policy set
    (that's a separate, stronger claim carried by guardrail_stub_insertion.py's
    own `enabled_policies=[...]` embedding, sourced from real Policy objects).
    Sent to the server as `candidate_policies` — an integrity/context hint only,
    never a substitute for the server's own policy resolution — mirroring the
    proposed wire contract's `candidate_policies` field (validate-only, never
    an input to policy selection). Omitted from the call entirely when empty,
    so every existing bare-call site and test is unaffected.
    """
    ext = file_ext.lower()
    out_var = variable
    src_type, dst_type = _source_dest_for_insertion_point(insertion_point)
    candidate_policy_ids = [p for p in (candidate_policy_ids or []) if p]

    if ext in (".js", ".ts", ".jsx", ".tsx"):
        # Calls gr_check()/GRBlockedError defined directly in this same file
        # (see _ts_gr_check_inline_source(), injected once per file by
        # _import_hint) instead of duplicating the full fetch + env +
        # error-handling logic at every call site. GRBlockedError is
        # distinguished from generic failures so a deliberate policy block
        # is never folded into fail-open (mirrors the fix already applied
        # to the Python branch below — see its comment for the full
        # incident this fixes).
        # gr_check()'s 6th positional param is a generic context object,
        # forwarded verbatim into the request body (see
        # _ts_gr_check_inline_source) — reached only by also passing the
        # tenantId/timeoutMs defaults positionally. Omitted entirely when
        # there are no candidate policies, so the bare 3-arg call (and every
        # test asserting its exact shape) is unaffected.
        _js_context_args = (
            f', "", 5000, {{ candidate_policies: {_policy_id_json_array(candidate_policy_ids)} }}'
            if candidate_policy_ids else ""
        )
        if is_async:
            return (
                f"{indent}try {{\n"
                f"{indent}  {out_var} = await gr_check({variable}, \"{src_type}\", \"{dst_type}\"{_js_context_args});\n"
                f"{indent}}} catch (_grExc) {{\n"
                f"{indent}  if (_grExc instanceof GRBlockedError) {{ throw _grExc; }}\n"
                f"{indent}  {out_var} = {variable};\n"
                f"{indent}  console.warn(\"Lineaje guardrail unavailable at '{src_type}->{dst_type}' — passing data through unchecked\");\n"
                f"{indent}}}"
            )
        # Sync context — cannot await, so this is fire-and-forget. A synchronous
        # call site fundamentally cannot block on or re-throw from gr_check()'s
        # async result, so a block decision here can only be logged loudly, not
        # enforced — flag that limitation instead of silently dropping it.
        return (
            f"{indent}void gr_check({variable}, \"{src_type}\", \"{dst_type}\"{_js_context_args}).catch((_grExc) => {{\n"
            f"{indent}  if (_grExc instanceof GRBlockedError) {{\n"
            f"{indent}    console.error(\"Lineaje: BLOCK at '{src_type}->{dst_type}' could not be enforced — call site is synchronous (fire-and-forget)\");\n"
            f"{indent}  }}\n"
            f"{indent}}}); // fire-and-forget (sync context)"
        )

    if ext == ".go":
        # grCheck() (see _go_gr_check_inline_source, injected once per file by
        # _import_hint) owns the full net/http + encoding/json request/fail-open
        # logic — the call site is now a single assignment instead of the ~19
        # lines of POST-building code that used to be duplicated at every site.
        # grCheck returns interface{}: in strongly-typed Go you'll still need a
        # type assertion (or to declare `variable` as interface{}) before this
        # compiles — same caveat the old inline block carried, just stated once.
        _go_cp_arg = (
            ", []string{" + ", ".join(f'"{p}"' for p in candidate_policy_ids) + "} /* candidate_policies */"
            if candidate_policy_ids else ", nil"
        )
        return (
            f"{indent}{out_var} = grCheck({variable}, \"{src_type}\", \"{dst_type}\"{_go_cp_arg}) "
            f"// Lineaje guardrail: policy-checks/masks {variable} at this boundary "
            f"({src_type}->{dst_type}); grCheck fails open and returns interface{{}} — "
            f"add a type assertion here if {variable} isn't already interface{{}} (see grCheck below)"
        )

    if ext == ".java":
        # GrClient.grCheck() (see _java_gr_check_inline_source, injected once per
        # file by _import_hint) owns the HttpURLConnection request-building logic
        # that used to be duplicated at every call site (~15-20 lines each). The
        # sync call site is now a single statement; the async one keeps the exact
        # same CompletableFuture/.join() shape as before (still needed: it's what
        # keeps the blocking HTTP call off the caller's original thread — see the
        # rationale kept on _java_gr_check_inline_source), just delegating the
        # actual request to the shared method instead of re-building it inline.
        _java_cp_arg = "null"
        if candidate_policy_ids:
            _java_items = ", ".join(
                '"%s"' % p.replace("\\", "\\\\").replace('"', '\\"') for p in candidate_policy_ids
            )
            _java_cp_arg = f"new String[]{{{_java_items}}} /* candidate_policies */"

        _java_check_call = (
            f'GrClient.grCheck({variable}, "{src_type}", "{dst_type}", {_java_cp_arg})'
        )

        if is_async:
            # Offloads the blocking HttpURLConnection call to a background
            # thread (CompletableFuture.supplyAsync, default ForkJoinPool.
            # commonPool() executor) instead of running it on the calling
            # thread directly — the same rationale as the Python branch's
            # `await asyncio.to_thread(...)`: a call site already inside an
            # async/reactive chain (CompletableFuture composition, a
            # WebFlux handler) must not block that thread with synchronous
            # network I/O. `.join()` still blocks — but the thread it blocks
            # is this background one, not the caller's original thread.
            # NOT safe inside a truly non-blocking reactive pipeline
            # (Project Reactor/WebFlux): .join() there still parks the
            # calling Reactor thread. A pipeline that genuinely can't block
            # at all should replace this stub with a non-blocking chain
            # (e.g. Mono.fromFuture(_grFuture)) instead of calling .join().
            return (
                f"{indent}try {{ // Lineaje guardrail: policy-check/mask {variable} off this thread\n"
                f"{indent}    java.util.concurrent.CompletableFuture<Object> _grFuture = "
                f"java.util.concurrent.CompletableFuture.supplyAsync(() -> {{\n"
                f"{indent}        try {{ return {_java_check_call}; }}\n"
                f"{indent}        catch (Exception _grInnerEx) {{ return {variable}; }} // Lineaje: fail-open inside the async task\n"
                f"{indent}    }});\n"
                f"{indent}    {variable} = _grFuture.join(); // Lineaje: blocks this background thread only, not the caller's original one\n"
                f"{indent}}} catch (Exception _grEx) {{ /* Lineaje: fail-open */ }}"
            )

        return (
            f"{indent}{_java_check_call}; "
            f"// Lineaje guardrail: policy-checks/masks {variable} at this boundary "
            f"({src_type}->{dst_type}) — TODO: capture & apply the returned value once "
            f"your JSON parsing is wired in (see GrClient.grCheck's own TODO)"
        )

    # Default: Python.
    # Calls gr_check() defined directly in this same file (see
    # _py_gr_check_inline_source(), injected once per file by _import_hint) —
    # no companion module, no path-based loader. The try/except here is the
    # fail-open guarantee: ANY failure (GR service unreachable, or anything
    # else) falls back to the original value instead of raising, so a
    # broken guardrail can never crash the app it's protecting.
    # GRBlockedError must NOT join the fail-open bucket: it is gr_check()'s signal
    # for a deliberate policy block from a *reachable* GR service (HTTP 403,
    # GR_BLOCK_MODE=enforce) — the exact opposite of "guardrail unavailable". A
    # bare `except Exception` here would catch it right alongside a genuine
    # network failure and silently pass the unfiltered data through either
    # way, making "enforce" mode inert at every call site. Checked by class name
    # (not `isinstance`) so this works even if gr_check itself is what raised.
    _warn = (
        f"{indent}    __import__(\"logging\").getLogger(\"lineaje.gr_client\").warning("
        f"\"Lineaje guardrail unavailable at '{src_type}->{dst_type}' — passing data through unchecked\")"
    )
    # gr_check()'s **context catches any extra kwarg and forwards it into the
    # request body verbatim (see _py_gr_check_inline_source) — omitted
    # entirely when there are no candidate policies, so the bare 3-arg call
    # (and every test asserting its exact shape) is unaffected.
    #
    # site_id (design doc Part III.0): "The context the stub carries — above
    # all its scan-time site_id — is what selects the routine at runtime."
    # Embedded the same way candidate_policies already is — an extra kwarg
    # forwarded verbatim by gr_check()'s **context — so /enforce's existing
    # site_id resolution path (Phase 6e) actually has something to resolve
    # once a stub reaches real customer code, not only in tests that call
    # /enforce directly with a hand-built request.
    _py_context_parts = []
    if candidate_policy_ids:
        _py_context_parts.append(f"candidate_policies={candidate_policy_ids!r}")
    if site_id:
        _py_context_parts.append(f"site_id={site_id!r}")
    _py_context_kwarg = (", " + ", ".join(_py_context_parts)) if _py_context_parts else ""
    if is_async:
        return (
            f"{indent}try:\n"
            f"{indent}    import asyncio as _gr_asyncio\n"
            f"{indent}    {out_var} = await _gr_asyncio.to_thread(gr_check, {variable}, \"{src_type}\", \"{dst_type}\"{_py_context_kwarg})\n"
            f"{indent}except Exception as _gr_exc:\n"
            f"{indent}    if type(_gr_exc).__name__ == \"GRBlockedError\": raise\n"
            f"{indent}    {out_var} = {variable}\n"
            f"{_warn}"
        )
    return (
        f"{indent}try:\n"
        f"{indent}    {out_var} = gr_check({variable}, \"{src_type}\", \"{dst_type}\"{_py_context_kwarg})\n"
        f"{indent}except Exception as _gr_exc:\n"
        f"{indent}    if type(_gr_exc).__name__ == \"GRBlockedError\": raise\n"
        f"{indent}    {out_var} = {variable}\n"
        f"{_warn}"
    )


def _py_gr_check_inline_source() -> str:
    """GRBlockedError + gr_check(), inlined once per instrumented file.

    Compact on purpose: this block is copied into customer source. Behavior
    is unchanged (fail-open unless HTTP 403 + GR_BLOCK_MODE=enforce).
    """
    return (
        "# Copyright (c) Lineaje, Inc. All rights reserved.\n"
        "# gr_check() POSTs to GR_SERVICE_URL+/enforce; fail-open unless GRBlockedError.\n"
        "class GRBlockedError(Exception):\n"
        "    def __init__(self, policy_id, reason):\n"
        "        self.policy_id, self.reason = policy_id, reason\n"
        "        super().__init__(\"Guardrail block for policy %r: %s\" % (policy_id, reason))\n"
        "\n"
        "def gr_check(data, source_type, destination_type, tenant_id=\"\", timeout=5.0, **context):\n"
        "    import json as _j, logging as _lg, os as _os, urllib.error as _ue, urllib.request as _ur\n"
        "    _log = _lg.getLogger(\"lineaje.gr_client\")\n"
        "    url = _os.environ.get(\"GR_SERVICE_URL\", \"\")\n"
        "    if not url:\n"
        "        return data\n"
        "    tid = tenant_id or _os.environ.get(\"GR_TENANT_ID\", \"\")\n"
        "    bearer = _os.environ.get(\"GR_BEARER_TOKEN\") or _os.environ.get(\"LINEAJE_PAT_TOKEN\") or _os.environ.get(\"LINEAJE_PAT\", \"\")\n"
        "    hop_label = source_type + \"->\" + destination_type\n"
        "    params_key = \"out_params\" if destination_type == \"agent\" else \"in_params\"\n"
        "    try:\n"
        "        headers = {\"Content-Type\": \"application/json\"}\n"
        "        if bearer:\n"
        "            headers[\"Authorization\"] = \"Bearer \" + bearer\n"
        "        body = {\"source_type\": source_type, \"destination_type\": destination_type, params_key: {\"data\": data}}\n"
        "        for _k, _v in context.items():\n"
        "            if _v:\n"
        "                body[_k] = _v\n"
        "        if tid:\n"
        "            body[\"tenant_id\"] = tid\n"
        "        req = _ur.Request(url.rstrip(\"/\") + \"/enforce\", data=_j.dumps(body).encode(), headers=headers, method=\"POST\")\n"
        "        with _ur.urlopen(req, timeout=timeout) as resp:\n"
        "            result = _j.loads(resp.read())\n"
        "    except Exception as exc:\n"
        "        if isinstance(exc, _ue.HTTPError) and exc.code == 403:\n"
        "            try: detail = _j.loads(exc.read()).get(\"detail\", {})\n"
        "            except Exception: detail = {}\n"
        "            blocked_by = detail.get(\"blocked_by\") or []\n"
        "            policy_id = blocked_by[0][\"policy_id\"] if blocked_by else \"unknown\"\n"
        "            reason = detail.get(\"message\", \"Request denied by policy enforcement.\")\n"
        "            _log.warning(\"gr_client[%s]: BLOCKED by policy=%s — %s\", hop_label, policy_id, reason)\n"
        "            if _os.environ.get(\"GR_BLOCK_MODE\", \"enforce\").lower() == \"audit\":\n"
        "                return data\n"
        "            raise GRBlockedError(policy_id, reason)\n"
        "        _log.warning(\"gr_client[%s]: GR service call failed (%s) — failing open\", hop_label, exc)\n"
        "        return data\n"
        "    if result.get(\"status\") == \"escalate\":\n"
        "        _log.warning(\"gr_client[%s]: escalation flagged — passing through for human review\", hop_label)\n"
        "    return result.get(\"result\", {}).get(\"data\", data)"
    )


def _go_gr_check_inline_source() -> str:
    """Full Go grCheck() helper, inlined directly into the instrumented file —
    injected once per file by _import_hint(), same "no companion module, no
    go.mod dependency" contract as the Python/TS inline blocks: bytes,
    encoding/json, net/http, os, time (all stdlib). Every call site used to
    carry its own ~19-line copy of this POST-building logic; now they call
    this one function instead.

    Fails open (returns `data` unchanged) on any missing config or
    connectivity/parsing error. Returns interface{} — Go's static typing
    means a real call site still needs a type assertion (or `variable`
    declared as interface{}) before this compiles, same caveat the old
    per-site inline block carried via its own "TODO: type-assert" comment."""
    return (
        "// Copyright (c) Lineaje, Inc. All rights reserved.\n"
        "// Lineaje guardrail helper — stdlib only (bytes, encoding/json, net/http, os, time).\n"
        "// grCheck POSTs data to GR_SERVICE_URL + \"/enforce\" and returns the (possibly\n"
        "// masked) response data, or `data` unchanged (fail-open) if GR_SERVICE_URL is unset\n"
        "// or the call fails. `data` and the return value are both interface{} — add a type\n"
        "// assertion at the call site if the target variable isn't already interface{}.\n"
        "func grCheck(data interface{}, sourceType string, destinationType string, candidatePolicies []string) interface{} {\n"
        "\turl := os.Getenv(\"GR_SERVICE_URL\") // Lineaje: guardrail endpoint; unset = fail-open below\n"
        "\tif url == \"\" {\n"
        "\t\treturn data // Lineaje: fail-open — GR_SERVICE_URL not configured\n"
        "\t}\n"
        "\tparamsKey := \"in_params\"\n"
        "\tif destinationType == \"agent\" {\n"
        "\t\tparamsKey = \"out_params\"\n"
        "\t}\n"
        "\tbody := map[string]interface{}{ // Lineaje: /enforce request body\n"
        "\t\t\"source_type\":      sourceType,\n"
        "\t\t\"destination_type\": destinationType,\n"
        "\t\tparamsKey:           map[string]interface{}{\"data\": data},\n"
        "\t}\n"
        "\tif len(candidatePolicies) > 0 {\n"
        "\t\tbody[\"candidate_policies\"] = candidatePolicies // Lineaje: validate-only context, never an enablement claim\n"
        "\t}\n"
        "\tpayload, _ := json.Marshal(body)\n"
        "\tbearer := os.Getenv(\"GR_BEARER_TOKEN\") // Lineaje: bearer precedence — GR_BEARER_TOKEN, then LINEAJE_PAT_TOKEN, then LINEAJE_PAT\n"
        "\tif bearer == \"\" {\n"
        "\t\tbearer = os.Getenv(\"LINEAJE_PAT_TOKEN\")\n"
        "\t}\n"
        "\tif bearer == \"\" {\n"
        "\t\tbearer = os.Getenv(\"LINEAJE_PAT\")\n"
        "\t}\n"
        "\treq, _ := http.NewRequest(http.MethodPost, url+\"/enforce\", bytes.NewReader(payload))\n"
        "\treq.Header.Set(\"Content-Type\", \"application/json\")\n"
        "\treq.Header.Set(\"Authorization\", \"Bearer \"+bearer)\n"
        "\tresp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req) // Lineaje: POST /enforce\n"
        "\tif err != nil {\n"
        "\t\treturn data // Lineaje: fail-open — GR service unreachable\n"
        "\t}\n"
        "\tdefer resp.Body.Close()\n"
        "\tvar out struct {\n"
        "\t\tResult map[string]interface{} `json:\"result\"`\n"
        "\t}\n"
        "\tif err := json.NewDecoder(resp.Body).Decode(&out); err != nil {\n"
        "\t\treturn data // Lineaje: fail-open — malformed /enforce response\n"
        "\t}\n"
        "\tif val, ok := out.Result[\"data\"]; ok {\n"
        "\t\treturn val // Lineaje: the (possibly masked) value the guardrail returned\n"
        "\t}\n"
        "\treturn data\n"
        "}\n"
    )


def _java_gr_check_inline_source() -> str:
    """Full Java GrClient.grCheck() helper, inlined directly into the
    instrumented file — injected once per file by _import_hint(), same
    "no companion module, no extra dependency" contract as the Python/TS/Go
    inline blocks: java.net.HttpURLConnection (JDK stdlib) only. Every call
    site used to carry its own ~15-20 line copy of this connection-building
    logic; now they call this one static method instead.

    Fails open (returns `data` unchanged) on any missing config or
    connectivity error — mirrors the original per-call-site behavior, which
    never parsed the response back into a return value either (see the TODO
    on the response-handling branch below); a real project wires in its own
    JSON library there."""
    return (
        "// Copyright (c) Lineaje, Inc. All rights reserved.\n"
        "class GrClient {\n"
        "    // Lineaje guardrail helper — java.net.HttpURLConnection (JDK stdlib), no extra\n"
        "    // dependency. POSTs to GR_SERVICE_URL + \"/enforce\"; fails open (returns `data`\n"
        "    // unchanged) on any missing config or connectivity error. `data` is serialized\n"
        "    // with toString() — for complex objects replace `objJson` with your project's\n"
        "    // JSON library call (Jackson: objectMapper.writeValueAsString(data)).\n"
        "    static Object grCheck(Object data, String sourceType, String destinationType, String[] candidatePolicies) {\n"
        "        String url = System.getenv(\"GR_SERVICE_URL\") != null ? System.getenv(\"GR_SERVICE_URL\") : \"\";\n"
        "        if (url.isEmpty()) {\n"
        "            return data; // Lineaje: fail-open — GR_SERVICE_URL not configured\n"
        "        }\n"
        "        try {\n"
        "            java.net.HttpURLConnection conn = (java.net.HttpURLConnection) new java.net.URL(url + \"/enforce\").openConnection();\n"
        "            conn.setRequestMethod(\"POST\");\n"
        "            conn.setDoOutput(true);\n"
        "            conn.setConnectTimeout(5000);\n"
        "            conn.setReadTimeout(5000);\n"
        "            conn.setRequestProperty(\"Content-Type\", \"application/json\");\n"
        "            String bearer = System.getenv(\"GR_BEARER_TOKEN\") != null ? System.getenv(\"GR_BEARER_TOKEN\") :\n"
        "                (System.getenv(\"LINEAJE_PAT_TOKEN\") != null ? System.getenv(\"LINEAJE_PAT_TOKEN\") :\n"
        "                (System.getenv(\"LINEAJE_PAT\") != null ? System.getenv(\"LINEAJE_PAT\") : \"\")); // Lineaje: bearer precedence\n"
        "            conn.setRequestProperty(\"Authorization\", \"Bearer \" + bearer);\n"
        "            String objJson = data.toString(); // TODO: replace with your JSON library's serialize(data)\n"
        "            String paramsKey = destinationType.equals(\"agent\") ? \"out_params\" : \"in_params\";\n"
        "            StringBuilder cpJson = new StringBuilder();\n"
        "            if (candidatePolicies != null && candidatePolicies.length > 0) { // Lineaje: validate-only context\n"
        "                cpJson.append(\",\\\"candidate_policies\\\":[\");\n"
        "                for (int i = 0; i < candidatePolicies.length; i++) {\n"
        "                    if (i > 0) cpJson.append(\",\");\n"
        "                    cpJson.append(\"\\\"\").append(candidatePolicies[i]).append(\"\\\"\");\n"
        "                }\n"
        "                cpJson.append(\"]\");\n"
        "            }\n"
        "            byte[] reqBody = (\"{\\\"source_type\\\":\\\"\" + sourceType + \"\\\",\\\"destination_type\\\":\\\"\" + destinationType\n"
        "                + \"\\\",\\\"\" + paramsKey + \"\\\":{\\\"data\\\":\" + objJson + \"}\" + cpJson + \"}\")\n"
        "                .getBytes(java.nio.charset.StandardCharsets.UTF_8);\n"
        "            conn.getOutputStream().write(reqBody); // Lineaje: POST /enforce\n"
        "            if (conn.getResponseCode() == 200) {\n"
        "                String rawResp = new String(conn.getInputStream().readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);\n"
        "                // TODO: parse rawResp, extract [\"result\"][\"data\"], and return it in place of `data`\n"
        "            }\n"
        "        } catch (Exception e) {\n"
        "            // Lineaje: fail-open on any connectivity/parsing error\n"
        "        }\n"
        "        return data;\n"
        "    }\n"
        "}\n"
    )


def _import_hint(file_ext: str) -> str:
    """Return the code block needed once per file for the stub call sites to
    resolve — the gr_check()/GrClient.grCheck() source (plus GRBlockedError
    for Python/JS/TS), inlined directly into this same file for every
    language (no dropped-in lineaje/ companion module, no relative-path
    import to keep valid across repo moves/copies, no go.mod/pom.xml
    dependency to add)."""
    ext = file_ext.lower()
    if ext in (".js", ".jsx", ".ts", ".tsx"):
        return _ts_gr_check_inline_source()
    if ext == ".java":
        return _java_gr_check_inline_source()
    if ext == ".go":
        return (
            'import ("bytes"; "encoding/json"; "net/http"; "os"; "time")  // stdlib — no go get needed\n'
            + _go_gr_check_inline_source()
        )
    return _py_gr_check_inline_source()


def _py_guardrail_middleware_inline_source() -> str:
    """GuardrailMiddleware class, inlined directly into a file where a
    create_agent(...) call was rewritten to add middleware=[GuardrailMiddleware()].
    Requires _py_gr_check_inline_source() to already be present in the same
    file (the main per-call-site stub writer inserts it first).

    No fail-open no-op fallback needed here, unlike the old companion-module
    design: since gr_check is defined directly in this same file rather than
    loaded from a separate dropped-in module, there is no load-failure mode
    to guard against — GuardrailMiddleware either compiles with the rest of
    the file or the file doesn't compile at all. Local `_lineaje_`-prefixed
    import aliases avoid colliding with the customer's own top-level
    langchain imports in this file."""
    return (
        "import asyncio as _lineaje_asyncio\n"
        "from langchain.agents.middleware import (\n"
        "    AgentMiddleware as _lineaje_AgentMiddleware,\n"
        "    ModelResponse as _lineaje_ModelResponse,\n"
        ")\n"
        "from langchain_core.messages import (\n"
        "    messages_to_dict as _lineaje_messages_to_dict,\n"
        "    messages_from_dict as _lineaje_messages_from_dict,\n"
        ")\n"
        "\n"
        "\n"
        "class GuardrailMiddleware(_lineaje_AgentMiddleware):\n"
        "    \"\"\"Registered via create_agent(middleware=[GuardrailMiddleware()]).\"\"\"\n"
        "\n"
        "    def wrap_model_call(self, request, handler):\n"
        "        checked = gr_check(_lineaje_messages_to_dict(request.messages), \"agent\", \"llm\")\n"
        "        request = request.override(messages=_lineaje_messages_from_dict(checked))\n"
        "        response = handler(request)\n"
        "        checked_result = gr_check(_lineaje_messages_to_dict(response.result), \"llm\", \"agent\")\n"
        "        return _lineaje_ModelResponse(\n"
        "            result=_lineaje_messages_from_dict(checked_result),\n"
        "            structured_response=response.structured_response,\n"
        "        )\n"
        "\n"
        "    async def awrap_model_call(self, request, handler):\n"
        "        checked = await _lineaje_asyncio.to_thread(\n"
        "            gr_check, _lineaje_messages_to_dict(request.messages), \"agent\", \"llm\"\n"
        "        )\n"
        "        request = request.override(messages=_lineaje_messages_from_dict(checked))\n"
        "        response = await handler(request)\n"
        "        checked_result = await _lineaje_asyncio.to_thread(\n"
        "            gr_check, _lineaje_messages_to_dict(response.result), \"llm\", \"agent\"\n"
        "        )\n"
        "        return _lineaje_ModelResponse(\n"
        "            result=_lineaje_messages_from_dict(checked_result),\n"
        "            structured_response=response.structured_response,\n"
        "        )\n"
        "\n"
        "    def wrap_tool_call(self, request, handler):\n"
        "        checked_call = gr_check(request.tool_call, \"agent\", \"tool\")\n"
        "        request = request.override(tool_call=checked_call)\n"
        "        response = handler(request)\n"
        "        checked_content = gr_check(response.content, \"agent\", \"tool\")\n"
        "        return response.model_copy(update={\"content\": checked_content})\n"
        "\n"
        "    async def awrap_tool_call(self, request, handler):\n"
        "        checked_call = await _lineaje_asyncio.to_thread(gr_check, request.tool_call, \"agent\", \"tool\")\n"
        "        request = request.override(tool_call=checked_call)\n"
        "        response = await handler(request)\n"
        "        checked_content = await _lineaje_asyncio.to_thread(gr_check, response.content, \"agent\", \"tool\")\n"
        "        return response.model_copy(update={\"content\": checked_content})"
    )


def _ts_guardrail_middleware_inline_source() -> str:
    """LangChain.js GuardrailMiddleware, inlined directly into a file where a
    createAgent(...) call was rewritten to add middleware: [GuardrailMiddleware].
    Requires _ts_gr_check_inline_source() to already be present in the same
    file. See _py_guardrail_middleware_inline_source's docstring for why no
    load-failure fallback is needed once everything lives in one file."""
    return (
        "\n"
        "import { createMiddleware } from \"langchain\";\n"
        "import { Command } from \"@langchain/langgraph\";\n"
        "import {\n"
        "  mapChatMessagesToStoredMessages,\n"
        "  mapStoredMessagesToChatMessages,\n"
        "} from \"@langchain/core/messages\";\n"
        "import type { AIMessage } from \"@langchain/core/messages\";\n"
        "\n"
        "export const GuardrailMiddleware = createMiddleware({\n"
        "  name: \"GuardrailMiddleware\",\n"
        "\n"
        "  wrapModelCall: async (request, handler) => {\n"
        "    const checkedMessages = await gr_check(\n"
        "      mapChatMessagesToStoredMessages(request.messages),\n"
        "      \"agent\", \"llm\",\n"
        "    );\n"
        "    const response = await handler({\n"
        "      ...request,\n"
        "      messages: mapStoredMessagesToChatMessages(checkedMessages as any),\n"
        "    });\n"
        "    const checkedResponse = await gr_check(\n"
        "      mapChatMessagesToStoredMessages([response as any]),\n"
        "      \"llm\", \"agent\",\n"
        "    );\n"
        "    return mapStoredMessagesToChatMessages(checkedResponse as any)[0] as AIMessage;\n"
        "  },\n"
        "\n"
        "  wrapToolCall: async (request, handler) => {\n"
        "    const checkedCall = await gr_check(request.toolCall, \"agent\", \"tool\");\n"
        "    const response = await handler({ ...request, toolCall: checkedCall as any });\n"
        "    if (response instanceof Command) {\n"
        "      return response; // control-flow object, not a message — nothing to scan\n"
        "    }\n"
        "    const checkedContent = await gr_check(response.content, \"agent\", \"tool\");\n"
        "    response.content = checkedContent as any;\n"
        "    return response;\n"
        "  },\n"
        "});"
    )


def _ts_gr_check_inline_source() -> str:
    """Full TypeScript gr_check()/GRBlockedError source, inlined directly into
    the instrumented file — no dropped-in lineaje/ companion module, no
    relative import whose "../" hop count must track the file's depth.

    Mirrors the Python inline block's contract exactly (same env vars, same
    fail-open behavior, same GRBlockedError semantics on HTTP 403) so a mixed
    Python + TS/JS repo enforces identically on both sides. Uses only `fetch`
    (Node 18+ / browser built-in) and `AbortController` for the timeout — no
    npm dependency, consistent with the rest of this pipeline's stdlib-only
    design. Valid, strict-mode-clean TypeScript; a plain .js call site can
    still use it as long as the project's build tooling accepts TS-flavored
    syntax in a .js file, or the block is trimmed of type annotations by hand.

    Timeout unit note: Python's gr_check() takes `timeout` in seconds
    (urllib convention); this one takes `timeoutMs` in milliseconds (fetch/
    AbortController convention) — both default to the same 5-second budget.
    """
    return '''// Copyright (c) Lineaje, Inc. All rights reserved.
// Lineaje guardrail helper — inlined once per file (see _import_hint); no npm
// package to install. gr_check() POSTs to GR_SERVICE_URL + "/enforce" and fails
// open (returns `data` unchanged) unless a policy deliberately blocks it
// (GRBlockedError, only on GR_BLOCK_MODE=enforce + an HTTP 403).
type GrEnv = Record<string, string | undefined>;
const _env: GrEnv = ((globalThis as any).process?.env ?? {}) as GrEnv; // Lineaje: env lookup shim (works in Node and browser bundles)

export class GRBlockedError extends Error {
  policyId: string;
  reason: string;

  constructor(policyId: string, reason: string) {
    super(`Guardrail block for policy '${policyId}': ${reason}`);
    this.name = "GRBlockedError";
    this.policyId = policyId;
    this.reason = reason;
  }
}

export async function gr_check(
  data: unknown,
  sourceType: string,
  destinationType: string,
  tenantId: string = "",
  timeoutMs: number = 5000,
  context: Record<string, string | undefined> = {},
): Promise<unknown> {
  const url = _env["GR_SERVICE_URL"] || "";
  if (!url) {
    return data; // fail-open: GR_SERVICE_URL not configured
  }

  const tid = tenantId || _env["GR_TENANT_ID"] || "";
  const bearer = _env["GR_BEARER_TOKEN"] || _env["LINEAJE_PAT_TOKEN"] || _env["LINEAJE_PAT"] || "";
  const hopLabel = `${sourceType}->${destinationType}`;
  const paramsKey = destinationType === "agent" ? "out_params" : "in_params";

  const body: Record<string, unknown> = {
    source_type: sourceType,
    destination_type: destinationType,
    [paramsKey]: { data },
  };
  for (const [k, v] of Object.entries(context)) {
    if (v) {
      body[k] = v;
    }
  }
  if (tid) {
    body["tenant_id"] = tid;
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  let resp: Response;
  try {
    resp = await fetch(url.replace(/\\/+$/, "") + "/enforce", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: "Bearer " + bearer,
      },
      body: JSON.stringify(body),
      signal: controller.signal,
    });
  } catch (exc) {
    console.warn(
      `gr_client[${hopLabel}]: GR service call failed (${exc}) — failing open`,
    );
    return data;
  } finally {
    clearTimeout(timer);
  }

  if (resp.status === 403) {
    let detail: any = {};
    try {
      const errBody: any = await resp.json();
      detail = errBody?.detail ?? {};
    } catch {
      detail = {};
    }
    const blockedBy = detail.blocked_by ?? [];
    const policyId = blockedBy[0]?.policy_id ?? "unknown";
    const reason = detail.message ?? "Request denied by policy enforcement.";
    console.warn(
      `gr_client[${hopLabel}]: BLOCKED by policy=${policyId} — ${reason}`,
    );
    if ((_env["GR_BLOCK_MODE"] || "enforce").toLowerCase() === "audit") {
      return data;
    }
    throw new GRBlockedError(policyId, reason);
  }

  if (!resp.ok) {
    console.warn(
      `gr_client[${hopLabel}]: GR service call failed (HTTP ${resp.status}) — failing open`,
    );
    return data;
  }

  let result: any;
  try {
    result = await resp.json();
  } catch (exc) {
    console.warn(
      `gr_client[${hopLabel}]: GR service call failed (${exc}) — failing open`,
    );
    return data;
  }

  if (result?.status === "escalate") {
    console.warn(
      `gr_client[${hopLabel}]: escalation flagged — passing through for human review`,
    );
  }

  return result?.result?.data ?? data;
}
'''


def fetch_insertion_point_map(
    gr_service_url: str,
    tenant_id: str,
    pat: str = "",
) -> dict[str, list[dict]]:
    """Fetch {insertion_point → [{policy_id, name}, ...]} from the GR service.

    Calls GET /policies/insertion-points?tenant_id=<tenant_id>.
    Returns an empty dict on any error (scanner continues without policy_ids — fail-open).
    Requires GR_SERVICE_URL to be set; returns {} immediately if it is not.
    """
    import json as _json
    import urllib.request as _urllib_req

    url = (gr_service_url or "").rstrip("/")
    if not url:
        _logger.info("[INSERTION] GR service URL empty — skipping insertion-point map fetch")
        return {}

    try:
        req = _urllib_req.Request(
            f"{url}/policies/insertion-points?tenant_id={tenant_id}",
            headers={"Authorization": f"Bearer {pat}"} if pat else {},
            method="GET",
        )
        with _urllib_req.urlopen(req, timeout=5) as resp:
            data = _json.loads(resp.read())
        mapping = data.get("mapping", {}) or {}
        _logger.info(
            "[INSERTION] Fetched insertion-point map from GR service: %d type(s) (%s)",
            len(mapping),
            ", ".join(
                f"{ip}={len(v) if isinstance(v, list) else v}"
                for ip, v in sorted(mapping.items())
            ) or "empty",
        )
        return mapping
    except Exception as exc:
        _logger.warning(
            "[INSERTION] GR insertion-point map fetch failed (fail-open, continuing without policy_ids): %s",
            exc,
        )
        return {}


# Mirrors guardrail_service/gr_service/handlers/sync.py's _KNOWN_INSERTION_POINTS /
# _APPLIES_TO_MAP exactly (kept in sync by hand -- small and rarely-changing).
# gr_service computes the SAME insertion_point mapping this way from applies_to,
# then persists it into its own SQLite DB via a live sync against the Lineaje
# backend's /api/v1/policies. Reading the aiepo-content policy JSON files directly
# and applying this same static, hardcoded expansion reproduces
# get_insertion_point_map()'s output for a LOCAL policy content checkout, with no
# database, no live gr_service process, and no network call -- see
# build_insertion_point_map_from_content() below. What this can't reproduce is
# real per-tenant enablement (gr_service's SQLite `policies.enabled` column /
# live backend data) -- that has to come from wherever the caller already has an
# enabled-policy list for this tenant (e.g. the same pipeline scan's own loaded
# Policy objects), not from this static content.
# NOTE: deliberately NOT named "_KNOWN_INSERTION_POINTS" — that name is
# already bound above (line ~191, the annotation-validation set). A second
# module-level `_KNOWN_INSERTION_POINTS = {...}` here previously SHADOWED
# that earlier frozenset entirely (last assignment wins at module scope),
# silently making the annotation-validation set permanently equal to this
# GR-sync set instead of the two independent purposes their own docstrings
# describe. Given a distinct name so both actually take effect.
_GR_SYNC_KNOWN_INSERTION_POINTS = {
    "agent_to_llm", "llm_to_agent", "db_read", "api_call", "data_outbound",
    "file_upload", "mcp_call", "skill_invocation", "security_decision",
    "risky_operation", "user_to_llm", "agent_to_agent", "llm_to_user",
    # UI-boundary points, distinct from user_to_llm/llm_to_user (raw human
    # input/output) — agent/LLM traffic crossing into or out of a UI layer
    # (e.g. rendering to a frontend widget, a WebSocket/socket.io push).
    # Validation-only for now: no regex/AST auto-detection wired up yet —
    # these are only stubbed via an explicit @gr:insertion_point= annotation.
    "agent_to_ui", "ui_to_agent", "llm_to_ui", "ui_to_llm",
    # Finer-grained user_interface edges — see _guess_interaction_type.
    "agent_to_user", "user_to_agent",     "tool_to_user", "user_to_tool",
    "html_to_user",
    # Schema-v2 canonical phase; AI_DAT_SEC_012 guardrail.insertion_point.
    "data_egress",
    # Schema-v2 phase + insertion_point; AI_DAT_SEC_010 ("Do not log PII").
    "log_emit",
}

_APPLIES_TO_MAP: dict[str, list[str]] = {
    "AI Agent":         ["agent_to_llm", "llm_to_agent", "mcp_call",
                         "skill_invocation", "security_decision", "risky_operation",
                         "user_to_llm", "agent_to_agent", "llm_to_user",
                         "file_upload", "data_outbound", "data_egress", "log_emit"],
    "AI Model":         ["agent_to_llm", "llm_to_agent", "user_to_llm", "llm_to_user"],
    "LLM":              ["agent_to_llm", "llm_to_agent", "user_to_llm", "llm_to_user"],
    "LLM Application":  ["agent_to_llm", "llm_to_agent", "api_call", "user_to_llm", "llm_to_user"],
    "MCP Server":       ["mcp_call"],
    "MCP Client":       ["mcp_call"],
    "System Of Record": ["db_read"],
    "System of Record": ["db_read"],
    "component":        ["db_read", "api_call"],
    "Skills":           ["skill_invocation"],
}


def build_insertion_point_map_from_content(content_dir: str) -> "dict[str, list[dict]]":
    """{insertion_point -> [{policy_id, name}, ...]} built by reading aiepo-content
    policy JSON files (AI_*.json) directly. NOT used by the live scan path (see
    hardcoded_insertion_point_map() below, which is what fetch_insertion_point_map()
    actually falls back to) -- this is the offline GENERATOR that produced
    _POLICY_CATALOG / _POLICY_INSERTION_POINTS. Re-run this against a fresh
    aiepo-content checkout and copy its output into those two dicts whenever the
    policy catalog changes; the live server should never need a local content
    directory to exist. Includes BOTH enabled and disabled policies (matches
    gr_service's own endpoint behavior). Returns {} if content_dir doesn't exist
    or has no AI_*.json files -- never raises.
    """
    import glob as _glob
    import json as _json

    mapping: dict[str, list[dict]] = {}
    if not content_dir or not os.path.isdir(content_dir):
        return mapping

    for path in sorted(_glob.glob(os.path.join(content_dir, "AI_*.json"))):
        try:
            with open(path, "r", encoding="utf-8") as fh:
                data = _json.load(fh)
        except (OSError, ValueError):
            continue
        policy_id = (data.get("ai_policy_id") or data.get("policy_id") or "").strip()
        if not policy_id:
            policy_id = os.path.splitext(os.path.basename(path))[0]
        name = (data.get("name") or policy_id).strip()

        ips: set = set()
        for gr in data.get("guardrail") or []:
            if not isinstance(gr, dict):
                continue
            gip = (gr.get("insertion_point") or "").strip()
            if gip in _GR_SYNC_KNOWN_INSERTION_POINTS:
                ips.add(gip)
        for label in data.get("applies_to") or []:
            ips.update(_APPLIES_TO_MAP.get(label, []))

        for ip in ips:
            mapping.setdefault(ip, []).append({"policy_id": policy_id, "name": name})

    return mapping


def enabled_policy_ids_by_insertion_point(policies: "list[Any]") -> "dict[str, list[str]]":
    """{insertion_point -> [policy_id, ...]} computed from REAL policy objects
    (``.is_enabled`` / ``.applies_to`` / ``.guardrail``) — this is the caller-
    supplied real per-tenant enablement that
    build_insertion_point_map_from_content()'s own docstring above says a
    static content-file read can't reproduce. Used to embed "which policies
    are enabled for this tenant at this insertion point" into a generated
    stub at scan time (Independent Code Review "Flowchart 4" optimization —
    lets the runtime GR service skip a live tenant+insertion_point DB query
    on every call when the embedded list is present).

    Disabled policies (``is_enabled`` falsy) are excluded entirely — only
    enabled policy_ids are ever embedded. Same insertion-point derivation as
    build_insertion_point_map_from_content() above: union of
    ``_APPLIES_TO_MAP``-expanded ``applies_to`` labels and any explicit
    per-guardrail ``insertion_point`` field.

    Accepts anything with ``is_enabled``/``applies_to``/``guardrail``/
    ``policy_id``/``ai_policy_id`` attributes (duck-typed, e.g.
    ``pipeline.foundation.models.Policy`` instances) rather than importing
    that type directly — this scanner has no import dependency on the
    pipeline package today and this function shouldn't be the one to add it.
    """
    out: dict[str, list[str]] = {}
    for p in policies or []:
        if not getattr(p, "is_enabled", True):
            continue
        policy_id = (getattr(p, "ai_policy_id", "") or getattr(p, "policy_id", "") or "").strip()
        if not policy_id:
            continue

        ips: set = set()
        for label in getattr(p, "applies_to", None) or []:
            ips.update(_APPLIES_TO_MAP.get(label, []))
        for gr in getattr(p, "guardrail", None) or []:
            if not isinstance(gr, dict):
                continue
            gip = (gr.get("insertion_point") or "").strip()
            if gip in _GR_SYNC_KNOWN_INSERTION_POINTS:
                ips.add(gip)

        for ip in ips:
            out.setdefault(ip, []).append(policy_id)

    return out


# Static snapshot of aiepo-content's policy catalog (78 policies as of the last
# regeneration), used so the live scan path never needs a local aiepo-content
# checkout or a running GR service to report policy coverage per stub. Same
# insertion_point-derivation algorithm as gr_service's own
# sync.py::_map_applies_to() (applies_to label -> _APPLIES_TO_MAP expansion,
# unioned with any explicit per-guardrail insertion_point field) -- just computed
# once, offline, via build_insertion_point_map_from_content(), instead of on
# every request. Regenerate by re-running that function against a fresh
# aiepo-content checkout and pasting its output here when the policy catalog
# changes; this will drift from the live catalog over time between
# regenerations, which is an accepted tradeoff for not depending on a live
# service or a local content directory at scan time.
_POLICY_CATALOG: dict[str, str] = {
    'AI_APP_SEC_001': 'Do not allow malicious content via hidden prompts',
    'AI_APP_SEC_002': 'Do not allow malicious content via encoded prompts',
    'AI_APP_SEC_006': "Use only LLMs from the organization's approved list.",
    'AI_APP_SEC_014': 'MCP server must validate and sanitize all input',
    'AI_APP_SEC_022': 'MCP clients must log all interactions with the MCP server',
    'AI_APP_SEC_023': 'Client must validate and sanitize any output from a MCP server',
    'AI_APP_SEC_028': "Do not use LLMs from the organization's disallowed list",
    'AI_APP_SEC_029': 'Agent must validate, sanitize LLM output including for presence of eval or any dynamic code execution primitive in LLM output.',
    'AI_APP_SEC_032': 'Do not allow malicious content via hidden prompts written in leetspeak.',
    'AI_APP_SEC_033': 'MCP server must not interact directly with an LLM',
    'AI_APP_SEC_034': 'Clear exit or termination criteria must exist for the agent to consider its task complete and stop executing.',
    'AI_APP_SEC_035': 'Agents must log all interactions with an LLM',
    'AI_APP_SEC_038': 'The AI Model must validate and sanitize any input before processing.',
    'AI_APP_SEC_039': 'Sanitize and validate all input to the AI Model.',
    'AI_APP_SEC_040': 'Do not allow malicious content via prompts included in uploaded files.',
    'AI_APP_SEC_059': 'Do not allow prompts that can execute malicious commands at runtime.',
    'AI_APP_SEC_064': 'Enforce synthetic content provenance, labeling, and watermarking for AI-generated outputs.',
    'AI_APP_SEC_066': 'Do not allow malicious content via prompts included in source files.',
    'AI_APP_SEC_067': 'Detect direct string interpolation of untrusted input into LLM prompts',
    'AI_APP_SEC_068': 'Detect LLM output used directly in security-sensitive decisions without Human in the Loop (HITL) validation',
    'AI_APP_SEC_069': 'AI Agent must implement Human in the Loop (HITL) approval flow for risky operations like delete, purge, destroy',
    'AI_APP_SEC_070': 'Detect and block all forms of prompt injection attacks in user inputs and file contents',
    'AI_APP_SEC_071': 'Enforce chemical, biological, radiological, or nuclear (CBRN) threat prevention safeguards in AI-enabled systems',
    'AI_APP_SEC_072': 'AI systems making consequential decisions must implement explainability mechanisms disclosing decision factors',
    'AI_APP_SEC_073': 'AI consequential decisions must include a human review pathway before final determination',
    'AI_APP_SEC_074': 'AI systems must implement emergency shutdown and forced-termination mechanisms',
    'AI_APP_SEC_075': 'Detect and block use of facial recognition APIs or libraries in employment decision workflows',
    'AI_APP_SEC_076': 'High-risk AI systems must provide enhanced disclosures including decision factors, known limitations, accuracy metrics, and appeal rights',
    'AI_APP_SEC_077': 'AI systems must provide consumer notice before using ADMT in a consequential decision',
    'AI_APP_SEC_078': 'Human review workflows for AI consequential decisions must enforce override authority, reviewer context, and no auto-approve defaults',
    'AI_APP_SEC_079': 'Enforce rate limiting and throttling on AI API calls',
    'AI_DAT_SEC_001': 'Do not store secrets in code.',
    'AI_DAT_SEC_009': 'If PII data must be shared, it must be encrypted',
    'AI_DAT_SEC_010': 'Do not log PII.',
    'AI_DAT_SEC_011': 'Do not send PII and/or secrets to AI Models',
    'AI_DAT_SEC_012': 'Mask PII on user interfaces',
    'AI_DAT_SEC_023': 'Redact PII from uploaded files.',
    'AI_DAT_SEC_024': 'Uploaded files must not contain PII (Singapore).',
    'AI_DAT_SEC_025': 'No file should contain any PII.',
    'AI_DAT_SEC_027': 'Enforce output data minimisation for model, tool, and API responses.',
    'AI_DAT_SEC_029': 'Enforce decision logging, audit trail, and forensic readiness for AI-driven actions.',
    'AI_DAT_SEC_030': 'Enforce minimum six-month log retention for high-risk AI systems',
    'AI_DAT_SEC_031': 'Disclose training data sources including categories, types, timeframes, and geography.',
    'AI_DAT_SEC_032': 'Disclose data acquisition methods including permissions, licensing, and preprocessing steps.',
    'AI_DAT_SEC_033': 'Patient acknowledgment of AI-assisted care must be documented and retained before clinical AI use',
    'AI_DAT_SEC_036': 'Biometric data collection must be preceded by explicit, documented consent capture',
    'AI_DAT_SEC_037': 'Biometric data stores must declare a retention limit and deletion scheduling mechanism',
    'AI_DAT_SEC_038': 'AI consequential decision records must be retained for a minimum of three years',
    'AI_DAT_SEC_039': 'AI data stores must enforce encryption at rest and TLS in transit.',
    'AI_IAC_002': 'MCP client must authenticate MCP server',
    'AI_IAC_006': 'MCP server must authenticate all clients',
    'AI_IAC_007': 'Inter agent communication must be authenticated.',
    'AI_IAC_008': 'Agents must not hold excessive external system credentials',
    'AI_IAC_009': 'LLM endpoints must require authentication',
    'AI_IAC_014': 'A user must authenticate before accessing the AI Agent.',
    'AI_IAC_015': 'Enforce URL allowlists for agent fetches, tools, and outbound HTTP.',
    'AI_IAC_016': 'Detect and block agent privilege escalation attempts.',
    'AI_IAC_017': 'Maintain session token integrity with signing, verification, expiry, and binding.',
    'AI_IAC_018': 'Enforce cryptographically verified user-to-agent binding for every request.',
    'AI_IAC_020': 'Restrict AI agents to an explicit tool allow list.',
    'AI_IAC_022': 'Enforce resource bounds, termination limits, and traceability for subagent spawning',
    'AI_IAC_023': 'Chatbot and AI interfaces must disclose AI identity to the user',
    'AI_IAC_024': 'General purpose AI model integrations must reference a model card or technical documentation',
    'AI_IAC_025': 'Healthcare AI systems must disclose AI use to patients before diagnosis, treatment, or imaging',
    'AI_IAC_026': 'AI clinical recommendations must disclose that human clinicians retain final decision authority',
    'AI_IAC_027': 'Healthcare AI communications must include patient instructions to request human-only review',
    'AI_IAC_028': 'AI system deployments must declare a risk classification level in configuration metadata',
    'AI_IAC_029': 'AI model deployments must maintain version tracking, change logs, and release documentation',
    'AI_IAC_030': 'AI system deployments must declare a covered domain classification per automated decision-making regulations',
    'AI_IAC_031': 'AI model endpoints must enforce role-based access control with minimal OAuth scopes',
    'AI_SKILL_DAT_SEC_001': 'Do not allow skills that exfiltrate data',
    'AI_SKILL_SEC_001': 'Do not allow malicious skills',
    'AI_SKILL_SEC_002': 'Do not allow suspicious skills',
    'AI_SKILL_SEC_003': 'Do not allow skills that are pending a scan',
    'AI_VULN_SEC_002': 'Do not allow critical or high vulnerabilities in the code.',
    'AI_VULN_SEC_005': 'Enforce foundation model identity, version pinning, and approved model registry for all AI workloads.',
    'AI_VULN_SEC_006': 'Memory safety and buffer overflow prevention in native AI code (C/C++/Rust)',
    'AI_VULN_SEC_007': 'AI systems must implement incident detection, structured logging, and reporting mechanisms',
}

_POLICY_INSERTION_POINTS: dict[str, list[str]] = {
    'AI_APP_SEC_001': ['agent_to_agent', 'agent_to_llm', 'data_outbound', 'file_upload', 'llm_to_agent', 'llm_to_user', 'agent_to_user', 'user_to_agent', 'tool_to_user', 'user_to_tool', 'mcp_call', 'risky_operation', 'security_decision', 'skill_invocation', 'user_to_llm'],
    'AI_APP_SEC_002': ['agent_to_agent', 'agent_to_llm', 'data_outbound', 'file_upload', 'llm_to_agent', 'llm_to_user', 'agent_to_user', 'user_to_agent', 'tool_to_user', 'user_to_tool', 'mcp_call', 'risky_operation', 'security_decision', 'skill_invocation', 'user_to_llm'],
    'AI_APP_SEC_006': ['agent_to_agent', 'agent_to_llm', 'data_outbound', 'file_upload', 'llm_to_agent', 'llm_to_user', 'agent_to_user', 'user_to_agent', 'tool_to_user', 'user_to_tool', 'mcp_call', 'risky_operation', 'security_decision', 'skill_invocation', 'user_to_llm'],
    'AI_APP_SEC_014': ['mcp_call'],
    'AI_APP_SEC_022': ['agent_to_agent', 'agent_to_llm', 'data_outbound', 'file_upload', 'llm_to_agent', 'llm_to_user', 'agent_to_user', 'user_to_agent', 'tool_to_user', 'user_to_tool', 'mcp_call', 'risky_operation', 'security_decision', 'skill_invocation', 'user_to_llm'],
    'AI_APP_SEC_023': ['agent_to_agent', 'agent_to_llm', 'data_outbound', 'file_upload', 'llm_to_agent', 'llm_to_user', 'agent_to_user', 'user_to_agent', 'tool_to_user', 'user_to_tool', 'mcp_call', 'risky_operation', 'security_decision', 'skill_invocation', 'user_to_llm'],
    'AI_APP_SEC_028': ['agent_to_agent', 'agent_to_llm', 'data_outbound', 'file_upload', 'llm_to_agent', 'llm_to_user', 'agent_to_user', 'user_to_agent', 'tool_to_user', 'user_to_tool', 'mcp_call', 'risky_operation', 'security_decision', 'skill_invocation', 'user_to_llm'],
    'AI_APP_SEC_029': ['agent_to_agent', 'agent_to_llm', 'data_outbound', 'file_upload', 'llm_to_agent', 'llm_to_user', 'agent_to_user', 'user_to_agent', 'tool_to_user', 'user_to_tool', 'mcp_call', 'risky_operation', 'security_decision', 'skill_invocation', 'user_to_llm'],
    'AI_APP_SEC_032': ['agent_to_agent', 'agent_to_llm', 'data_outbound', 'file_upload', 'llm_to_agent', 'llm_to_user', 'agent_to_user', 'user_to_agent', 'tool_to_user', 'user_to_tool', 'mcp_call', 'risky_operation', 'security_decision', 'skill_invocation', 'user_to_llm'],
    'AI_APP_SEC_033': ['mcp_call'],
    'AI_APP_SEC_034': ['agent_to_agent', 'agent_to_llm', 'data_outbound', 'file_upload', 'llm_to_agent', 'llm_to_user', 'agent_to_user', 'user_to_agent', 'tool_to_user', 'user_to_tool', 'mcp_call', 'risky_operation', 'security_decision', 'skill_invocation', 'user_to_llm'],
    'AI_APP_SEC_035': ['agent_to_agent', 'agent_to_llm', 'data_outbound', 'file_upload', 'llm_to_agent', 'llm_to_user', 'agent_to_user', 'user_to_agent', 'tool_to_user', 'user_to_tool', 'mcp_call', 'risky_operation', 'security_decision', 'skill_invocation', 'user_to_llm'],
    'AI_APP_SEC_038': ['agent_to_llm', 'llm_to_agent', 'llm_to_user', 'agent_to_user', 'user_to_agent', 'tool_to_user', 'user_to_tool', 'user_to_llm'],
    'AI_APP_SEC_039': ['agent_to_agent', 'agent_to_llm', 'data_outbound', 'file_upload', 'llm_to_agent', 'llm_to_user', 'agent_to_user', 'user_to_agent', 'tool_to_user', 'user_to_tool', 'mcp_call', 'risky_operation', 'security_decision', 'skill_invocation', 'user_to_llm'],
    'AI_APP_SEC_040': ['agent_to_agent', 'agent_to_llm', 'data_outbound', 'file_upload', 'llm_to_agent', 'llm_to_user', 'agent_to_user', 'user_to_agent', 'tool_to_user', 'user_to_tool', 'mcp_call', 'risky_operation', 'security_decision', 'skill_invocation', 'user_to_llm'],
    'AI_APP_SEC_059': ['agent_to_agent', 'agent_to_llm', 'data_outbound', 'file_upload', 'llm_to_agent', 'llm_to_user', 'agent_to_user', 'user_to_agent', 'tool_to_user', 'user_to_tool', 'mcp_call', 'risky_operation', 'security_decision', 'skill_invocation', 'user_to_llm'],
    'AI_APP_SEC_064': ['agent_to_agent', 'agent_to_llm', 'api_call', 'data_outbound', 'file_upload', 'llm_to_agent', 'llm_to_user', 'agent_to_user', 'user_to_agent', 'tool_to_user', 'user_to_tool', 'mcp_call', 'risky_operation', 'security_decision', 'skill_invocation', 'user_to_llm'],
    'AI_APP_SEC_066': ['agent_to_agent', 'agent_to_llm', 'data_outbound', 'file_upload', 'llm_to_agent', 'llm_to_user', 'agent_to_user', 'user_to_agent', 'tool_to_user', 'user_to_tool', 'mcp_call', 'risky_operation', 'security_decision', 'skill_invocation', 'user_to_llm'],
    'AI_APP_SEC_067': ['agent_to_agent', 'agent_to_llm', 'api_call', 'data_outbound', 'file_upload', 'llm_to_agent', 'llm_to_user', 'agent_to_user', 'user_to_agent', 'tool_to_user', 'user_to_tool', 'mcp_call', 'risky_operation', 'security_decision', 'skill_invocation', 'user_to_llm'],
    'AI_APP_SEC_068': ['agent_to_agent', 'agent_to_llm', 'api_call', 'data_outbound', 'file_upload', 'llm_to_agent', 'llm_to_user', 'agent_to_user', 'user_to_agent', 'tool_to_user', 'user_to_tool', 'mcp_call', 'risky_operation', 'security_decision', 'skill_invocation', 'user_to_llm'],
    'AI_APP_SEC_069': ['agent_to_agent', 'agent_to_llm', 'data_outbound', 'file_upload', 'llm_to_agent', 'llm_to_user', 'agent_to_user', 'user_to_agent', 'tool_to_user', 'user_to_tool', 'mcp_call', 'risky_operation', 'security_decision', 'skill_invocation', 'user_to_llm'],
    'AI_APP_SEC_070': ['agent_to_agent', 'agent_to_llm', 'data_outbound', 'file_upload', 'llm_to_agent', 'llm_to_user', 'agent_to_user', 'user_to_agent', 'tool_to_user', 'user_to_tool', 'mcp_call', 'risky_operation', 'security_decision', 'skill_invocation', 'user_to_llm'],
    'AI_APP_SEC_071': ['agent_to_agent', 'agent_to_llm', 'api_call', 'data_outbound', 'file_upload', 'llm_to_agent', 'llm_to_user', 'agent_to_user', 'user_to_agent', 'tool_to_user', 'user_to_tool', 'mcp_call', 'risky_operation', 'security_decision', 'skill_invocation', 'user_to_llm'],
    'AI_APP_SEC_072': ['agent_to_agent', 'agent_to_llm', 'api_call', 'data_outbound', 'file_upload', 'llm_to_agent', 'llm_to_user', 'agent_to_user', 'user_to_agent', 'tool_to_user', 'user_to_tool', 'mcp_call', 'risky_operation', 'security_decision', 'skill_invocation', 'user_to_llm'],
    'AI_APP_SEC_073': ['agent_to_agent', 'agent_to_llm', 'api_call', 'data_outbound', 'file_upload', 'llm_to_agent', 'llm_to_user', 'agent_to_user', 'user_to_agent', 'tool_to_user', 'user_to_tool', 'mcp_call', 'risky_operation', 'security_decision', 'skill_invocation', 'user_to_llm'],
    'AI_APP_SEC_074': ['agent_to_agent', 'agent_to_llm', 'api_call', 'data_outbound', 'file_upload', 'llm_to_agent', 'llm_to_user', 'agent_to_user', 'user_to_agent', 'tool_to_user', 'user_to_tool', 'mcp_call', 'risky_operation', 'security_decision', 'skill_invocation', 'user_to_llm'],
    'AI_APP_SEC_075': ['agent_to_agent', 'agent_to_llm', 'api_call', 'data_outbound', 'file_upload', 'llm_to_agent', 'llm_to_user', 'agent_to_user', 'user_to_agent', 'tool_to_user', 'user_to_tool', 'mcp_call', 'risky_operation', 'security_decision', 'skill_invocation', 'user_to_llm'],
    'AI_APP_SEC_076': ['agent_to_agent', 'agent_to_llm', 'api_call', 'data_outbound', 'file_upload', 'llm_to_agent', 'llm_to_user', 'agent_to_user', 'user_to_agent', 'tool_to_user', 'user_to_tool', 'mcp_call', 'risky_operation', 'security_decision', 'skill_invocation', 'user_to_llm'],
    'AI_APP_SEC_077': ['agent_to_agent', 'agent_to_llm', 'api_call', 'data_outbound', 'file_upload', 'llm_to_agent', 'llm_to_user', 'agent_to_user', 'user_to_agent', 'tool_to_user', 'user_to_tool', 'mcp_call', 'risky_operation', 'security_decision', 'skill_invocation', 'user_to_llm'],
    'AI_APP_SEC_078': ['agent_to_agent', 'agent_to_llm', 'api_call', 'data_outbound', 'file_upload', 'llm_to_agent', 'llm_to_user', 'agent_to_user', 'user_to_agent', 'tool_to_user', 'user_to_tool', 'mcp_call', 'risky_operation', 'security_decision', 'skill_invocation', 'user_to_llm'],
    'AI_APP_SEC_079': ['agent_to_agent', 'agent_to_llm', 'api_call', 'data_outbound', 'file_upload', 'llm_to_agent', 'llm_to_user', 'agent_to_user', 'user_to_agent', 'tool_to_user', 'user_to_tool', 'mcp_call', 'risky_operation', 'security_decision', 'skill_invocation', 'user_to_llm'],
    'AI_DAT_SEC_001': ['agent_to_agent', 'agent_to_llm', 'data_outbound', 'file_upload', 'llm_to_agent', 'llm_to_user', 'agent_to_user', 'user_to_agent', 'tool_to_user', 'user_to_tool', 'mcp_call', 'risky_operation', 'security_decision', 'skill_invocation', 'user_to_llm'],
    'AI_DAT_SEC_009': ['agent_to_agent', 'agent_to_llm', 'data_outbound', 'file_upload', 'llm_to_agent', 'llm_to_user', 'agent_to_user', 'user_to_agent', 'tool_to_user', 'user_to_tool', 'mcp_call', 'risky_operation', 'security_decision', 'skill_invocation', 'user_to_llm'],
    'AI_DAT_SEC_010': ['agent_to_agent', 'agent_to_llm', 'data_outbound', 'file_upload', 'llm_to_agent', 'llm_to_user', 'agent_to_user', 'user_to_agent', 'tool_to_user', 'user_to_tool', 'mcp_call', 'risky_operation', 'security_decision', 'skill_invocation', 'user_to_llm'],
    'AI_DAT_SEC_011': ['agent_to_agent', 'agent_to_llm', 'data_outbound', 'file_upload', 'llm_to_agent', 'llm_to_user', 'agent_to_user', 'user_to_agent', 'tool_to_user', 'user_to_tool', 'mcp_call', 'risky_operation', 'security_decision', 'skill_invocation', 'user_to_llm'],
    'AI_DAT_SEC_012': ['agent_to_agent', 'agent_to_llm', 'data_outbound', 'file_upload', 'llm_to_agent', 'llm_to_user', 'agent_to_user', 'user_to_agent', 'tool_to_user', 'user_to_tool', 'html_to_user', 'mcp_call', 'risky_operation', 'security_decision', 'skill_invocation', 'user_to_llm'],
    'AI_DAT_SEC_023': ['agent_to_agent', 'agent_to_llm', 'data_outbound', 'file_upload', 'llm_to_agent', 'llm_to_user', 'agent_to_user', 'user_to_agent', 'tool_to_user', 'user_to_tool', 'mcp_call', 'risky_operation', 'security_decision', 'skill_invocation', 'user_to_llm'],
    'AI_DAT_SEC_024': ['agent_to_agent', 'agent_to_llm', 'data_outbound', 'file_upload', 'llm_to_agent', 'llm_to_user', 'agent_to_user', 'user_to_agent', 'tool_to_user', 'user_to_tool', 'mcp_call', 'risky_operation', 'security_decision', 'skill_invocation', 'user_to_llm'],
    'AI_DAT_SEC_025': ['agent_to_agent', 'agent_to_llm', 'data_outbound', 'file_upload', 'llm_to_agent', 'llm_to_user', 'agent_to_user', 'user_to_agent', 'tool_to_user', 'user_to_tool', 'mcp_call', 'risky_operation', 'security_decision', 'skill_invocation', 'user_to_llm'],
    'AI_DAT_SEC_027': ['agent_to_agent', 'agent_to_llm', 'api_call', 'data_outbound', 'file_upload', 'llm_to_agent', 'llm_to_user', 'agent_to_user', 'user_to_agent', 'tool_to_user', 'user_to_tool', 'mcp_call', 'risky_operation', 'security_decision', 'skill_invocation', 'user_to_llm'],
    'AI_DAT_SEC_029': ['agent_to_agent', 'agent_to_llm', 'api_call', 'data_outbound', 'file_upload', 'llm_to_agent', 'llm_to_user', 'agent_to_user', 'user_to_agent', 'tool_to_user', 'user_to_tool', 'mcp_call', 'risky_operation', 'security_decision', 'skill_invocation', 'user_to_llm'],
    'AI_DAT_SEC_030': ['agent_to_agent', 'agent_to_llm', 'api_call', 'data_outbound', 'file_upload', 'llm_to_agent', 'llm_to_user', 'agent_to_user', 'user_to_agent', 'tool_to_user', 'user_to_tool', 'mcp_call', 'risky_operation', 'security_decision', 'skill_invocation', 'user_to_llm'],
    'AI_DAT_SEC_031': ['agent_to_agent', 'agent_to_llm', 'api_call', 'data_outbound', 'file_upload', 'llm_to_agent', 'llm_to_user', 'agent_to_user', 'user_to_agent', 'tool_to_user', 'user_to_tool', 'mcp_call', 'risky_operation', 'security_decision', 'skill_invocation', 'user_to_llm'],
    'AI_DAT_SEC_032': ['agent_to_agent', 'agent_to_llm', 'api_call', 'data_outbound', 'file_upload', 'llm_to_agent', 'llm_to_user', 'agent_to_user', 'user_to_agent', 'tool_to_user', 'user_to_tool', 'mcp_call', 'risky_operation', 'security_decision', 'skill_invocation', 'user_to_llm'],
    'AI_DAT_SEC_033': ['agent_to_agent', 'agent_to_llm', 'api_call', 'data_outbound', 'file_upload', 'llm_to_agent', 'llm_to_user', 'agent_to_user', 'user_to_agent', 'tool_to_user', 'user_to_tool', 'mcp_call', 'risky_operation', 'security_decision', 'skill_invocation', 'user_to_llm'],
    'AI_DAT_SEC_036': ['agent_to_agent', 'agent_to_llm', 'api_call', 'data_outbound', 'file_upload', 'llm_to_agent', 'llm_to_user', 'agent_to_user', 'user_to_agent', 'tool_to_user', 'user_to_tool', 'mcp_call', 'risky_operation', 'security_decision', 'skill_invocation', 'user_to_llm'],
    'AI_DAT_SEC_037': ['agent_to_agent', 'agent_to_llm', 'api_call', 'data_outbound', 'file_upload', 'llm_to_agent', 'llm_to_user', 'agent_to_user', 'user_to_agent', 'tool_to_user', 'user_to_tool', 'mcp_call', 'risky_operation', 'security_decision', 'skill_invocation', 'user_to_llm'],
    'AI_DAT_SEC_038': ['agent_to_agent', 'agent_to_llm', 'api_call', 'data_outbound', 'file_upload', 'llm_to_agent', 'llm_to_user', 'agent_to_user', 'user_to_agent', 'tool_to_user', 'user_to_tool', 'mcp_call', 'risky_operation', 'security_decision', 'skill_invocation', 'user_to_llm'],
    'AI_DAT_SEC_039': ['agent_to_agent', 'agent_to_llm', 'api_call', 'data_outbound', 'file_upload', 'llm_to_agent', 'llm_to_user', 'agent_to_user', 'user_to_agent', 'tool_to_user', 'user_to_tool', 'mcp_call', 'risky_operation', 'security_decision', 'skill_invocation', 'user_to_llm'],
    'AI_IAC_002': ['agent_to_agent', 'agent_to_llm', 'data_outbound', 'file_upload', 'llm_to_agent', 'llm_to_user', 'agent_to_user', 'user_to_agent', 'tool_to_user', 'user_to_tool', 'mcp_call', 'risky_operation', 'security_decision', 'skill_invocation', 'user_to_llm'],
    'AI_IAC_006': ['mcp_call'],
    'AI_IAC_007': ['agent_to_agent', 'agent_to_llm', 'data_outbound', 'file_upload', 'llm_to_agent', 'llm_to_user', 'agent_to_user', 'user_to_agent', 'tool_to_user', 'user_to_tool', 'mcp_call', 'risky_operation', 'security_decision', 'skill_invocation', 'user_to_llm'],
    'AI_IAC_008': ['agent_to_agent', 'agent_to_llm', 'data_outbound', 'file_upload', 'llm_to_agent', 'llm_to_user', 'agent_to_user', 'user_to_agent', 'tool_to_user', 'user_to_tool', 'mcp_call', 'risky_operation', 'security_decision', 'skill_invocation', 'user_to_llm'],
    'AI_IAC_009': ['agent_to_llm', 'llm_to_agent', 'llm_to_user', 'agent_to_user', 'user_to_agent', 'tool_to_user', 'user_to_tool', 'user_to_llm'],
    'AI_IAC_014': ['agent_to_agent', 'agent_to_llm', 'data_outbound', 'file_upload', 'llm_to_agent', 'llm_to_user', 'agent_to_user', 'user_to_agent', 'tool_to_user', 'user_to_tool', 'mcp_call', 'risky_operation', 'security_decision', 'skill_invocation', 'user_to_llm'],
    'AI_IAC_015': ['agent_to_agent', 'agent_to_llm', 'api_call', 'data_outbound', 'file_upload', 'llm_to_agent', 'llm_to_user', 'agent_to_user', 'user_to_agent', 'tool_to_user', 'user_to_tool', 'mcp_call', 'risky_operation', 'security_decision', 'skill_invocation', 'user_to_llm'],
    'AI_IAC_016': ['agent_to_agent', 'agent_to_llm', 'api_call', 'data_outbound', 'file_upload', 'llm_to_agent', 'llm_to_user', 'agent_to_user', 'user_to_agent', 'tool_to_user', 'user_to_tool', 'mcp_call', 'risky_operation', 'security_decision', 'skill_invocation', 'user_to_llm'],
    'AI_IAC_017': ['agent_to_agent', 'agent_to_llm', 'api_call', 'data_outbound', 'file_upload', 'llm_to_agent', 'llm_to_user', 'agent_to_user', 'user_to_agent', 'tool_to_user', 'user_to_tool', 'mcp_call', 'risky_operation', 'security_decision', 'skill_invocation', 'user_to_llm'],
    'AI_IAC_018': ['agent_to_agent', 'agent_to_llm', 'api_call', 'data_outbound', 'file_upload', 'llm_to_agent', 'llm_to_user', 'agent_to_user', 'user_to_agent', 'tool_to_user', 'user_to_tool', 'mcp_call', 'risky_operation', 'security_decision', 'skill_invocation', 'user_to_llm'],
    'AI_IAC_020': ['agent_to_agent', 'agent_to_llm', 'api_call', 'data_outbound', 'file_upload', 'llm_to_agent', 'llm_to_user', 'agent_to_user', 'user_to_agent', 'tool_to_user', 'user_to_tool', 'mcp_call', 'risky_operation', 'security_decision', 'skill_invocation', 'user_to_llm'],
    'AI_IAC_022': ['agent_to_agent', 'agent_to_llm', 'api_call', 'data_outbound', 'file_upload', 'llm_to_agent', 'llm_to_user', 'agent_to_user', 'user_to_agent', 'tool_to_user', 'user_to_tool', 'mcp_call', 'risky_operation', 'security_decision', 'skill_invocation', 'user_to_llm'],
    'AI_IAC_023': ['agent_to_agent', 'agent_to_llm', 'api_call', 'data_outbound', 'file_upload', 'llm_to_agent', 'llm_to_user', 'agent_to_user', 'user_to_agent', 'tool_to_user', 'user_to_tool', 'mcp_call', 'risky_operation', 'security_decision', 'skill_invocation', 'user_to_llm'],
    'AI_IAC_024': ['agent_to_agent', 'agent_to_llm', 'api_call', 'data_outbound', 'file_upload', 'llm_to_agent', 'llm_to_user', 'agent_to_user', 'user_to_agent', 'tool_to_user', 'user_to_tool', 'mcp_call', 'risky_operation', 'security_decision', 'skill_invocation', 'user_to_llm'],
    'AI_IAC_025': ['agent_to_agent', 'agent_to_llm', 'api_call', 'data_outbound', 'file_upload', 'llm_to_agent', 'llm_to_user', 'agent_to_user', 'user_to_agent', 'tool_to_user', 'user_to_tool', 'mcp_call', 'risky_operation', 'security_decision', 'skill_invocation', 'user_to_llm'],
    'AI_IAC_026': ['agent_to_agent', 'agent_to_llm', 'api_call', 'data_outbound', 'file_upload', 'llm_to_agent', 'llm_to_user', 'agent_to_user', 'user_to_agent', 'tool_to_user', 'user_to_tool', 'mcp_call', 'risky_operation', 'security_decision', 'skill_invocation', 'user_to_llm'],
    'AI_IAC_027': ['agent_to_agent', 'agent_to_llm', 'api_call', 'data_outbound', 'file_upload', 'llm_to_agent', 'llm_to_user', 'agent_to_user', 'user_to_agent', 'tool_to_user', 'user_to_tool', 'mcp_call', 'risky_operation', 'security_decision', 'skill_invocation', 'user_to_llm'],
    'AI_IAC_028': ['agent_to_agent', 'agent_to_llm', 'api_call', 'data_outbound', 'file_upload', 'llm_to_agent', 'llm_to_user', 'agent_to_user', 'user_to_agent', 'tool_to_user', 'user_to_tool', 'mcp_call', 'risky_operation', 'security_decision', 'skill_invocation', 'user_to_llm'],
    'AI_IAC_029': ['agent_to_agent', 'agent_to_llm', 'api_call', 'data_outbound', 'file_upload', 'llm_to_agent', 'llm_to_user', 'agent_to_user', 'user_to_agent', 'tool_to_user', 'user_to_tool', 'mcp_call', 'risky_operation', 'security_decision', 'skill_invocation', 'user_to_llm'],
    'AI_IAC_030': ['agent_to_agent', 'agent_to_llm', 'api_call', 'data_outbound', 'file_upload', 'llm_to_agent', 'llm_to_user', 'agent_to_user', 'user_to_agent', 'tool_to_user', 'user_to_tool', 'mcp_call', 'risky_operation', 'security_decision', 'skill_invocation', 'user_to_llm'],
    'AI_IAC_031': ['agent_to_llm', 'llm_to_agent', 'llm_to_user', 'agent_to_user', 'user_to_agent', 'tool_to_user', 'user_to_tool', 'user_to_llm'],
    'AI_SKILL_DAT_SEC_001': ['agent_to_agent', 'agent_to_llm', 'data_outbound', 'file_upload', 'llm_to_agent', 'llm_to_user', 'agent_to_user', 'user_to_agent', 'tool_to_user', 'user_to_tool', 'mcp_call', 'risky_operation', 'security_decision', 'skill_invocation', 'user_to_llm'],
    'AI_SKILL_SEC_001': ['agent_to_agent', 'agent_to_llm', 'data_outbound', 'file_upload', 'llm_to_agent', 'llm_to_user', 'agent_to_user', 'user_to_agent', 'tool_to_user', 'user_to_tool', 'mcp_call', 'risky_operation', 'security_decision', 'skill_invocation', 'user_to_llm'],
    'AI_SKILL_SEC_002': ['agent_to_agent', 'agent_to_llm', 'data_outbound', 'file_upload', 'llm_to_agent', 'llm_to_user', 'agent_to_user', 'user_to_agent', 'tool_to_user', 'user_to_tool', 'mcp_call', 'risky_operation', 'security_decision', 'skill_invocation', 'user_to_llm'],
    'AI_SKILL_SEC_003': ['agent_to_agent', 'agent_to_llm', 'data_outbound', 'file_upload', 'llm_to_agent', 'llm_to_user', 'agent_to_user', 'user_to_agent', 'tool_to_user', 'user_to_tool', 'mcp_call', 'risky_operation', 'security_decision', 'skill_invocation', 'user_to_llm'],
    'AI_VULN_SEC_002': ['agent_to_agent', 'agent_to_llm', 'api_call', 'data_outbound', 'db_read', 'file_upload', 'llm_to_agent', 'llm_to_user', 'agent_to_user', 'user_to_agent', 'tool_to_user', 'user_to_tool', 'mcp_call', 'risky_operation', 'security_decision', 'skill_invocation', 'user_to_llm'],
    'AI_VULN_SEC_005': ['agent_to_agent', 'agent_to_llm', 'api_call', 'data_outbound', 'file_upload', 'llm_to_agent', 'llm_to_user', 'agent_to_user', 'user_to_agent', 'tool_to_user', 'user_to_tool', 'mcp_call', 'risky_operation', 'security_decision', 'skill_invocation', 'user_to_llm'],
    'AI_VULN_SEC_006': ['agent_to_agent', 'agent_to_llm', 'data_outbound', 'file_upload', 'llm_to_agent', 'llm_to_user', 'agent_to_user', 'user_to_agent', 'tool_to_user', 'user_to_tool', 'mcp_call', 'risky_operation', 'security_decision', 'skill_invocation', 'user_to_llm'],
    'AI_VULN_SEC_007': ['agent_to_agent', 'agent_to_llm', 'api_call', 'data_outbound', 'file_upload', 'llm_to_agent', 'llm_to_user', 'agent_to_user', 'user_to_agent', 'tool_to_user', 'user_to_tool', 'mcp_call', 'risky_operation', 'security_decision', 'skill_invocation', 'user_to_llm'],
}

# Every routine/policy also applies at function-return (data_egress) and
# log/print (log_emit) sites — those two regexes are the catch-all hops
# that aren't named in the original content-mapped lists.
for _pid, _ips in _POLICY_INSERTION_POINTS.items():
    for _extra in ("data_egress", "log_emit"):
        if _extra not in _ips:
            _ips.append(_extra)

def _routine_backed_policy_ids() -> "set[str]":
    """The ONLY source of truth for 'this policy has real runtime enforcement
    behind it': a direct, in-process import of guardrail_service's routine
    registry (pure Python, self-registers via @register decorators at import
    time -- no network call, no GR service HTTP round trip, no database).

    Fails closed: returns an empty set if guardrail_service isn't importable
    from this process (e.g. a deployment that only ships mcp_server.py). An
    empty set here means hardcoded_insertion_point_map() below claims NOTHING
    is covered rather than falling back to the old broad content-mapped list
    -- no coverage claim without proof."""
    try:
        _gr_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "guardrail_service")
        import sys as _sys
        if _gr_dir not in _sys.path:
            _sys.path.insert(0, _gr_dir)
        import gr_service.routines  # noqa: F401 -- self-registers every built-in routine
        from gr_service.routines.registry import registered_policy_ids
        return registered_policy_ids()
    except Exception:
        return set()


def _signature_verified_policy_ids() -> "set[str] | None":
    """Pre-insertion trust check (pulled forward from the routine-code-signing
    plan): verify each registered routine's CURRENT compiled bytecode against
    a signed manifest, not just "is a Python function registered under this
    name" (which is all _routine_backed_policy_ids() above checks). Opt-in,
    gated behind UNIFAI_VERIFY_ROUTINE_SIGNATURES=1 -- returns None (not a
    set) when unset or when no signed manifest/key exists yet, so
    hardcoded_insertion_point_map() can fall back to the pre-existing
    existence-only behavior instead of silently trusting nothing (which
    would break every scan in an environment that hasn't run
    scripts/sign_routines.py yet, including this repo's own huge existing
    test suite). When it IS configured, a routine whose registered function
    doesn't match the signed digest is EXCLUDED from stub-insertion coverage
    entirely -- fail closed on a signature mismatch, not fail open.

    Distinct from _routine_backed_policy_ids()'s file I/O-free contract:
    this one real disk read (the signature manifest + dev-signing key,
    both local files, no network) is the necessary cost of an actual trust
    check instead of a bare existence lookup."""
    import os as _os
    if _os.environ.get("UNIFAI_VERIFY_ROUTINE_SIGNATURES", "").strip().lower() not in ("1", "true", "yes"):
        return None
    db_path = _os.environ.get("GR_DB_PATH", "./gr_policies.db")
    try:
        _gr_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "guardrail_service")
        import sys as _sys
        if _gr_dir not in _sys.path:
            _sys.path.insert(0, _gr_dir)
        import gr_service.routines  # noqa: F401 -- self-registers every built-in routine
        from gr_service.routines.registry import _ROUTINE_MAP
        from gr_service.routines import routine_signing
        from gr_service.policy_source import dev_signing

        manifest = routine_signing.load_routine_signatures(db_path)
        if manifest is None:
            _logger.warning(
                "insertion_point_scanner: UNIFAI_VERIFY_ROUTINE_SIGNATURES=1 but no "
                "routine_signatures.json found next to %r -- run scripts/sign_routines.py "
                "first; falling back to existence-only routine coverage for this scan",
                db_path,
            )
            return None
        key = dev_signing.load_or_create_key(db_path)
        return routine_signing.verified_policy_ids(dict(_ROUTINE_MAP), manifest, key)
    except Exception as exc:
        _logger.warning(
            "insertion_point_scanner: routine signature verification failed (%s) -- "
            "falling back to existence-only routine coverage for this scan", exc,
        )
        return None


def hardcoded_insertion_point_map() -> "dict[str, list[dict]]":
    """{insertion_point -> [{policy_id, name}, ...]}, filtered to policies that
    have an ACTUAL registered enforcement routine (_routine_backed_policy_ids()
    above) -- never a policy that's merely content-mapped to this insertion_point
    in aiepo-content with nothing behind it. No file I/O, no live network call,
    no database: this is the sole source of policy-coverage claims for guardrail
    stub scanning -- GR_SERVICE_URL is never queried at scan time (see adapter.py's
    _scan_stub_insertions_readonly), since that would (a) require a network
    dependency during a source-code scan and (b) surface every content-mapped
    policy regardless of whether anything actually enforces it.

    When UNIFAI_VERIFY_ROUTINE_SIGNATURES=1 is set (see
    _signature_verified_policy_ids()), this filters further: a policy_id
    whose registered routine's compiled code doesn't match a signed digest
    is excluded even though it's genuinely registered -- the pre-insertion
    trust check, not just an existence check."""
    routine_ids = _routine_backed_policy_ids()
    verified_ids = _signature_verified_policy_ids()
    if verified_ids is not None:
        routine_ids = routine_ids & verified_ids
    mapping: "dict[str, list[dict]]" = {}
    for policy_id, ips in _POLICY_INSERTION_POINTS.items():
        if policy_id not in routine_ids:
            continue
        name = _POLICY_CATALOG.get(policy_id, policy_id)
        for ip in ips:
            mapping.setdefault(ip, []).append({"policy_id": policy_id, "name": name})
    return mapping


def _scan_annotations(
    file_path: str,
    source: str,
    lineaje_pat: str,
    insertion_point_types: list[str] | None,
    policy_map: dict[str, list[dict]] | None,
    companion_hops: int = 0,
) -> list[InsertionCandidate]:
    """Scan for @gr:insertion_point= annotations.  Language-agnostic, highest priority.

    A single pass over raw source lines — no grammar, no AST.  Works for any
    language in _SCANNABLE_EXTENSIONS (and any new language added later).

    Rules:
    - Annotation on a comment-only line → target is the NEXT non-blank code line
      (up to 5 lines ahead; skips over blank lines and adjacent comment lines).
    - Annotation inline on a code line  → target is that same line.
    - insert_after defaults from _LHS_INSERTION_POINTS when not specified.
    - variable= is optional; falls back to _extract_variable() on the target line.
      If extraction also fails, safe_to_insert=False so the coding agent reviews it.
    - Stubs already present (detected by _STUB_MARKERS) are skipped — idempotent.
    """
    lines = source.splitlines()
    n = len(lines)
    file_ext = Path(file_path).suffix.lower()

    _STUB_MARKERS = (
        "gr_check(", "grCheck(", "GRBlockedError",
        "GR_SERVICE_URL", "LINEAJE_PAT", "GR_BEARER_TOKEN",
        "_gr_req", "_gr_resp", "_gr_call", "_grResp", "_grConn",
        '"insertion_point"', "_grUrl",
        # Current VIII.5/VIII.6 stub shape (SiteDescriptor + .check()) — see
        # the sibling _STUB_MARKERS tuple's comment above for the gap this closes.
        "_lineaje_load_gr_client", "_gr_client.check(", "_gr_client.enforce(", "_gr_decision", "SiteDescriptor(",
    )
    _GUARD_WINDOW = 15

    def _already_guarded(lineno: int) -> bool:
        start = max(0, lineno - _GUARD_WINDOW - 1)
        end = min(n, lineno + _GUARD_WINDOW)
        return any(
            any(mk in lines[k] for mk in _STUB_MARKERS)
            for k in range(start, end)
        )

    candidates: list[InsertionCandidate] = []
    seen: set[tuple[str, int]] = set()

    for i, raw_line in enumerate(lines):
        m = _GR_ANNOTATION_RE.search(raw_line)
        if m is None:
            continue

        ip: str = m.group(1)
        explicit_var: str = m.group(2) or ""
        insert_after_str: str | None = m.group(3)

        # Filter to requested insertion point types when caller specified them
        if insertion_point_types is not None and ip not in insertion_point_types:
            continue

        is_comment_only = bool(_COMMENT_ONLY_RE.match(raw_line))
        if is_comment_only:
            # Annotation on its own comment line — find the next non-blank code line
            target_idx: int | None = None
            for j in range(i + 1, min(i + 6, n)):
                stripped = lines[j].strip()
                if stripped and not _COMMENT_ONLY_RE.match(lines[j]):
                    target_idx = j
                    break
            if target_idx is None:
                continue
            target_lineno = target_idx + 1          # 1-based
            context_line = lines[target_idx]
        else:
            # Inline annotation (e.g. code + trailing comment)
            target_lineno = i + 1                   # 1-based
            context_line = raw_line

        if _already_guarded(target_lineno):
            continue

        key = (ip, target_lineno)
        if key in seen:
            continue
        seen.add(key)

        # insert_after: annotation override > _LHS_INSERTION_POINTS default
        if insert_after_str is not None:
            insert_after = insert_after_str.lower() == "true"
        else:
            insert_after = ip in _LHS_INSERTION_POINTS

        # Resolve variable
        if explicit_var:
            variable = explicit_var
            safe = True
            skip_reason = ""
        else:
            hint = "lhs" if insert_after else "arg1"
            variable = _extract_variable(
                context_line,
                hint,
                context_lines=lines[:target_lineno - 1],
                following_lines=lines[target_lineno: target_lineno + 10],
            )
            if variable:
                safe = True
                skip_reason = ""
            else:
                variable = "data"
                safe = False
                skip_reason = (
                    "variable= not specified in @gr annotation and could not be "
                    "extracted from the target line — add variable=<name> to the "
                    "@gr:insertion_point annotation before inserting"
                )

        indent = context_line[: len(context_line) - len(context_line.lstrip())]
        # Detect async context so the stub uses await (async) vs void+catch (sync).
        if file_ext in (".py",):
            is_async = _is_async_context(lines, target_lineno)
        elif file_ext in (".js", ".ts", ".jsx", ".tsx"):
            # Walk backwards from the target line to find the enclosing function
            # declaration. Any 'async function' or '=>' preceded by 'async' means
            # the stub can use await; otherwise use void+catch (fire-and-forget).
            _async_re = re.compile(r"\basync\b")
            _fn_re = re.compile(r"\b(function|=>|\bclass\b)\b")
            is_async = False
            for _li in range(target_lineno - 1, max(0, target_lineno - 60), -1):
                _l = lines[_li] if _li < len(lines) else ""
                if _async_re.search(_l) and _fn_re.search(_l):
                    is_async = True
                    break
                if _fn_re.search(_l):
                    break  # found a function boundary, not async
        else:
            is_async = False
        policy_reasons = list(policy_map.get(ip, [])) if policy_map else []
        policy_ids = [pr["policy_id"] for pr in policy_reasons]
        stub_line = _make_stub_line(
            variable, ip, lineaje_pat, indent, file_ext,
            is_async=is_async,
            insert_after=insert_after,
            candidate_policy_ids=policy_ids,
        )

        candidates.append(InsertionCandidate(
            file=file_path,
            line=target_lineno,
            insertion_point=ip,
            pattern_matched=f"annotation:@gr:insertion_point={ip}",
            context_line=context_line.rstrip(),
            suggested_variable=variable,
            description=(
                f"Developer-annotated guardrail boundary ({ip}) at line {target_lineno} — "
                "explicit annotation; evolves with the code, takes priority over "
                "pattern-matched stubs on the same line"
            ),
            proposed_stub=stub_line,
            safe_to_insert=safe,
            skip_reason=skip_reason,
            policy_ids=policy_ids,
            policy_reasons=policy_reasons,
            insert_after=insert_after,
            variable_to_use_in_call="",
            companion_hops=companion_hops,
        ))

    return candidates


# ── Site identity: canonical phase + boundary translation (Phase 6a) ────────
# This scanner's insertion_point vocabulary conflates source/sink/phase into
# one flat string (agent_to_llm, db_read, ...) rather than the design doc's
# three independent axes (VI.2: phase is one of a closed 8-value set; source
# and sink are separate classifications). This table is a best-effort,
# NOT-verified-per-call derivation from that flat vocabulary onto the three
# axes — good enough to drive candidate_when set-membership matching; not a
# substitute for real per-call data-flow analysis (see PLAN.md Phase 6a).
#
# insertion_point -> (canonical_phase, boundary_source, boundary_sink)
_PHASE_AND_BOUNDARY_BY_INSERTION_POINT: dict[str, tuple[str, str, str]] = {
    "agent_to_llm":     ("pre_model",          "agent_message",  "model"),
    "user_to_llm":      ("pre_model",          "user_interface", "model"),
    "ui_to_llm":        ("pre_model",          "user_interface", "model"),
    "llm_to_agent":     ("post_model",         "model",          "agent_message"),
    "agent_to_agent":   ("pre_agent_send",     "agent_message",  "agent_message"),
    "ui_to_agent":      ("post_agent_receive", "user_interface", "agent_message"),
    "db_read":          ("post_tool",          "database",       "agent_message"),
    "api_call":         ("post_tool",          "external_endpoint", "agent_message"),
    "mcp_call":         ("post_tool",          "tool_result",    "agent_message"),
    "skill_invocation": ("pre_tool",           "agent_message",  "tool_result"),
    "llm_to_user":      ("data_egress",        "model",          "user_interface"),
    "agent_to_ui":      ("data_egress",        "agent_message",  "user_interface"),
    "llm_to_ui":        ("data_egress",        "model",          "user_interface"),
    "data_outbound":    ("data_egress",        "agent_message",  "external_endpoint"),
    "file_upload":      ("data_egress",        "agent_message",  "external_endpoint"),
    "security_decision": ("security_decision", "agent_message",  "agent_message"),
    "risky_operation":  ("security_decision",  "agent_message",  "agent_message"),
    "agent_to_user":    ("data_egress",        "agent_message",  "user_interface"),
    "user_to_agent":    ("post_agent_receive", "user_interface", "agent_message"),
    "tool_to_user":     ("data_egress",        "tool_result",    "user_interface"),
    "user_to_tool":     ("pre_tool",           "user_interface", "tool_result"),
    "html_to_user":     ("data_egress",        "html",           "user_interface"),
    "data_egress":      ("data_egress",        "agent_message",  "user_interface"),
    # source=log (not agent_message): Job 2 set-membership is source ∩
    # candidate_when.sources. AI_DAT_SEC_010 lists log as a source class
    # (the payload is already at the log sink) as well as sink=log.
    "log_emit":         ("log_emit",           "log",            "log"),
}


def _canonical_phase_and_boundary(insertion_point: str) -> "tuple[str, dict]":
    """Look up (phase, {source, sink}) for an insertion_point. Falls back to
    security_decision (the most conservative canonical phase, never silently
    None) with a warning log when a future insertion_point is added without a
    table entry, so the gap is visible instead of swallowed."""
    entry = _PHASE_AND_BOUNDARY_BY_INSERTION_POINT.get(insertion_point)
    if entry is None:
        _logger.warning(
            "insertion_point_scanner: no phase/boundary mapping for "
            "insertion_point=%r — add an entry to "
            "_PHASE_AND_BOUNDARY_BY_INSERTION_POINT; defaulting to "
            "security_decision (the most conservative canonical phase)",
            insertion_point,
        )
        return "security_decision", {"source": "agent_message", "sink": "agent_message"}
    phase, source, sink = entry
    return phase, {"source": source, "sink": sink}


_SYMBOL_DEF_RE = re.compile(
    r"^\s*(?:export\s+)?(?:async\s+)?(?:def|function|func)\s+([A-Za-z_][A-Za-z0-9_]*)"
    r"|^\s*(?:public|private|protected|static)?\s*[\w<>\[\],\s]+?\s+([A-Za-z_][A-Za-z0-9_]*)\s*\("
)


def _enclosing_symbol(lines: "list[str]", lineno: int) -> str:
    """Best-effort nearest-preceding function/method definition above `lineno`
    (1-based) — used only to make site_id stable-and-distinguishing, not a
    real symbol-table lookup. Returns "" for module-level code (still a valid,
    stable site_id keyed on file+insertion_point+pattern)."""
    for i in range(min(lineno, len(lines)) - 1, -1, -1):
        m = _SYMBOL_DEF_RE.match(lines[i])
        if m:
            return m.group(1) or m.group(2) or ""
    return ""


def _derive_site_id(rel_file: str, symbol: str, insertion_point: str, pattern_matched: str) -> str:
    """Deterministic site identity: sha256 over the repo-relative file path,
    enclosing symbol name, insertion_point, and the matched pattern's own text
    — not raw line content, so incidental reformatting doesn't change
    identity, while the boundary moving to a different symbol or matching a
    different pattern does. v0 fingerprint; full AST-shape hashing is a
    documented fast-follow (PLAN.md Phase 6a)."""
    basis = f"{rel_file}::{symbol}::{insertion_point}::{pattern_matched}"
    digest = hashlib.sha256(basis.encode("utf-8")).hexdigest()
    return f"site:sha256:{digest}"


# ── PII-in-UI-output detection (cross-language, "llm_to_user") ──────────────
# Neither the call-shaped _PATTERNS table above nor the AST call-classifier
# (_ast_classify) can see this shape at all: `html = f"...{record['ssn']}..."`
# / `return html` has no ast.Call node on the line that actually matters — the
# f-string build and the bare-name return are both non-call constructs. That's
# a real, confirmed gap (AI_DAT_SEC_012 "Mask PII on user interfaces" lists
# "llm_to_user" as one of its insertion points in _POLICY_INSERTION_POINTS,
# but until this function, nothing ever produced a "llm_to_user" candidate).
#
# This is a line/text heuristic, not a real per-language parser, so it runs
# for every _SCANNABLE_EXTENSIONS language uniformly instead of needing a
# bespoke AST walker per grammar. Deliberately conservative in two ways:
#   1. It only fires when a PII-shaped field access (see _PII_FIELD_HINTS)
#      actually reaches a `return` statement or a recognized UI-response call
#      — building a PII-bearing string that's only ever logged/printed is
#      explicitly NOT a violation under this policy (see the sample fixture
#      this was built against), so logging/console sinks are excluded here
#      the same way the LLM evaluator excludes them. Exception: in a Python
#      ``if __name__ == "__main__"`` block, ``print(response)`` after
#      ``response = render_*(...)`` / ``chat_*_response(...)`` is the script's
#      actual user-facing display, so we also emit a consumer-side site
#      immediately after that assignment (insert_after), before the print.
#   2. Same-function tracking is a bounded forward line-scan, not real
#      dataflow/scope analysis — good enough for the common "build then
#      return a few lines later" shape, not a substitute for a real taint
#      analyzer (see semgrep_taint_scanner.py's confirm_with_taint_analysis
#      for that).
_PII_FIELD_HINTS: frozenset[str] = frozenset({
    "ssn", "socialsecurity", "socialsecuritynumber",
    "dob", "dateofbirth", "birthdate", "birthplace",
    "passport", "passportnumber",
    "driverslicense", "driverlicense", "licensenumber",
    "taxid", "taxpayerid", "taxpayer",
    "creditcard", "cardnumber", "cvv",
    "bankaccount", "accountnumber", "routingnumber", "financialaccount",
    "maidenname", "mothersmaidenname",
    "homeaddress", "streetaddress", "mailingaddress",
    "phone", "phonenumber", "mobilenumber",
    "yearofbirth",
    "employeeid",
    "ipaddress",
    "nationalid",
    "medicalrecord", "healthrecord", "insurancenumber",
    "biometric",
    "vin",
    "email",
})

# Extracts candidate field/key identifiers from a blob of source text:
#   .attr / .getSsn()      -- attribute or getter access
#   ['ssn'] / ["ssn"]      -- dict/map subscript access
#   get_ssn() / getSsn()   -- explicit getter call, snake_case or camelCase
_PII_IDENT_EXTRACT_RE = re.compile(
    r"\.([A-Za-z_][A-Za-z0-9_]*)"
    r"|\[\s*['\"]([A-Za-z_][A-Za-z0-9_]*)['\"]\s*\]"
    r"|\bget_?([A-Za-z_][A-Za-z0-9_]*)\s*\("
)


def _normalize_ident(s: str) -> str:
    return re.sub(r"[^a-z0-9]", "", s.lower())


_PII_HINT_NORMS: frozenset[str] = frozenset(_normalize_ident(h) for h in _PII_FIELD_HINTS)


def _pii_hint_in_text(text: str) -> "str | None":
    """Return the matched identifier if `text` references a field/key whose
    name looks like a PII attribute (e.g. "ssn", "record['ssn']",
    "getDateOfBirth()"), else None."""
    for m in _PII_IDENT_EXTRACT_RE.finditer(text):
        ident = m.group(1) or m.group(2) or m.group(3)
        if not ident:
            continue
        norm = _normalize_ident(ident)
        if any(hint in norm for hint in _PII_HINT_NORMS):
            return ident
    return None


# Attribute names that conventionally carry an LLM/RAG response payload —
# arbitrary user-supplied document/chat content whose PII risk is inherent to
# the CODE SHAPE (any uploaded/retrieved text can carry PII at runtime), not
# to a named field _PII_FIELD_HINTS could match. Confirmed gap: a Chainlit
# RAG chatbot streaming ``chunk.answer`` and rendering a LangChain
# ``Document.page_content`` straight to the UI produced zero hits under the
# field-name heuristic above — there is no PII field NAME anywhere in that
# source, the leak only exists in the uploaded document's runtime content.
# Kept narrower than a bare ``.content``/``.text`` match (too generic —
# unrelated objects like HTTP response bytes use those names too) — these
# are the conventional attribute names of an LLM/RAG SDK's response object
# (LangChain's ``Document.page_content``/``.output_text``, quivr/most
# chat-completion wrappers' ``.answer``, OpenAI-style ``.completion``,
# HuggingFace's ``generated_text``).
_LLM_PASSTHROUGH_ATTR_HINTS: frozenset[str] = frozenset({
    "answer", "page_content", "output_text", "completion",
    "response_text", "generated_text", "assistant_message",
})
_LLM_PASSTHROUGH_ATTR_RE = re.compile(
    r"\.(" + "|".join(sorted(_LLM_PASSTHROUGH_ATTR_HINTS)) + r")\b"
)


def _llm_passthrough_hint_in_text(text: str) -> "str | None":
    """Return the matched attribute name if `text` accesses an LLM/RAG
    response-payload attribute (see _LLM_PASSTHROUGH_ATTR_HINTS), else None."""
    m = _LLM_PASSTHROUGH_ATTR_RE.search(text)
    return m.group(1) if m else None


# Sinks explicitly exempt from AI_DAT_SEC_012 (PII-in-UI): internal
# logs/console output are NOT "user interfaces". They ARE the log_emit
# insertion point (AI_DAT_SEC_010) — keep this regex in sync with the
# log_emit entry in _PATTERNS.
_LOGGING_SINK_RE = re.compile(
    r"\bprint\s*\("
    r"|\bconsole\.(?:log|debug|info|warn|error|trace)\s*\("
    r"|\blogger\.\w+\s*\("
    r"|\blogging\.\w+\s*\("
    r"|\blog\.\w+\s*\("
    r"|\bSystem\.(?:out|err)\.print\w*"
    r"|\bfmt\.Print(?:ln|f)?\s*\("
)

# Calls that hand data directly to an end user / UI surface — the actual
# "sink=user_interface" boundary AI_DAT_SEC_012 targets. Deliberately spans
# every _SCANNABLE_EXTENSIONS language (Python web frameworks + Streamlit,
# Node/Express/Next, Java Spring/Servlet, Go net/http/gin) since this
# detector is language-agnostic by design.
#
# Chainlit (`stream_token` / `cl.Text` / `cl.Message`) and Gradio
# (`gr.Textbox`/`gr.Markdown`/`gr.HTML`) added for chat/RAG-UI frameworks —
# a Chainlit chatbot streaming a RAG answer via
# ``await msg.stream_token(chunk.answer)`` or rendering a retrieved chunk via
# ``cl.Text(content=source.page_content, ...)`` is exactly the
# "sink=user_interface" shape this regex exists to catch, and previously had
# no match here at all.
_UI_SINK_CALL_RE = re.compile(
    r"\bjsonify\s*\("
    r"|\bmake_response\s*\("
    r"|\brender_template\w*\s*\("
    r"|\bHttpResponse\s*\("
    r"|\bJsonResponse\s*\("
    r"|\bJSONResponse\s*\("
    r"|\bTemplateResponse\s*\("
    r"|\bst\.(?:write|markdown|text)\s*\("
    r"|\bres\.(?:send|json|render)\s*\("
    r"|\bresponse\.write\s*\("
    r"|\bNextResponse\.json\s*\("
    r"|\bResponseEntity\.\w+\s*\("
    r"|\.getWriter\(\)\.(?:write|print)\w*\s*\("
    r"|\bw\.Write\s*\("
    r"|\bfmt\.Fprintf?\s*\(\s*w\b"
    r"|\bc\.(?:JSON|String)\s*\("
    r"|\bstream_token\s*\("
    r"|\bcl\.(?:Text|Message)\s*\("
    r"|\bgr\.(?:Textbox|Markdown|HTML)\s*\("
)

_PII_UI_ASSIGN_RE = re.compile(
    r"^\s*(?:const\s+|let\s+|var\s+|[A-Za-z_][\w.<>\[\],\s]*\s+)?"
    r"([A-Za-z_][A-Za-z0-9_]*)\s*(?::=|=)(?!=)\s*"
)
_PII_UI_BARE_RETURN_RE = re.compile(r"^\s*return\s+([A-Za-z_][A-Za-z0-9_]*)\s*;?\s*$")

_MAIN_GUARD_RE = re.compile(r"""^\s*if\s+__name__\s*==\s*['\"]__main__['\"]\s*:""")
_MAIN_RESPONSE_ASSIGN_RE = re.compile(
    r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*([A-Za-z_][A-Za-z0-9_\.]*)\s*\("
)
# Callee must look like it produced a user-facing body — not a raw DB fetch
# (`get_user_record`) that is only printed for debugging.
_MAIN_RESPONSE_CALLEE_HINTS = (
    "render", "page", "view", "response", "reply", "html",
    "agent", "chat", "profile", "display", "template",
)


def _python_main_block_range(lines: "list[str]") -> "tuple[int, int] | None":
    """1-based [start, end) of the suite under ``if __name__ == "__main__":``."""
    start = None
    guard_indent = 0
    for i, line in enumerate(lines):
        if _MAIN_GUARD_RE.match(line):
            start = i
            guard_indent = len(line) - len(line.lstrip())
            break
    if start is None:
        return None
    end = len(lines)
    for j in range(start + 1, len(lines)):
        if not lines[j].strip() or lines[j].lstrip().startswith("#"):
            continue
        if (len(lines[j]) - len(lines[j].lstrip())) <= guard_indent:
            end = j
            break
    return (start + 2, end + 1)  # 1-based; suite starts on the line after the if


def _main_line_prints_var(line: str, var: str) -> bool:
    if not re.search(r"\b(?:print|sys\.stdout\.write)\s*\(", line):
        return False
    return bool(re.search(rf"\b{re.escape(var)}\b", line))


def _main_response_interaction_type(callee: str, var: str) -> str:
    callee_l = (callee or "").lower()
    var_l = (var or "").lower()
    if any(h in callee_l or h in var_l for h in _AGENT_UI_NAME_HINTS):
        return "agent_to_user"
    if any(h in callee_l or h in var_l for h in ("html", "page", "render", "template", "view")):
        return "html_to_user"
    return _guess_interaction_type(callee, var, callee)

# Name hints for _guess_interaction_type. Checked in this order — an agent
# hint wins even when a tool-ish word also appears — so a function like
# "chat_agent_response" assigning to "agent_reply" lands on agent_to_user,
# not tool_to_user, even though "response"/"reply" could otherwise read as
# just "a function returned something".
_AGENT_UI_NAME_HINTS = ("agent", "chat", "assistant", "bot", "llm", "conversation")
_TOOL_UI_NAME_HINTS = (
    "render", "page", "view", "handler", "route", "endpoint",
    "template", "profile", "report", "html",
)
# Markup that means the payload is an HTML document/fragment, not a chat
# reply or a JSON/plain tool body. Checked after agent hints so
# chat_agent_response stays agent_to_user even if a comment mentions HTML.
_HTML_MARKUP_RE = re.compile(
    r"<\s*(?:html|body|head|div|p|span|table|tr|td|ul|ol|li|h[1-6]|form|"
    r"input|label|section|article|main|header|footer|nav)\b",
    re.IGNORECASE,
)


def _looks_like_html(var_name: str, window_text: str) -> bool:
    var_l = (var_name or "").lower()
    if var_l == "html" or var_l.endswith("html"):
        return True
    return bool(_HTML_MARKUP_RE.search(window_text or ""))


def _guess_interaction_type(func_name: str, var_name: str, window_text: str) -> str:
    """Best-effort edge label for a PII-bearing string reaching a `return` /
    UI-response call — NOT a guarantee of who actually produced it, just a
    first-pass triage label distinguishing:
      - agent_to_user — an agent/LLM-authored reply surfaces PII (function/
        variable naming suggests a chat/agent/assistant reply path)
      - html_to_user  — a rendered HTML document/fragment is sent to the UI
        (source=html; AI_DAT_SEC_012 candidate_when includes this class so
        the assembled HTML string is the payload to mask)
      - tool_to_user  — a plain data-fetch-and-render function returns a
        non-HTML body (JSON/text) with no agent/LLM in the loop at all
    Defaults to agent_to_user when neither hint fires — the same default the
    "producer is unclear, but it did reach the user" case should take.
    user_to_agent/user_to_tool (the reverse direction) aren't reachable from
    this specific egress-only detector, but share the same insertion_point
    vocabulary — see _PHASE_AND_BOUNDARY_BY_INSERTION_POINT."""
    func_l = (func_name or "").lower()
    var_l = (var_name or "").lower()
    if any(h in func_l or h in var_l for h in _AGENT_UI_NAME_HINTS):
        return "agent_to_user"
    if _looks_like_html(var_name, window_text):
        return "html_to_user"
    if any(h in func_l or h in var_l for h in _TOOL_UI_NAME_HINTS):
        return "tool_to_user"
    return "agent_to_user"


_PII_UI_WINDOW = 30    # lines joined to check "does this string/expr carry PII"
_PII_UI_FORWARD = 40   # lines scanned forward for a later return/sink use

# Well-known-format, entirely-synthetic canary values used ONLY for the
# scan-time "enforcement proof" (guardrail_stub_insertion.py's
# _verify_enforcement) — never embedded in the generated stub, never derived
# from real customer data. gr_service's PII routine (enforce_pii_masking)
# detects PII by VALUE PATTERN — Presidio NER + regex over actual SSN/
# credit-card/email/phone-shaped strings — not by source-code identifier
# names. Sending raw source text like `record['ssn']` or the surrounding
# f-string literal can NEVER trip it: that text has no PII-shaped value in
# it at all, only a field name referencing one that will only exist at
# customer runtime. Without a real value to test, the proof always comes
# back "allow" regardless of whether the site is wired correctly — which
# defeats the point of a proof. These canaries give the probe an actual
# value shaped like the category the matched field hints at, so the proof
# exercises the same detector real runtime traffic would hit.
_SYNTHETIC_PII_CANARIES: tuple[tuple[str, str], ...] = (
    ("ssn", "123-45-6789"),
    ("socialsecurity", "123-45-6789"),
    ("creditcard", "4111 1111 1111 1111"),
    ("cardnumber", "4111 1111 1111 1111"),
    ("cvv", "123"),
    ("passport", "X12345678"),
    ("driverslicense", "D1234-5678-9012"),
    ("driverlicense", "D1234-5678-9012"),
    ("licensenumber", "D1234-5678-9012"),
    ("email", "jane.doe@example.com"),
    ("phone", "+1-555-019-2837"),
    ("phonenumber", "+1-555-019-2837"),
    ("mobilenumber", "+1-555-019-2837"),
    ("yearofbirth", "1988"),
    ("employeeid", "EMP-04471"),
    ("ipaddress", "203.0.113.42"),
    ("vin", "1HGCM82633A004352"),
    ("bankaccount", "ACCT-00981234567"),
    ("accountnumber", "ACCT-00981234567"),
    ("routingnumber", "021000021"),
    ("financialaccount", "ACCT-00981234567"),
    ("taxid", "98-7654321"),
    ("taxpayerid", "98-7654321"),
    ("nationalid", "998-76-5432"),
    ("homeaddress", "742 Evergreen Terrace, Springfield, IL 62704"),
    ("streetaddress", "742 Evergreen Terrace, Springfield, IL 62704"),
    ("mailingaddress", "742 Evergreen Terrace, Springfield, IL 62704"),
    ("dob", "1988-04-12"),
    ("dateofbirth", "1988-04-12"),
    ("birthdate", "1988-04-12"),
    ("maidenname", "Callahan"),
    ("mothersmaidenname", "Callahan"),
    ("medicalrecord", "MRN-00219931"),
    ("healthrecord", "MRN-00219931"),
    ("insurancenumber", "INS-77201943"),
    ("biometric", "fp:6d3f9a1c-scan"),
)


def _synthetic_pii_probe(hint: str) -> str:
    """A representative, entirely-synthetic PII-shaped value for `hint` (the
    field identifier _pii_hint_in_text matched, e.g. "ssn", "home_address"),
    for use ONLY as the scan-time enforcement-proof payload — see
    _SYNTHETIC_PII_CANARIES above for why this exists. Falls back to a
    generic placeholder when `hint` doesn't match any known category (the
    proof still runs, just without a category-specific value shape to
    detect — better than silently reusing source code, which never has one
    either)."""
    norm = _normalize_ident(hint)
    for key, value in _SYNTHETIC_PII_CANARIES:
        if key in norm:
            return f"{hint}: {value}"
    return f"{hint}: <synthetic-pii-probe-value>"


def _scan_pii_ui_exposure(
    file_path: str,
    source: str,
    lineaje_pat: str,
    insertion_point_types: "list[str] | None",
    policy_map: "dict[str, list[dict]] | None",
    companion_hops: int,
    rel_file: "str | None" = None,
) -> "list[InsertionCandidate]":
    """Cross-language scan for PII flowing into a `return` or a UI-response
    call — see module comment above _PII_FIELD_HINTS for the exact gap this
    fills. Each hit is labeled agent_to_user, html_to_user, or tool_to_user by
    _guess_interaction_type rather than a single fixed "llm_to_user" —
    see that function's docstring. Returns [] immediately if the caller is
    filtering to insertion_point_types that don't overlap either possible
    label (mirrors every other path's insertion_point_types filter)."""
    _POSSIBLE_TYPES = ("agent_to_user", "tool_to_user", "html_to_user")
    # data_egress / llm_to_user are the schema-v2 / catalog names for the
    # same user_interface hop — a filtered scan keyed on the policy's
    # guardrail.insertion_point must still see these sites.
    _UI_WILDCARDS = frozenset({"data_egress", "llm_to_user"})
    _allowed_ui: "set[str] | None" = None
    if insertion_point_types is not None:
        _allowed_ui = set(insertion_point_types)
        if _allowed_ui & _UI_WILDCARDS:
            _allowed_ui.update(_POSSIBLE_TYPES)
        if not any(t in _allowed_ui for t in _POSSIBLE_TYPES):
            return []

    file_ext = Path(file_path).suffix.lower()
    lines = source.splitlines()
    candidates: list[InsertionCandidate] = []
    seen_lines: set[int] = set()
    main_range = _python_main_block_range(lines) if file_ext == ".py" else None

    _STUB_MARKERS = (
        "gr_check(", "grCheck(", "GRBlockedError", "GR_SERVICE_URL", "LINEAJE_PAT",
        "GR_BEARER_TOKEN", "_gr_req", "_gr_resp", "_gr_call", "_grResp",
        "_grConn", '"insertion_point"',
        # Current VIII.5/VIII.6 stub shape (SiteDescriptor + .check()) — see
        # the sibling _STUB_MARKERS tuple's comment above for the gap this
        # closes. Without this, _guarded_nearby() never recognized the
        # SiteDescriptor/.check() stub this module actually generates, so a
        # re-scan of an already-instrumented PII-in-UI site (e.g. a bare
        # `return html` reached by several PII field hints) kept emitting a
        # fresh, distinct candidate right next to the existing stub instead
        # of skipping it — the concrete duplicate-stub bug this closes.
        "_lineaje_load_gr_client", "_gr_client.check(", "_gr_client.enforce(", "_gr_decision", "SiteDescriptor(",
    )

    def _guarded_nearby(lineno: int) -> bool:
        start = max(0, lineno - 16)
        end = min(len(lines), lineno + 15)
        return any(any(m in lines[i] for m in _STUB_MARKERS) for i in range(start, end))

    def _emit(
        lineno: int, variable: str, safe: bool, skip_reason: str, hint: str, window_text: str,
        *, insert_after: bool = False, func_name: "str | None" = None,
        interaction_type: "str | None" = None, ignore_nearby: bool = False,
    ) -> None:
        if lineno in seen_lines:
            return
        if not ignore_nearby and _guarded_nearby(lineno):
            return
        func_name = func_name if func_name is not None else _enclosing_symbol(lines, lineno)
        if interaction_type is None:
            interaction_type = _guess_interaction_type(func_name, variable, window_text)
        if _allowed_ui is not None and interaction_type not in _allowed_ui:
            return
        seen_lines.add(lineno)
        indent_src = lines[lineno - 1] if lineno <= len(lines) else ""
        indent = indent_src[: len(indent_src) - len(indent_src.lstrip())]
        is_async = file_ext == ".py" and _is_async_context(lines, lineno)
        policy_reasons = list(policy_map.get(interaction_type, [])) if policy_map else []
        policy_ids = [pr["policy_id"] for pr in policy_reasons]
        pattern_matched = f"pii-ui-exposure:{hint}"
        _site_id = _derive_site_id(rel_file or file_path, func_name, interaction_type, pattern_matched)
        stub_line = _make_stub_line(
            variable if safe else "data", interaction_type, lineaje_pat, indent, file_ext,
            is_async=is_async, insert_after=insert_after,
            candidate_policy_ids=policy_ids, site_id=_site_id,
        )
        if safe and file_ext == ".py":
            _valid, _reason = _validate_stub_insertion(
                source, stub_line, lineno, _import_hint(file_ext), variable,
                insert_after=insert_after, stmt_end_line=lineno,
            )
            if not _valid:
                safe, skip_reason = False, _reason
                stub_line = _make_stub_line(
                    "data", interaction_type, lineaje_pat, indent, file_ext,
                    is_async=is_async, insert_after=insert_after,
                    candidate_policy_ids=policy_ids, site_id=_site_id,
                )
        candidates.append(InsertionCandidate(
            file=file_path,
            line=lineno,
            insertion_point=interaction_type,
            pattern_matched=pattern_matched,
            # rstrip only — NOT strip(): guardrail_stub_insertion.py's writer
            # derives the inserted stub's indent from this field's LEADING
            # whitespace (`context_line[:len(context_line)-len(context_line.
            # lstrip())]`), matching every other candidate path's convention
            # (raw_line.rstrip() in the regex loop below). Fully stripping it
            # here silently zeroed the indent for every candidate this
            # detector emitted, producing a stub at column 0 inside an
            # indented function body — a real SyntaxError caught only by
            # validate_python_source()'s post-hoc check, not by anything in
            # this module itself.
            context_line=lines[lineno - 1].rstrip() if lineno <= len(lines) else "",
            suggested_variable=variable if safe else "data",
            description=(
                f"PII-shaped field '{hint}' reaches a user-facing return/response "
                f"at line {lineno} ({interaction_type}) — mask before sending to the UI"
            ),
            proposed_stub=stub_line,
            safe_to_insert=safe,
            skip_reason=skip_reason,
            policy_ids=policy_ids,
            policy_reasons=policy_reasons,
            insert_after=insert_after,
            variable_to_use_in_call="",
            companion_hops=companion_hops,
            site_id=_site_id,
            stmt_end_line=lineno,
            # A synthetic, value-shaped canary for `hint` (see
            # _synthetic_pii_probe's docstring) rather than the raw source
            # window: gr_service's PII routine detects PII by VALUE PATTERN,
            # and source code (even the real assignment window this hint was
            # found in) never contains an actual PII-shaped value — only a
            # field name that will only hold one at customer runtime. Without
            # this, the scan-time enforcement proof always reports "allow"
            # regardless of whether the site is wired correctly at all.
            sample_text=_synthetic_pii_probe(hint),
        ))

    for i, line in enumerate(lines, start=1):
        if any(m in line for m in _STUB_MARKERS):
            continue
        stripped = line.strip()

        # Case 1 — bare-name return: `return html` / `return agentReply;`
        m = _PII_UI_BARE_RETURN_RE.match(stripped)
        if m:
            window = "\n".join(lines[i - 1: i - 1 + _PII_UI_WINDOW])
            hint = _pii_hint_in_text(window)
            if hint and not _LOGGING_SINK_RE.search(line):
                _emit(i, m.group(1), True, "", hint, window)
                continue

        # Case 2 — direct UI-sink call: `return jsonify(record)` / `res.send(html)`
        if _UI_SINK_CALL_RE.search(line) and not _LOGGING_SINK_RE.search(line):
            window = "\n".join(lines[max(0, i - 9): i])
            hint = _pii_hint_in_text(window)
            if hint:
                var = _extract_variable(
                    line, "arg1",
                    context_lines=lines[:i - 1],
                    following_lines=lines[i: i + 10],
                )
                if var:
                    _emit(i, var, True, "", hint, window)
                else:
                    _emit(
                        i, "data", False,
                        "PII-shaped field reaches a UI-response call, but the exact "
                        "argument variable could not be extracted — review and wrap "
                        "the response body manually before sending.",
                        hint, window,
                    )
                continue

            # Case 2b — LLM/RAG response payload reaches the same UI-sink
            # call, but with no named PII field anywhere in the code (see
            # _LLM_PASSTHROUGH_ATTR_HINTS): a chatbot streaming
            # `chunk.answer` or rendering a `Document.page_content` straight
            # to the UI is a PII risk by construction — the uploaded/
            # retrieved content is arbitrary at runtime — even though the
            # source never names a specific PII field for Case 2 to match.
            passthrough_hint = _llm_passthrough_hint_in_text(line)
            if passthrough_hint:
                var = _extract_variable(
                    line, "arg1",
                    context_lines=lines[:i - 1],
                    following_lines=lines[i: i + 10],
                )
                if var:
                    _emit(i, var, True, "", passthrough_hint, window, interaction_type="agent_to_user")
                else:
                    _emit(
                        i, "data", False,
                        "LLM/RAG response payload reaches a UI-sink call, but the "
                        "exact argument variable could not be extracted — review "
                        "and wrap the response body manually before sending.",
                        passthrough_hint, window, interaction_type="agent_to_user",
                    )
                continue

        # Case 3 — assignment now, returned/sent a few lines later.
        m = _PII_UI_ASSIGN_RE.match(line)
        if m:
            var = m.group(1)
            window = "\n".join(lines[i - 1: i - 1 + _PII_UI_WINDOW])
            hint = _pii_hint_in_text(window)
            if hint:
                for j in range(i, min(i + _PII_UI_FORWARD, len(lines))):
                    fline = lines[j]
                    if _LOGGING_SINK_RE.search(fline) and re.search(rf"\b{re.escape(var)}\b", fline):
                        continue  # this use is a log — keep looking, may ALSO be returned later
                    if re.search(rf"^\s*return\s+{re.escape(var)}\b", fline) or (
                        _UI_SINK_CALL_RE.search(fline) and re.search(rf"\b{re.escape(var)}\b", fline)
                    ):
                        _emit(j + 1, var, True, "", hint, window)
                        break

        # Case 4 — ``if __name__ == "__main__"``: a UI response assigned from
        # a render/chat/page call and later printed is the script's user-facing
        # display. Insert AFTER the assignment (payload exists) and before print.
        # Does not apply to debug ``print(record)`` inside functions (Case 3
        # still skips those via _LOGGING_SINK_RE).
        if main_range and main_range[0] <= i < main_range[1]:
            am = _MAIN_RESPONSE_ASSIGN_RE.match(line)
            if am:
                var, callee = am.group(1), am.group(2)
                callee_l = callee.lower()
                if (
                    not var.startswith("_")
                    and any(h in callee_l for h in _MAIN_RESPONSE_CALLEE_HINTS)
                ):
                    printed = any(
                        _main_line_prints_var(lines[j - 1], var)
                        for j in range(i, main_range[1])
                    )
                    if printed:
                        _emit(
                            i, var, True, "", "main-response",
                            f"{line}\n{callee}",
                            insert_after=True,
                            func_name="__main__",
                            interaction_type=_main_response_interaction_type(callee, var),
                            ignore_nearby=True,
                        )

    return candidates


def _scan_file_core(
    file_path: str,
    lineaje_pat: str = "",
    insertion_point_types: list[str] | None = None,
    policy_map: dict[str, list[dict]] | None = None,
    project_root: str | None = None,
) -> "tuple[list[InsertionCandidate], list[MiddlewareCandidate]]":
    """Scan a single file and return insertion candidates.

    Args:
        file_path: Absolute path to the file to scan.
        lineaje_pat: Lineaje PAT embedded in generated stubs (used at runtime by the stub).
        insertion_point_types: If provided, only return candidates for these insertion_point
            types. Pass the list of types relevant to a specific policy violation so the
            scan is targeted rather than scanning all patterns.
        policy_map: Optional {insertion_point → [{policy_id, name}, ...]} mapping from the GR
            service (see fetch_insertion_point_map). When provided, each candidate's
            policy_ids/policy_reasons fields are populated so the caller knows which
            policies the stub covers.
        project_root: Absolute path to the project root, used to compute how many
            directory levels this file sits below it (see _compute_companion_hops) —
            needed so the generated companion-loader stub can find
            <project_root>/lineaje/gr_client.py regardless of nesting depth.
    """
    path = Path(file_path).resolve()
    if path.suffix.lower() not in _SCANNABLE_EXTENSIONS:
        _logger.debug("[INSERTION] skip %s — unsupported extension %s", path, path.suffix)
        return [], []
    try:
        size = path.stat().st_size
        if size > _MAX_FILE_BYTES:
            _logger.info(
                "[INSERTION] skip %s — file too large (%d bytes > max %d)",
                path, size, _MAX_FILE_BYTES,
            )
            return [], []
        source = path.read_text(errors="replace")
    except OSError as exc:
        _logger.info("[INSERTION] skip %s — could not read file: %s", path, exc)
        return [], []

    file_ext = path.suffix.lower()
    companion_hops = _compute_companion_hops(str(path), project_root)

    # Site identity inputs (Phase 6a/follow-up): computed once per file, not
    # per-candidate — same rel_file derivation scan_file()'s wrapper uses, so
    # a site_id embedded here in the generated stub call and the site_id the
    # wrapper later assigns onto the same candidate are guaranteed identical
    # (same function, same inputs), never two independently-derived values
    # that could silently drift apart.
    try:
        _rel_file = (
            str(Path(file_path).resolve().relative_to(Path(project_root).resolve()))
            if project_root else file_path
        )
    except ValueError:
        _rel_file = file_path

    # ── Annotation-based scan (runs first, highest priority) ─────────────────
    # Language-agnostic: works for Python, TypeScript, Java, Go, and any future
    # extension.  Produces candidates for every @gr:insertion_point= comment in
    # the file, then records the (insertion_point, line) keys so the AST and
    # regex paths below don't emit a duplicate stub for the same line.
    _annotation_candidates = _scan_annotations(
        file_path, source, lineaje_pat, insertion_point_types, policy_map, companion_hops
    )
    _annotated_keys: set[tuple[str, int]] = {
        (c.insertion_point, c.line) for c in _annotation_candidates
    }

    # ── PII-in-UI-output scan (cross-language, runs for every extension) ─────
    # See _scan_pii_ui_exposure's docstring — catches the non-call shape
    # (a PII field embedded in a returned/response-bound string) that neither
    # the call-based regex/AST/tree-sitter paths below can see at all.
    _pii_ui_raw = _scan_pii_ui_exposure(
        file_path, source, lineaje_pat, insertion_point_types, policy_map,
        companion_hops, rel_file=_rel_file,
    )

    # ── AST path for Python ───────────────────────────────────────────────────
    # AST gives exact statement-level indentation, reads keyword args directly,
    # and skips unsafe contexts (lambdas, comprehensions) where inserting a
    # statement would be a syntax error.  Falls back to regex on SyntaxError
    # (e.g. Python 2 syntax, encoding issues, or partial/template files).
    #
    # After AST succeeds we still run regex as a SUPPLEMENT to catch patterns
    # that are non-call (e.g. response.content attribute access for llm_to_agent)
    # or not yet in _AST_SPECIFIC.  AST results take priority — a regex result on
    # the same (insertion_point, line) as an AST result is dropped.
    _py_ast_results: "list[InsertionCandidate] | None" = None
    _middleware_candidates: list[MiddlewareCandidate] = []
    _ast_unsafe_keys: set[tuple[str, int]] = set()
    _ast_ui_sink_lines: set[int] = set()
    if file_ext == ".py":
        _ast_result = _scan_file_ast(
            file_path, source, lineaje_pat, insertion_point_types, policy_map, companion_hops,
            rel_file=_rel_file,
        )
        if _ast_result is not None:
            _ast_candidates, _middleware_candidates, _ast_unsafe_keys = _ast_result
            _py_ast_results = [c for c in _ast_candidates if (c.insertion_point, c.line) not in _annotated_keys]
            _ast_ui_sink_lines = {
                c.line for c in _py_ast_results if c.insertion_point in _UI_SINK_INSERTION_POINTS
            }
            # Do NOT return — fall through to regex supplement below.

    _pii_ui_candidates = [
        c for c in _pii_ui_raw
        if (c.insertion_point, c.line) not in _annotated_keys
        and c.line not in _ast_ui_sink_lines
    ]
    _pii_ui_keys: set[tuple[str, int]] = {
        (c.insertion_point, c.line) for c in _pii_ui_candidates
    }

    # ── Tree-sitter AST path for JS / TS / Java ───────────────────────────────
    # Requires tree-sitter + grammar packages (see requirements.txt).
    # Gracefully falls back to regex if not installed.
    if file_ext in _TS_LANG_MAP:
        _ts_lang, _ts_is_java = _TS_LANG_MAP[file_ext]
        _ts_result = _scan_file_treesitter(
            file_path, source, _ts_lang, _ts_is_java,
            lineaje_pat, insertion_point_types, policy_map, companion_hops,
        )
        if _ts_result is not None:
            _ts_candidates, _middleware_candidates = _ts_result
            # Fall through to the regex supplement (same merge as the Python
            # AST path) so data_egress returns and log_emit sinks — which the
            # tree-sitter classifiers do not yet emit — still produce
            # candidates. Duplicates are dropped by (insertion_point, line).
            _py_ast_results = [
                c for c in _ts_candidates
                if (c.insertion_point, c.line) not in _annotated_keys
                and (c.insertion_point, c.line) not in _pii_ui_keys
            ]

    # ── Regex path ────────────────────────────────────────────────────────────
    # Fallback for: Python SyntaxError, tree-sitter not installed, unknown extension.

    lines = source.splitlines()
    candidates: list[InsertionCandidate] = []
    seen: set[tuple[str, int]] = set()

    # Computed once per file (not per-candidate — this parses the whole
    # file) so insert_after=True checks the real end of a multi-line
    # statement instead of "the matched line + 1" — see
    # _py_build_stmt_end_line_map's docstring for the bug this fixes.
    _stmt_end_map = _py_build_stmt_end_line_map(source) if file_ext.lower() == ".py" else None

    # Tokens that only appear in already-inserted stubs.
    _STUB_MARKERS = (
        "gr_check(", "grCheck(", "GRBlockedError",
        "GR_SERVICE_URL", "LINEAJE_PAT", "GR_BEARER_TOKEN", "_gr_req", "_gr_resp",
        "_gr_call", "_grResp", "_grConn", '"insertion_point"',
        # Current VIII.5/VIII.6 stub shape (SiteDescriptor + .check()) — see
        # the sibling _STUB_MARKERS tuple's comment above for the gap this closes.
        "_lineaje_load_gr_client", "_gr_client.check(", "_gr_client.enforce(", "_gr_decision", "SiteDescriptor(",
    )

    _GUARD_WINDOW = 15  # lines before/after a hit to check for an existing stub

    def _already_guarded(lineno: int) -> bool:
        """Return True if a stub marker exists within GUARD_WINDOW lines of lineno."""
        start = max(0, lineno - _GUARD_WINDOW - 1)
        end = min(len(lines), lineno + _GUARD_WINDOW)
        return any(
            any(m in lines[i] for m in _STUB_MARKERS)
            for i in range(start, end)
        )

    for lineno, raw_line in enumerate(lines, start=1):
        if any(m in raw_line for m in _STUB_MARKERS):
            continue
        if _already_guarded(lineno):
            continue
        # Skip lines already covered by an annotation — no duplicate stubs.
        if any(ip == lineno for _, ip in _annotated_keys):
            continue
        # Skip delegating return statements — e.g. `return await self.chat(x)`
        # is an internal wrapper, not a real boundary. Exceptions:
        #   - `return jsonify(x)` / `return Response(x)` — UI-response ctor
        #   - `return html` / `return payload` — bare-name data return
        #     (data_egress; every routine inserts before the value leaves)
        if (
            raw_line.strip().startswith("return ")
            and not _UI_SINK_CALL_RE.search(raw_line)
            and not _is_data_return_line(raw_line.strip())
        ):
            continue
        indent = raw_line[: len(raw_line) - len(raw_line.lstrip())]
        for insertion_point, compiled, hint, description in _COMPILED:
            # Skip insertion_point types the caller doesn't care about
            if insertion_point_types is not None and insertion_point not in insertion_point_types:
                continue
            if not compiled.search(raw_line):
                continue
            # fmt.Fprintf(w, html) matches both the log Print* regex and the
            # UI-response regex — that line is data_egress/llm_to_user, not
            # a log. Drop the log_emit hit so the UI sink owns the site.
            if insertion_point == "log_emit" and _UI_SINK_CALL_RE.search(raw_line):
                continue
            # Broad async "await x.get(/post(" patterns have no receiver-hint
            # gate baked into the regex itself — reject known non-HTTP async
            # primitives (asyncio.Queue, caches, ...) here instead. See
            # _async_call_receiver's docstring for the exact bug this fixes.
            if compiled.pattern in _ASYNC_HTTP_PATTERNS_NEEDING_RECEIVER_GATE:
                _receiver = _async_call_receiver(raw_line)
                if _receiver and _is_non_http_async_receiver(_receiver):
                    continue
            # Skip lines already covered by an annotation for this insertion point
            if (insertion_point, lineno) in _annotated_keys:
                continue
            key = (insertion_point, lineno)
            if key in seen:
                continue
            seen.add(key)

            variable = _extract_variable(
                raw_line,
                hint,
                context_lines=lines[:lineno - 1],
                following_lines=lines[lineno:lineno + 10],
            )
            # Empty string means extraction genuinely failed — "data" itself
            # can be a real extracted variable name (a customer's code might
            # legitimately have `data = ...`), so it must not be treated as
            # the failure sentinel here. Substitute the display placeholder
            # only now, after the safety decision below is captured.
            extraction_failed = not variable
            if extraction_failed:
                variable = "data"
            is_async = file_ext.lower() == ".py" and _is_async_context(lines, lineno)
            _ia = (hint == "lhs")
            if insertion_point == "data_egress":
                _regex_symbol_early = _enclosing_symbol(lines, lineno)
                _window = "\n".join(lines[max(0, lineno - 10): min(len(lines), lineno + 5)])
                insertion_point = _refine_ui_insertion_point(
                    "data_egress", _regex_symbol_early, variable, _window,
                )
            _regex_policy_reasons = list(policy_map.get(insertion_point, [])) if policy_map else []
            if not _regex_policy_reasons and policy_map and insertion_point != "data_egress":
                _regex_policy_reasons = list(policy_map.get("data_egress", []))
            _regex_policy_ids = [pr["policy_id"] for pr in _regex_policy_reasons]
            _regex_symbol = _enclosing_symbol(lines, lineno)
            _regex_site_id = _derive_site_id(_rel_file, _regex_symbol, insertion_point, compiled.pattern)
            stub_line = _make_stub_line(
                variable, insertion_point, lineaje_pat, indent, file_ext, is_async=is_async, insert_after=_ia,
                candidate_policy_ids=_regex_policy_ids, site_id=_regex_site_id,
            )

            if extraction_failed:
                safe_to_insert = False
                skip_reason = "could not extract variable name from source"
            elif file_ext.lower() == ".py":
                # Python: verify the extracted variable is actually bound on
                # every path reaching this point — not just "some name was
                # found nearby". This is what prevents e.g. a response-check
                # matched on `response.content` from being auto-inserted
                # before the real assignment, or across an if/else where only
                # one branch assigns it.
                safe_to_insert, skip_reason = _validate_stub_insertion(
                    source, stub_line, lineno, _import_hint(file_ext), variable,
                    insert_after=_ia, stmt_end_line=_stmt_end_map.get(lineno) if _stmt_end_map else None,
                )
            else:
                # Non-Python: no AST-based validator yet — fall back to the
                # existing "a name was found" heuristic.
                safe_to_insert = True
                skip_reason = ""
            policy_reasons = _regex_policy_reasons
            policy_ids = _regex_policy_ids

            candidates.append(InsertionCandidate(
                file=file_path,
                line=lineno,
                insertion_point=insertion_point,
                pattern_matched=compiled.pattern,
                context_line=raw_line.rstrip(),
                suggested_variable=variable,
                description=description,
                proposed_stub=stub_line,
                safe_to_insert=safe_to_insert,
                skip_reason=skip_reason,
                policy_ids=policy_ids,
                policy_reasons=policy_reasons,
                insert_after=_ia,
                variable_to_use_in_call="",
                companion_hops=companion_hops,
                site_id=_regex_site_id,
                stmt_end_line=(_stmt_end_map.get(lineno) if _stmt_end_map else None) or lineno,
            ))

    # ── Merge: AST primary + regex supplement for Python ─────────────────────
    if _py_ast_results is not None:
        # AST succeeded — use its results as primary and supplement with any
        # regex results on DIFFERENT (insertion_point, line) keys. Also
        # excludes _ast_unsafe_keys: lines the AST path examined and rejected
        # as unsafe (lambda body / comprehension) never produced a candidate,
        # so they're absent from _ast_seen by construction — without this,
        # the regex path (no unsafe-context awareness) re-adds a bogus
        # candidate for the exact line AST just ruled out.
        _ast_seen = {(c.insertion_point, c.line) for c in _py_ast_results} | _ast_unsafe_keys | _pii_ui_keys
        _regex_supplement = [
            c for c in candidates
            if (c.insertion_point, c.line) not in _ast_seen
        ]
        return (
            _annotation_candidates + _py_ast_results + _regex_supplement + _pii_ui_candidates,
            _middleware_candidates,
        )

    _regex_final = [c for c in candidates if (c.insertion_point, c.line) not in _pii_ui_keys]
    return _annotation_candidates + _regex_final + _pii_ui_candidates, _middleware_candidates


def _display_scan_path(file_path: str, project_root: str | None = None) -> str:
    """Repo-relative path for insertion-point logs; last few path parts if not under root."""
    try:
        resolved = Path(file_path).resolve()
        if project_root:
            return str(resolved.relative_to(Path(project_root).resolve()))
    except (ValueError, OSError):
        pass
    parts = Path(file_path).parts
    if len(parts) > 4:
        return str(Path(*parts[-4:]))
    return file_path


def _ip_count_summary(candidates: "list[InsertionCandidate]") -> str:
    counts: dict[str, int] = {}
    for c in candidates:
        ip = c.insertion_point or "unknown"
        counts[ip] = counts.get(ip, 0) + 1
    return ", ".join(f"{ip}={n}" for ip, n in sorted(counts.items())) or "none"


def _log_insertion_candidates(
    file_path: str,
    candidates: "list[InsertionCandidate]",
    project_root: str | None = None,
    middleware_count: int = 0,
) -> None:
    """INFO lines matching the evaluator's [EVAL] style so a live scan shows each site."""
    rel = _display_scan_path(file_path, project_root)
    _logger.info("[INSERTION] Scanning %s", rel)
    for c in candidates:
        ctx = (c.context_line or "").strip().replace("\n", " ")
        if len(ctx) > 160:
            ctx = ctx[:157] + "..."
        _logger.info(
            "[INSERTION] Found %s at %s:%s (safe=%s confidence=%s) — %s",
            c.insertion_point or "unknown",
            rel,
            c.line,
            c.safe_to_insert,
            getattr(c, "confidence", "medium") or "medium",
            ctx or "(empty line)",
        )
    extra = f"; middleware={middleware_count}" if middleware_count else ""
    _logger.info(
        "[INSERTION] %s: %d insertion point(s) (%s)%s",
        rel,
        len(candidates),
        _ip_count_summary(candidates),
        extra,
    )


def scan_file(
    file_path: str,
    lineaje_pat: str = "",
    insertion_point_types: list[str] | None = None,
    policy_map: dict[str, list[dict]] | None = None,
    project_root: str | None = None,
    confirm_with_taint_analysis: bool = False,
) -> "tuple[list[InsertionCandidate], list[MiddlewareCandidate]]":
    """Scan a single file and return insertion candidates, each with its site
    identity (site_id, boundary, phase) filled in — see PLAN.md Phase 6a.

    Thin wrapper around _scan_file_core(): the scanning logic itself
    (annotation/AST/tree-sitter/regex paths) is untouched; this only derives
    each candidate's site_id/boundary/phase post-hoc from
    (file, line, insertion_point, pattern_matched), additively, so nothing
    about candidate detection itself changes.

    confirm_with_taint_analysis: opt-in only, default False. Runs semgrep as
    a subprocess per insertion_point group found in the file (see
    semgrep_taint_scanner.py) to upgrade candidate confidence on confirmed
    dataflow. Deliberately NOT automatic just because semgrep happens to be
    on PATH — measured live: this added ~500x wall-clock overhead to a
    266-test suite (0.25s -> 123s) when triggered unconditionally. Callers
    that want the confirmation pass (e.g. a one-off deep scan, not routine
    CI/IDE scanning) opt in explicitly per call.
    """
    candidates, middleware_candidates = _scan_file_core(
        file_path, lineaje_pat, insertion_point_types, policy_map, project_root,
    )
    if candidates:
        try:
            lines = Path(file_path).resolve().read_text(errors="replace").splitlines()
        except OSError:
            lines = []
        try:
            rel_file = (
                str(Path(file_path).resolve().relative_to(Path(project_root).resolve()))
                if project_root else file_path
            )
        except ValueError:
            rel_file = file_path
        for c in candidates:
            symbol = _enclosing_symbol(lines, c.line) if lines else ""
            phase, boundary = _canonical_phase_and_boundary(c.insertion_point)
            c.site_id = _derive_site_id(rel_file, symbol, c.insertion_point, c.pattern_matched)
            c.boundary = boundary
            c.phase = phase

        # Taint-mode confirmation (graph-based source->sink verification) —
        # optional, additive, OPT-IN (see confirm_with_taint_analysis above):
        # upgrades confidence "medium"/"low" -> "high" on confirmed dataflow,
        # never removes a candidate the paths above already found. See
        # semgrep_taint_scanner.py's module docstring for why this exists
        # (best-effort proximity matching vs. real dataflow) and PLAN.md for
        # scope (Python only for v1).
        if confirm_with_taint_analysis:
            try:
                import semgrep_taint_scanner as _taint
                _taint.confirm_candidates(file_path, candidates)
            except ImportError:
                pass
    _log_insertion_candidates(
        file_path, candidates, project_root, middleware_count=len(middleware_candidates),
    )
    return candidates, middleware_candidates


def scan_project(
    project_root: str,
    files_to_scan: list[str] | None = None,
    lineaje_pat: str = "",
    max_files: int = 200,
    insertion_point_types: list[str] | None = None,
    policy_map: dict[str, list[dict]] | None = None,
) -> "tuple[list[InsertionCandidate], list[MiddlewareCandidate]]":
    """Scan a project directory (or specific files) for insertion candidates.

    insertion_point_types and policy_map are forwarded to each scan_file() call —
    see scan_file() docstring for semantics.
    """
    root = Path(project_root)
    all_candidates: list[InsertionCandidate] = []

    if files_to_scan:
        targets = [root / f for f in files_to_scan]
    else:
        targets = []
        skip_dirs = {
            "node_modules", ".git", "__pycache__", "venv", ".venv",
            "dist", "build", ".tox", ".mypy_cache", ".next", ".nuxt",
            "out", ".svelte-kit", ".venv-scan",
        }
        for p in root.rglob("*"):
            if any(part in skip_dirs for part in p.parts):
                continue
            if p.is_file() and p.suffix.lower() in _SCANNABLE_EXTENSIONS:
                targets.append(p)
            if len(targets) >= max_files:
                break

    _logger.info(
        "[INSERTION] Scanning %d file(s) for insertion points (root=%s)",
        len(targets),
        project_root,
    )
    all_middleware_candidates: list[MiddlewareCandidate] = []
    for t in targets:
        _candidates, _mw_candidates = scan_file(
            str(t),
            lineaje_pat=lineaje_pat,
            insertion_point_types=insertion_point_types,
            policy_map=policy_map,
            project_root=project_root,
        )
        all_candidates.extend(_candidates)
        all_middleware_candidates.extend(_mw_candidates)

    files_hit = len({c.file for c in all_candidates})
    _logger.info(
        "[INSERTION] Scan complete: %d candidate(s) across %d file(s) — %s",
        len(all_candidates),
        files_hit,
        _ip_count_summary(all_candidates),
    )
    return all_candidates, all_middleware_candidates


def build_llm_scan_prompt(
    project_root: str,
    scanned_files: list[str],
    candidates: list[InsertionCandidate],
) -> str:
    """Build a structured prompt for an LLM-assisted pass to catch what the AST scanner missed.

    The coding agent (Cursor, Claude Code, etc.) receives this as part of the tool output
    and performs an additional review of the scanned files.  The prompt tells the agent:
      - Which files were scanned
      - What the static scanner already found (so it avoids duplicates)
      - What patterns to look for that regex/AST can't catch (dynamic dispatch, aliases, etc.)
      - Expected output format so results can be merged with the AST findings

    Returns a markdown string to be appended to the display_report.
    """
    if not scanned_files:
        return ""

    found_by_file: dict[str, list[InsertionCandidate]] = {}
    for c in candidates:
        found_by_file.setdefault(c.file, []).append(c)

    lines: list[str] = [
        "",
        "---",
        "## LLM-Assisted Scan — Additional Instructions for the Coding Agent",
        "",
        "The static AST scanner found the insertion points listed above.  "
        "Please perform an **LLM-assisted pass** on each file below to catch patterns "
        "the static scanner cannot see: aliased imports, dynamic method dispatch, "
        "SDK wrapper classes, factory helpers, and indirect calls.",
        "",
        "### What to look for (missed by the static scanner)",
        "",
        "- **Aliased / re-exported clients** — `import openai as client; client.chat.completions.create(...)`",
        "- **SDK wrapper methods** — internal helpers that call the LLM under the hood",
        "- **Factory-created clients** — `get_llm_client().invoke(...)` where the return type holds an AI client",
        "- **Indirect DB reads** — ORM `.filter().all()`, SQLAlchemy sessions, custom DAOs",
        "- **Dynamic HTTP clients** — `httpx.AsyncClient`, `aiohttp.ClientSession.get/post`",
        "- **Tool / function calls forwarded to LLMs** — `agent.run(tool_input)`, `executor.execute(...)`",
        "",
        "### Enrich inserted gr_check() calls with event context",
        "",
        "Every inserted `gr_check(data, source_type, destination_type)` call accepts "
        "optional keyword context — `agent_id`, `agent_name`, `task`, `task_id`, `user_id`, "
        "`source_name`, `source_id`, `source_url`, `dest_name`, `dest_id`, `dest_url` "
        "(Python: keyword args; TS/JS: a trailing context object, e.g. "
        "`gr_check(data, \"agent\", \"llm\", \"\", 5000, { agent_id, task })`). "
        "The static scanner cannot see this — it only knows the call site's data flow, "
        "not the surrounding business logic. Policy rubrics reference these exact field "
        "names (e.g. \"destination_type is 'tool' ... task value ... mirrored in dest_name / "
        "dest_id\"), so filling them in is what lets those policies actually evaluate.",
        "",
        "For each inserted `gr_check(...)` call, look at the enclosing function/class for "
        "values you can confidently attribute to this specific call — an agent's own name "
        "or ID field, the current task/request identifier, the authenticated user, or the "
        "literal name/ID/URL of whatever is being called (an MCP tool name, an API endpoint, "
        "a file path). **Only add a field when the surrounding code makes it unambiguous — "
        "never guess or invent a value.** Leave a field out entirely rather than passing a "
        "placeholder, an empty string, or a value copied from an unrelated part of the file; "
        "an omitted field is harmless (the GR service treats it as unknown), a wrong one "
        "produces a wrong policy decision.",
        "",
        "### Files to review",
        "",
    ]

    for fpath in sorted(scanned_files):
        rel = os.path.relpath(fpath, project_root) if project_root else fpath
        already = found_by_file.get(fpath, [])
        if already:
            found_summary = ", ".join(
                f"line {c.line} (`{c.insertion_point}`)" for c in already
            )
            lines.append(f"- `{rel}` — already found: {found_summary}")
        else:
            lines.append(f"- `{rel}` — **no static hits; review manually**")

    lines += [
        "",
        "### Expected output format",
        "",
        "For each **additional** insertion point found (do **not** repeat the ones listed above), "
        "output one line in this format:",
        "",
        "```",
        "MISSED | file: <relative-path> | line: <N> | insertion_point: <type> | reason: <why>",
        "```",
        "",
        "Where `<type>` is one of: `agent_to_llm`, `llm_to_agent`, `db_read`, `db_write`, "
        "`outbound_http`, `file_read`, `file_write`, `mcp_tool_call`, `risky_operation`.",
        "",
        "If no additional sites are found, output: `MISSED | none`",
    ]

    return "\n".join(lines)
