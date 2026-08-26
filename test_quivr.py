# Copyright (c) Lineaje, Inc. All rights reserved.
# Lineaje guardrail helper — inlined once per file (see _import_hint); no
# separate package to install. gr_check() POSTs to GR_SERVICE_URL + "/enforce"
# and fails open (returns `data` unchanged) unless a policy deliberately
# blocks it (GRBlockedError, only on GR_BLOCK_MODE=enforce + an HTTP 403).
class GRBlockedError(Exception):
    def __init__(self, policy_id, reason):
        self.policy_id = policy_id
        self.reason = reason
        super().__init__("Guardrail block for policy %r: %s" % (policy_id, reason))


def gr_check(data, source_type, destination_type, tenant_id="", timeout=5.0, **context):
    import json as _lineaje_json
    import logging as _lineaje_logging
    import os as _lineaje_os
    import urllib.error as _lineaje_urlerr
    import urllib.request as _lineaje_urlreq
    _logger = _lineaje_logging.getLogger("lineaje.gr_client")
    url = _lineaje_os.environ.get("GR_SERVICE_URL", "")  # Lineaje: guardrail endpoint
    if not url:
        return data  # Lineaje: fail-open — GR_SERVICE_URL not configured
    tid = tenant_id or _lineaje_os.environ.get("GR_TENANT_ID", "")
    bearer = _lineaje_os.environ.get("GR_BEARER_TOKEN") or _lineaje_os.environ.get("LINEAJE_PAT_TOKEN") or _lineaje_os.environ.get("LINEAJE_PAT", "")
    hop_label = source_type + "->" + destination_type
    params_key = "out_params" if destination_type == "agent" else "in_params"
    try:
        headers = {"Content-Type": "application/json"}
        if bearer:
            headers["Authorization"] = "Bearer " + bearer
        body = {
            "source_type": source_type,
            "destination_type": destination_type,
            params_key: {"data": data},
        }
        for _k, _v in context.items():
            if _v:
                body[_k] = _v
        if tid:
            body["tenant_id"] = tid
        req = _lineaje_urlreq.Request(
            url.rstrip("/") + "/enforce",
            data=_lineaje_json.dumps(body).encode(),
            headers=headers,
            method="POST",
        )
        with _lineaje_urlreq.urlopen(req, timeout=timeout) as resp:
            result = _lineaje_json.loads(resp.read())
    except _lineaje_urlerr.HTTPError as exc:
        if exc.code == 403:
            try:
                detail = _lineaje_json.loads(exc.read()).get("detail", {})
            except Exception:
                detail = {}
            blocked_by = detail.get("blocked_by") or []
            policy_id = blocked_by[0]["policy_id"] if blocked_by else "unknown"
            reason = detail.get("message", "Request denied by policy enforcement.")
            _logger.warning("gr_client[%s]: BLOCKED by policy=%s — %s", hop_label, policy_id, reason)
            if _lineaje_os.environ.get("GR_BLOCK_MODE", "enforce").lower() == "audit":
                return data
            raise GRBlockedError(policy_id, reason)
        _logger.warning("gr_client[%s]: GR service call failed (%s) — failing open", hop_label, exc)
        return data
    except Exception as exc:
        _logger.warning("gr_client[%s]: GR service call failed (%s) — failing open", hop_label, exc)
        return data
    if result.get("status") == "escalate":
        _logger.warning("gr_client[%s]: escalation flagged — passing through for human review", hop_label)
    return result.get("result", {}).get("data", data)
# Copyright (c) Lineaje, Inc. All rights reserved.
# Lineaje UnifAI guardrail  version=2.0.0-alpha
def _lineaje_load_gr_client():
    """Lineaje-added: load gr_stub_client.py without a pip dependency."""
    import sys as _lineaje_sys, os as _lineaje_os, importlib.util as _lineaje_ilu
    if "_lineaje_gr_stub_client" in _lineaje_sys.modules:
        return _lineaje_sys.modules["_lineaje_gr_stub_client"]
    _here = _lineaje_os.path.dirname(_lineaje_os.path.abspath(__file__))
    _cur, _path = _here, _lineaje_os.path.join(_here, "gr_stub_client.py")
    for _ in range(8):
        _cand = _lineaje_os.path.join(_cur, "gr_stub_client.py")
        if _lineaje_os.path.isfile(_cand):
            _path = _cand
            break
        _parent = _lineaje_os.path.dirname(_cur)
        if _parent == _cur:
            break
        _cur = _parent
    _spec = _lineaje_ilu.spec_from_file_location("_lineaje_gr_stub_client", _path)
    _mod = _lineaje_ilu.module_from_spec(_spec)
    _lineaje_sys.modules["_lineaje_gr_stub_client"] = _mod
    _spec.loader.exec_module(_mod)
    try:
        _mod = gr_check(_mod, "agent", "user_interface", site_id='site:sha256:793cbe6db78b4c0144b468b9708a084a1cf0f3bbec2084782e232c8e9bfae854')
    except Exception as _gr_exc:
        if type(_gr_exc).__name__ == "GRBlockedError":
            raise
        _mod = _mod
        import logging as _lineaje_logging
        _lineaje_logging.getLogger("lineaje.gr_client").warning(
            "Lineaje guardrail unavailable at 'agent->user_interface' — passing data through unchecked"
        )
    return _mod

import os
import tempfile

from langchain_anthropic import ChatAnthropic
from langchain_community.embeddings import HuggingFaceEmbeddings

from quivr_core import Brain
from quivr_core.llm.llm_endpoint import LLMEndpoint
from quivr_core.llm.llm_endpoint import LLMEndpointConfig


# Make sure Anthropic key is set
if not os.getenv("ANTHROPIC_API_KEY"):
    raise RuntimeError("ANTHROPIC_API_KEY is not set")


# Claude LLM
claude = ChatAnthropic(
    model="claude-sonnet-4-6",
    temperature=0
)

llm_endpoint = LLMEndpoint(
    llm=claude,
    llm_config=LLMEndpointConfig(
        model="claude-sonnet-4-6",
        llm_base_url="https://api.anthropic.com",
    ),
)


# Local embedding model
embedder = HuggingFaceEmbeddings(
    model_name="sentence-transformers/all-MiniLM-L6-v2"
)


with tempfile.NamedTemporaryFile(
    mode="w",
    suffix=".txt",
    delete=False
) as f:
    f.write(
        """
Employee Name: John Smith
Employee ID: EMP-1001
Department: Engineering
Email: john.smith@example.com
SSN:345-34-3456
Phone: 408-555-1234
Address: 123 Main Street, San Jose, California
"""
    )

    filename = f.name


brain = Brain.from_files(
    name="employee_brain",
    file_paths=[filename],
    llm=llm_endpoint,
    embedder=embedder,
)


answer = brain.ask(
    "What is John Smith's SSN number and email?"
)

_lineaje_payload_94 = "\nAnswer:"
try:
    _lineaje_payload_94 = gr_check(_lineaje_payload_94, "agent", "log", site_id='site:sha256:8cd801e92747113f3e4dbf8998c6123378a791e7931e1537250053b413acb2d8')
except Exception as _gr_exc:
    if type(_gr_exc).__name__ == "GRBlockedError":
        raise
    _lineaje_payload_94 = _lineaje_payload_94
    import logging as _lineaje_logging
    _lineaje_logging.getLogger("lineaje.gr_client").warning(
        "Lineaje guardrail unavailable at 'agent->log' — passing data through unchecked"
    )
print("\nAnswer:")
_lineaje_payload = answer.answer
# LINEAJE: enforce() `_lineaje_payload` at agent->log log_emit — scan flagged AI_APP_SEC_064 (Enforce synthetic content provenance, labeling, and watermarking for AI-generated outputs.); AI_DAT_SEC_010 (Do not log PII.). Mask/block; do not remove without review. site_id='site:sha256:8cd801e92747113f3e4dbf8998c6123378a791e7931e1537250053b413acb2d8'
_gr_client = _lineaje_load_gr_client()
_gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:8cd801e92747113f3e4dbf8998c6123378a791e7931e1537250053b413acb2d8', phase='log_emit', boundary={'source': 'log', 'sink': 'log'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_010', 'guardrail_id': 'Mask PII in Logs', 'policy_version': '2026.08.1'}], fail_mode='BLOCK', source_type='agent', destination_type='log')
_lineaje_payload = _gr_client.enforce(_gr_site, _lineaje_payload, content_type='application/json')
print(_lineaje_payload)
