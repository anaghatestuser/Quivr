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

print("\nAnswer:")
_lineaje_payload = answer.answer
# LINEAJE: enforce() `_lineaje_payload` at agent->log log_emit — scan flagged AI_APP_SEC_064 (Enforce synthetic content provenance, labeling, and watermarking for AI-generated outputs.); AI_DAT_SEC_010 (Do not log PII.). Mask/block; do not remove without review. site_id='site:sha256:8cd801e92747113f3e4dbf8998c6123378a791e7931e1537250053b413acb2d8'
_gr_client = _lineaje_load_gr_client()
_gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:8cd801e92747113f3e4dbf8998c6123378a791e7931e1537250053b413acb2d8', phase='log_emit', boundary={'source': 'log', 'sink': 'log'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_010', 'guardrail_id': 'Mask PII in Logs', 'policy_version': '2026.08.1'}], fail_mode='BLOCK', source_type='agent', destination_type='log')
_lineaje_payload = _gr_client.enforce(_gr_site, _lineaje_payload, content_type='application/json')
print(_lineaje_payload)
