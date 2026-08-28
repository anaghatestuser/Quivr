# Copyright (c) Lineaje, Inc. All rights reserved.
# Lineaje UnifAI guardrail  version=2.0.0-alpha
def _lineaje_load_gr_client():
    """Lineaje-added: load gr_stub_client.py without a pip dependency."""
    import sys as _s, importlib.util as _ilu
    from pathlib import Path as _P
    n = "_lineaje_gr_stub_client"
    if n in _s.modules: return _s.modules[n]
    h = _P(__file__).resolve().parent
    _cand = next((d / "gr_stub_client.py" for d in [h, *h.parents][:8] if (d / "gr_stub_client.py").is_file()), h / "gr_stub_client.py")
    _spec = _ilu.spec_from_file_location(n, _cand)
    _s.modules[n] = _m = _ilu.module_from_spec(_spec)
    _spec.loader.exec_module(_m); return _m
import os
import sys
import tempfile

from langchain_anthropic import ChatAnthropic
from langchain_community.embeddings import HuggingFaceEmbeddings

from quivr_core import Brain
from quivr_core.llm.llm_endpoint import LLMEndpoint
from quivr_core.llm.llm_endpoint import LLMEndpointConfig


# Make sure Anthropic key is set
if not os.getenv("ANTHROPIC_API_KEY"):
    raise RuntimeError("ANTHROPIC_API_KEY is not set")


# Claude LLM — claude-3-5-sonnet-20241022 is retired (Anthropic 404).
MODEL = "claude-sonnet-4-5"
claude = ChatAnthropic(
    model=MODEL,
    temperature=0
)

llm_endpoint = LLMEndpoint(
    llm=claude,
    llm_config=LLMEndpointConfig(
        model=MODEL,
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
SSN: 123-45-6789
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
    "What is John Smith's Department, Phone Number, Employee ID, SSN, email address and address?"
)

# False positive for "Do not log PII": field names and already-redacted placeholders.
# No SSN, email, phone, or address values are written.
print("PII fields in query: SSN, email, phone, address (values not logged)")
_lineaje_payload_99 = "SSN: XXX-XX-XXXX"
# LINEAJE: enforce() `_lineaje_payload_99` at agent->log log_emit — scan flagged AI_DAT_SEC_010 (Do not log PII.). Mask/block; do not remove without review. site_id='site:sha256:e62b30e1ce1600104cb8c81e04ee008ee16510087d0e0065acb36a5f40e3d507'
_gr_client = _lineaje_load_gr_client()
_gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:e62b30e1ce1600104cb8c81e04ee008ee16510087d0e0065acb36a5f40e3d507', phase='log_emit', boundary={'source': 'log', 'sink': 'log'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_010', 'guardrail_id': 'Mask PII in Logs', 'policy_version': '2026.08.1'}], fail_mode='BLOCK', source_type='agent', destination_type='log')
_lineaje_payload_99 = _gr_client.enforce(_gr_site, _lineaje_payload_99, content_type='application/json')
print(_lineaje_payload_99)
_lineaje_payload_100 = "email: [REDACTED]"
# LINEAJE: enforce() `_lineaje_payload_100` at agent->log log_emit — scan flagged AI_DAT_SEC_010 (Do not log PII.). Mask/block; do not remove without review. site_id='site:sha256:42e5cd847ba1edbe7757461a21e2a1b6688ec1c049f54e846523da425c0bba0e'
_gr_client = _lineaje_load_gr_client()
_gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:42e5cd847ba1edbe7757461a21e2a1b6688ec1c049f54e846523da425c0bba0e', phase='log_emit', boundary={'source': 'log', 'sink': 'log'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_010', 'guardrail_id': 'Mask PII in Logs', 'policy_version': '2026.08.1'}], fail_mode='BLOCK', source_type='agent', destination_type='log')
_lineaje_payload_100 = _gr_client.enforce(_gr_site, _lineaje_payload_100, content_type='application/json')
print(_lineaje_payload_100)

# False negative for "Do not log PII": the model answer (SSN/email/phone/address)
# still goes to stderr. That is logging. sys.stderr.write is not print(), so a
# scan that only stubs print() can miss it.
sys.stderr.write(answer.answer + "\n")

_lineaje_payload_107 = "\nAnswer:"
# LINEAJE: enforce() `_lineaje_payload_107` at agent->log log_emit — scan flagged AI_DAT_SEC_010 (Do not log PII.). Mask/block; do not remove without review. site_id='site:sha256:f1562620f5b0ff2196e8f399d0ed424859728a2f0aa9c3b1015e129b5989757b'
_gr_client = _lineaje_load_gr_client()
_gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:f1562620f5b0ff2196e8f399d0ed424859728a2f0aa9c3b1015e129b5989757b', phase='log_emit', boundary={'source': 'log', 'sink': 'log'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_010', 'guardrail_id': 'Mask PII in Logs', 'policy_version': '2026.08.1'}], fail_mode='BLOCK', source_type='agent', destination_type='log')
_lineaje_payload_107 = _gr_client.enforce(_gr_site, _lineaje_payload_107, content_type='application/json')
print(_lineaje_payload_107)
_lineaje_payload = answer.answer
# LINEAJE: enforce() `_lineaje_payload` at agent->log log_emit — scan flagged AI_DAT_SEC_010 (Do not log PII.). Mask/block; do not remove without review. site_id='site:sha256:8cd801e92747113f3e4dbf8998c6123378a791e7931e1537250053b413acb2d8'
_gr_client = _lineaje_load_gr_client()
_gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:8cd801e92747113f3e4dbf8998c6123378a791e7931e1537250053b413acb2d8', phase='log_emit', boundary={'source': 'log', 'sink': 'log'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_010', 'guardrail_id': 'Mask PII in Logs', 'policy_version': '2026.08.1'}], fail_mode='BLOCK', source_type='agent', destination_type='log')
_lineaje_payload = _gr_client.enforce(_gr_site, _lineaje_payload, content_type='application/json')
print(_lineaje_payload)
