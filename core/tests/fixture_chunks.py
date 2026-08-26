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
        _mod = gr_check(_mod, "agent", "user_interface", site_id='site:sha256:178e165de3f3da280414bd5d7d755478dcbbb1e2dfd1b983cde266ddb117ae4e')
    except Exception as _gr_exc:
        if type(_gr_exc).__name__ == "GRBlockedError":
            raise
        _mod = _mod
        import logging as _lineaje_logging
        _lineaje_logging.getLogger("lineaje.gr_client").warning(
            "Lineaje guardrail unavailable at 'agent->user_interface' — passing data through unchecked"
        )
    return _mod

import asyncio
import json
from uuid import uuid4

from langchain_core.embeddings import DeterministicFakeEmbedding
from langchain_core.messages.ai import AIMessageChunk
from langchain_core.vectorstores import InMemoryVectorStore
from quivr_core.rag.entities.chat import ChatHistory
from quivr_core.rag.entities.config import LLMEndpointConfig, RetrievalConfig
from quivr_core.llm import LLMEndpoint
from quivr_core.rag.quivr_rag_langgraph import QuivrQARAGLangGraph


async def main():
    retrieval_config = RetrievalConfig(llm_config=LLMEndpointConfig(model="gpt-4o"))
    embedder = DeterministicFakeEmbedding(size=20)
    vec = InMemoryVectorStore(embedder)

    llm = LLMEndpoint.from_config(retrieval_config.llm_config)
    chat_history = ChatHistory(uuid4(), uuid4())
    rag_pipeline = QuivrQARAGLangGraph(
        retrieval_config=retrieval_config, llm=llm, vector_store=vec
    )

    conversational_qa_chain = rag_pipeline.build_chain()

    with open("response.jsonl", "w") as f:
        async for event in conversational_qa_chain.astream_events(
            {
                "messages": [
                    ("user", "What is NLP, give a very long detailed answer"),
                ],
                "chat_history": chat_history,
                "custom_personality": None,
            },
            version="v1",
            config={"metadata": {}},
        ):
            kind = event["event"]
            if (
                kind == "on_chat_model_stream"
                and event["metadata"]["langgraph_node"] == "generate"
            ):
                chunk = event["data"]["chunk"]
                dict_chunk = {
                    k: v.dict() if isinstance(v, AIMessageChunk) else v
                    for k, v in chunk.items()
                }
                # LINEAJE: enforce() `dict_chunk` at agent->external data_egress — scan flagged AI_APP_SEC_029 (Agent must validate, sanitize LLM output including for presence of eval or any dynamic code execution primitive in LLM output.); AI_APP_SEC_064 (Enforce synthetic content provenance, labeling, and watermarking for AI-generated outputs.). Mask/block; do not remove without review. site_id='site:sha256:5c68389e092835bfceae8e47f5bc611a1349443c14c403a6dc79dca9fb96a8d8'
                _gr_client = _lineaje_load_gr_client()
                _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:5c68389e092835bfceae8e47f5bc611a1349443c14c403a6dc79dca9fb96a8d8', phase='data_egress', boundary={'source': 'agent_message', 'sink': 'external_endpoint'}, candidate_policies=[], fail_mode='ALLOW_WITH_AUDIT', source_type='agent', destination_type='external')
                dict_chunk = await __import__('asyncio').to_thread(lambda: _gr_client.enforce(_gr_site, dict_chunk, content_type='application/json', variable_name='dict_chunk', source_file=__file__, before_line=49))
                try:
                    import asyncio as _gr_asyncio
                    dict_chunk = await _gr_asyncio.to_thread(gr_check, dict_chunk, "agent", "external", site_id='site:sha256:5c68389e092835bfceae8e47f5bc611a1349443c14c403a6dc79dca9fb96a8d8')
                except Exception as _gr_exc:
                    if type(_gr_exc).__name__ == "GRBlockedError":
                        raise
                    dict_chunk = dict_chunk
                    import logging as _lineaje_logging
                    _lineaje_logging.getLogger("lineaje.gr_client").warning(
                        "Lineaje guardrail unavailable at 'agent->external' — passing data through unchecked"
                    )
                f.write(json.dumps(dict_chunk) + "\n")


asyncio.run(main())
