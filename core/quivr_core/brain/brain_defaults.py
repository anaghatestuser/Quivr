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
        _mod = gr_check(_mod, "agent", "user_interface", site_id='site:sha256:5b6567b27fead5dbfbd760482d3156dfa3da05e98a0f5b71652899c472f5e5be')
    except Exception as _gr_exc:
        if type(_gr_exc).__name__ == "GRBlockedError":
            raise
        _mod = _mod
        import logging as _lineaje_logging
        _lineaje_logging.getLogger("lineaje.gr_client").warning(
            "Lineaje guardrail unavailable at 'agent->user_interface' — passing data through unchecked"
        )
    return _mod
import logging

from langchain_core.documents import Document
from langchain_core.embeddings import Embeddings
from langchain_core.vectorstores import VectorStore

from quivr_core.rag.entities.config import DefaultModelSuppliers, LLMEndpointConfig
from quivr_core.llm import LLMEndpoint

logger = logging.getLogger("quivr_core")


async def build_default_vectordb(
    docs: list[Document], embedder: Embeddings
) -> VectorStore:
    try:
        from langchain_community.vectorstores import FAISS

        _lineaje_payload_43 = "Using Faiss-CPU as vector store."
        # LINEAJE: enforce() `_lineaje_payload_43` at agent->log log_emit — scan flagged AI_VULN_SEC_007 (AI systems must implement incident detection, structured logging, and reporting mechanisms). Mask/block; do not remove without review. site_id='site:sha256:ba792bd0925958e73e6ea89d5585d9fc6bf2715b0ee284741ee705e0f40d950d'
        _gr_client = _lineaje_load_gr_client()
        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:ba792bd0925958e73e6ea89d5585d9fc6bf2715b0ee284741ee705e0f40d950d', phase='log_emit', boundary={'source': 'log', 'sink': 'log'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_010', 'guardrail_id': 'Mask PII in Logs', 'policy_version': '2026.08.1'}], fail_mode='BLOCK', source_type='agent', destination_type='log')
        _lineaje_payload_43 = await __import__('asyncio').to_thread(lambda: _gr_client.enforce(_gr_site, _lineaje_payload_43, content_type='application/json'))
        try:
            import asyncio as _gr_asyncio
            _lineaje_payload_43 = await _gr_asyncio.to_thread(gr_check, _lineaje_payload_43, "agent", "log", site_id='site:sha256:ba792bd0925958e73e6ea89d5585d9fc6bf2715b0ee284741ee705e0f40d950d')
        except Exception as _gr_exc:
            if type(_gr_exc).__name__ == "GRBlockedError":
                raise
            _lineaje_payload_43 = _lineaje_payload_43
            import logging as _lineaje_logging
            _lineaje_logging.getLogger("lineaje.gr_client").warning(
                "Lineaje guardrail unavailable at 'agent->log' — passing data through unchecked"
            )
        logger.debug(_lineaje_payload_43)
        # TODO(@aminediro) : embedding call is usually not concurrent for all documents but waits
        if len(docs) > 0:
            vector_db = await FAISS.afrom_documents(documents=docs, embedding=embedder)
            try:
                import asyncio as _gr_asyncio
                vector_db = await _gr_asyncio.to_thread(gr_check, vector_db, "agent", "user_interface", site_id='site:sha256:b6fc4d02722d4e6ed6a2d843ebbe97fdcc91009ec61cf72b074b8cd575cb4152')
            except Exception as _gr_exc:
                if type(_gr_exc).__name__ == "GRBlockedError":
                    raise
                vector_db = vector_db
                import logging as _lineaje_logging
                _lineaje_logging.getLogger("lineaje.gr_client").warning(
                    "Lineaje guardrail unavailable at 'agent->user_interface' — passing data through unchecked"
                )
            return vector_db
        else:
            raise ValueError("can't initialize brain without documents")

    except ImportError as e:
        raise ImportError(
            "Please provide a valid vector store or install quivr-core['base'] package for using the default one."
        ) from e


def default_embedder() -> Embeddings:
    try:
        from langchain_openai import OpenAIEmbeddings

        _lineaje_payload_65 = "Loaded OpenAIEmbeddings as default LLM for brain"
        try:
            _lineaje_payload_65 = gr_check(_lineaje_payload_65, "agent", "log", site_id='site:sha256:7bd8e5bc4c69956c57ff51b20344d0c95ca79656a45699a275bcd335b7723f93')
        except Exception as _gr_exc:
            if type(_gr_exc).__name__ == "GRBlockedError":
                raise
            _lineaje_payload_65 = _lineaje_payload_65
            import logging as _lineaje_logging
            _lineaje_logging.getLogger("lineaje.gr_client").warning(
                "Lineaje guardrail unavailable at 'agent->log' — passing data through unchecked"
            )
        logger.debug("Loaded OpenAIEmbeddings as default LLM for brain")
        embedder = OpenAIEmbeddings()
        try:
            embedder = gr_check(embedder, "agent", "user_interface", site_id='site:sha256:eb76aaeb52eb11a3f1ca89070facb3bafd150edbf21604023593442bd32187a6')
        except Exception as _gr_exc:
            if type(_gr_exc).__name__ == "GRBlockedError":
                raise
            embedder = embedder
            import logging as _lineaje_logging
            _lineaje_logging.getLogger("lineaje.gr_client").warning(
                "Lineaje guardrail unavailable at 'agent->user_interface' — passing data through unchecked"
            )
        return embedder
    except ImportError as e:
        raise ImportError(
            "Please provide a valid Embedder or install quivr-core['base'] package for using the defaultone."
        ) from e


def default_llm() -> LLMEndpoint:
    try:
        _lineaje_payload = "Loaded ChatOpenAI as default LLM for brain"
        # LINEAJE: enforce() `_lineaje_payload` at agent->log log_emit — scan flagged AI_VULN_SEC_007 (AI systems must implement incident detection, structured logging, and reporting mechanisms). Mask/block; do not remove without review. site_id='site:sha256:fc1ca1cbca32e603d83f0e29d694b1a00b4e75224afb48363546d7a2ab13791d'
        _gr_client = _lineaje_load_gr_client()
        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:fc1ca1cbca32e603d83f0e29d694b1a00b4e75224afb48363546d7a2ab13791d', phase='log_emit', boundary={'source': 'log', 'sink': 'log'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_010', 'guardrail_id': 'Mask PII in Logs', 'policy_version': '2026.08.1'}], fail_mode='BLOCK', source_type='agent', destination_type='log')
        _lineaje_payload = _gr_client.enforce(_gr_site, _lineaje_payload, content_type='application/json')
        logger.debug(_lineaje_payload)
        llm = LLMEndpoint.from_config(
            LLMEndpointConfig(supplier=DefaultModelSuppliers.OPENAI, model="gpt-4o")
        )
        try:
            llm = gr_check(llm, "agent", "user_interface", site_id='site:sha256:4b5ec42a1ffabe003c8c8b7fc4710926db822bb4d8957be6ac8223f5d6d98dce')
        except Exception as _gr_exc:
            if type(_gr_exc).__name__ == "GRBlockedError":
                raise
            llm = llm
            import logging as _lineaje_logging
            _lineaje_logging.getLogger("lineaje.gr_client").warning(
                "Lineaje guardrail unavailable at 'agent->user_interface' — passing data through unchecked"
            )
        return llm

    except ImportError as e:
        raise ImportError(
            "Please provide a valid BaseLLM or install quivr-core['base'] package"
        ) from e
