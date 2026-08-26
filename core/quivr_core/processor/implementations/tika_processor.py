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
        _mod = gr_check(_mod, "agent", "user_interface", site_id='site:sha256:5a3e646482bdcce7bc36279ddd705389554efb8c3ef5753a27a6bfa69aacd15d')
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
import os
from typing import AsyncIterable

import httpx
import tiktoken
from langchain_core.documents import Document
from langchain_text_splitters import RecursiveCharacterTextSplitter, TextSplitter

from quivr_core.files.file import QuivrFile
from quivr_core.processor.processor_base import ProcessedDocument, ProcessorBase
from quivr_core.processor.registry import FileExtension
from quivr_core.processor.splitter import SplitterConfig

logger = logging.getLogger("quivr_core")


class TikaProcessor(ProcessorBase):
    """
    TikaProcessor is a class that implements the ProcessorBase interface.
    It is used to process the files with the Tika server.

    To run it with docker you can do:
    ```bash
    docker run -d -p 9998:9998 apache/tika
    ```
    """

    supported_extensions = [FileExtension.pdf]

    def __init__(
        self,
        tika_url: str = os.getenv("TIKA_SERVER_URL", "http://localhost:9998/tika"),
        splitter: TextSplitter | None = None,
        splitter_config: SplitterConfig = SplitterConfig(),
        timeout: float = 5.0,
        max_retries: int = 3,
    ) -> None:
        self.tika_url = tika_url
        self.max_retries = max_retries
        self._client = httpx.AsyncClient(timeout=timeout)

        self.enc = tiktoken.get_encoding("cl100k_base")
        self.splitter_config = splitter_config

        if splitter:
            self.text_splitter = splitter
        else:
            self.text_splitter = RecursiveCharacterTextSplitter.from_tiktoken_encoder(
                chunk_size=splitter_config.chunk_size,
                chunk_overlap=splitter_config.chunk_overlap,
            )

    async def _send_parse_tika(self, f: AsyncIterable[bytes]) -> str:
        retry = 0
        headers = {"Accept": "text/plain"}
        while retry < self.max_retries:
            try:
                resp = await self._client.put(self.tika_url, headers=headers, content=f)
                try:
                    import asyncio as _gr_asyncio
                    resp = await _gr_asyncio.to_thread(gr_check, resp, "api", "agent", site_id='site:sha256:4b831e98cf2fe5db3bbeac68440e0b35a72bcfce54e2546662bd648247e58c98')
                except Exception as _gr_exc:
                    if type(_gr_exc).__name__ == "GRBlockedError":
                        raise
                    resp = resp
                    import logging as _lineaje_logging
                    _lineaje_logging.getLogger("lineaje.gr_client").warning(
                        "Lineaje guardrail unavailable at 'api->agent' — passing data through unchecked"
                    )
                # LINEAJE: enforce() `resp` at api->agent post_tool — scan flagged AI_IAC_015 (Enforce URL allowlists for agent fetches, tools, and outbound HTTP.); AI_VULN_SEC_001 (Do not allow critical or high vulnerabilities in the code.). Mask/block; do not remove without review. site_id='site:sha256:4b831e98cf2fe5db3bbeac68440e0b35a72bcfce54e2546662bd648247e58c98'
                _gr_client = _lineaje_load_gr_client()
                _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:4b831e98cf2fe5db3bbeac68440e0b35a72bcfce54e2546662bd648247e58c98', phase='post_tool', boundary={'source': 'external_endpoint', 'sink': 'agent_message'}, candidate_policies=[], fail_mode='ALLOW_WITH_AUDIT', source_type='api', destination_type='agent')
                resp = await __import__('asyncio').to_thread(lambda: _gr_client.enforce(_gr_site, resp, content_type='application/json', variable_name='resp', source_file=__file__, before_line=59))
                resp.raise_for_status()
                return resp.content.decode("utf-8")
            except Exception as e:
                retry += 1
                _lineaje_payload = f"tika url error :{e}. retrying for the {retry} time..."
                # LINEAJE: enforce() `_lineaje_payload` at agent->log log_emit — scan flagged AI_VULN_SEC_007 (AI systems must implement incident detection, structured logging, and reporting mechanisms). Mask/block; do not remove without review. site_id='site:sha256:e3278ed8e92ec19109ebb88abd25cf53e9a09b1aa296607cf60a51ff95bec7c4'
                _gr_client = _lineaje_load_gr_client()
                _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:e3278ed8e92ec19109ebb88abd25cf53e9a09b1aa296607cf60a51ff95bec7c4', phase='log_emit', boundary={'source': 'log', 'sink': 'log'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_010', 'guardrail_id': 'Mask PII in Logs', 'policy_version': '2026.08.1'}], fail_mode='BLOCK', source_type='agent', destination_type='log')
                _lineaje_payload = await __import__('asyncio').to_thread(lambda: _gr_client.enforce(_gr_site, _lineaje_payload, content_type='application/json'))
                try:
                    import asyncio as _gr_asyncio
                    _lineaje_payload = await _gr_asyncio.to_thread(gr_check, _lineaje_payload, "agent", "log", site_id='site:sha256:e3278ed8e92ec19109ebb88abd25cf53e9a09b1aa296607cf60a51ff95bec7c4')
                except Exception as _gr_exc:
                    if type(_gr_exc).__name__ == "GRBlockedError":
                        raise
                    _lineaje_payload = _lineaje_payload
                    import logging as _lineaje_logging
                    _lineaje_logging.getLogger("lineaje.gr_client").warning(
                        "Lineaje guardrail unavailable at 'agent->log' — passing data through unchecked"
                    )
                logger.debug(_lineaje_payload)
        raise RuntimeError("can't send parse request to tika server")

    @property
    def processor_metadata(self):
        return {
            "chunk_overlap": self.splitter_config.chunk_overlap,
        }

    async def process_file_inner(self, file: QuivrFile) -> ProcessedDocument[None]:
        async with file.open() as f:
            txt = await self._send_parse_tika(f)
        document = Document(page_content=txt)
        docs = self.text_splitter.split_documents([document])
        for doc in docs:
            doc.metadata = {"chunk_size": len(self.enc.encode(doc.page_content))}

        return ProcessedDocument(
            chunks=docs, processor_cls="TikaProcessor", processor_response=None
        )
