# Copyright (c) Lineaje, Inc. All rights reserved.
# Lineaje UnifAI guardrail  version=2.0.0-alpha
def _lineaje_gr_load(_f):
    """Lineaje-added: load gr_stub_client.py beside _f or in one of its 7 parent folders. Missing or broken:
    a pass-through client and ONE warning per process (GR_REQUIRE_CLIENT=1: ImportError instead)."""
    import sys, os, logging, importlib.util as u, pathlib
    n = "_lineaje_gr_stub_client"
    if n in sys.modules: return sys.modules[n]
    h = pathlib.Path(_f or ".").resolve().parent
    d = [h, *h.parents][:8]
    p = next((x / "gr_stub_client.py" for x in d if (x / "gr_stub_client.py").is_file()), None)
    try:
        s = u.spec_from_file_location(n, p) if p else None
        if s is None: raise FileNotFoundError("gr_stub_client.py")
        m = sys.modules[n] = u.module_from_spec(s); s.loader.exec_module(m); return m
    except Exception as e:
        sys.modules.pop(n, None)
        w = ("gr_stub_client.py not found for %s (searched: %s)" % (_f or "<no __file__>", ", ".join(map(str, d)))
             if p is None else "%s failed to load (%s%s)" % (p, type(e).__name__,
                                                          " line %s" % e.lineno if isinstance(e, SyntaxError) else ""))
        w = ("Lineaje guardrail NOT active: " + w + ". Calls pass through unchecked; set GR_REQUIRE_CLIENT=1 to fail "
             "instead. Each deploy unit needs gr_stub_client.py beside its code and GR_SERVICE_URL plus credentials as "
             "environment variables.")
        if os.environ.get("GR_REQUIRE_CLIENT", "").strip() == "1": raise ImportError(w) from (None if p is None else e)
        z = sys.__dict__.setdefault("_lineaje_gr_null", __import__('types').SimpleNamespace(STUB_API=999999, GuardrailUnavailableError=type('GuardrailUnavailableError', (PermissionError,), {}), SiteDescriptor=lambda *a, **k: None, new_interaction_id=lambda *a, **k: None, enforce=lambda _s, _p, *a, **k: _p, enforce_request=lambda _s, _p, *a, **k: _p, enforce_reply=lambda _s, _p, *a, **k: _p, _lineaje_seen=set()))
        k = "missing" if p is None else (str(p), type(e).__name__)
        if k not in z._lineaje_seen:
            z._lineaje_seen.add(k); g = logging.getLogger("lineaje.guardrail"); g.log(30 if p is None else 40, w)
            if g.hasHandlers(): sys.stderr.write(w + "\n")
        return z
__import__("sys").__dict__.setdefault("_lineaje_gr_load_v1", _lineaje_gr_load)
del _lineaje_gr_load
def _lineaje_load_gr_client():
    """Lineaje-added: this file's gr_stub_client.py (the loader _lineaje_gr_load registered)."""
    return __import__("sys").__dict__["_lineaje_gr_load_v1"](globals().get("__file__"))
if __import__("os").environ.get("GR_REQUIRE_CLIENT", "").strip() == "1": __import__("sys").__dict__["_lineaje_gr_load_v1"](globals().get("__file__"))

import logging
from typing import AsyncIterable

import httpx
from langchain_core.documents import Document
from langchain_text_splitters import RecursiveCharacterTextSplitter, TextSplitter

from quivr_core.files.file import QuivrFile
from quivr_core.processor.processor_base import ProcessorBase
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
        tika_url: str = "http://localhost:9998/tika",
        splitter: TextSplitter | None = None,
        splitter_config: SplitterConfig = SplitterConfig(),
        timeout: float = 5.0,
        max_retries: int = 3,
    ) -> None:
        self.tika_url = tika_url
        self.max_retries = max_retries
        self._client = httpx.AsyncClient(timeout=timeout)

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
                # LINEAJE: runtime guardrail checks `resp` as it flows from an external API to the agent, after the tool returns (in TikaProcessor._send_parse_tika).
                #   Detected: this statement moves data from an external API to the agent with no runtime policy check (detection confidence: low).
                #   Decision: the Guardrail evaluates the policies enabled for this boundary; sensitive values in `resp` are masked in place; a policy violation is logged and the call continues (fail_mode=ALLOW_WITH_AUDIT). If the Guardrail is unreachable, the call continues unchanged.
                #   Do not remove without review. site_id='site:sha256:4b831e98cf2fe5db3bbeac68440e0b35a72bcfce54e2546662bd648247e58c98'
                _gr_client = _lineaje_load_gr_client()
                _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:4b831e98cf2fe5db3bbeac68440e0b35a72bcfce54e2546662bd648247e58c98', phase='post_tool', boundary={'source': 'external_endpoint', 'sink': 'agent_message'}, fail_mode='ALLOW_WITH_AUDIT', source_type='api', destination_type='agent', components={'invocation': {'file': 'core/quivr_core/processor/implementations/tika_processor.py', 'line': 56, 'function': 'TikaProcessor._send_parse_tika'}, 'file': 'core/quivr_core/processor/implementations/tika_processor.py', 'line': 56, 'function': '_send_parse_tika', 'agent_name': 'TikaProcessor', 'agent_name_source': 'inferred_from_class', 'not_on_graph': True})
                try:
                    if not __import__('builtins').hasattr(_gr_client, 'aenforce'):
                        __import__("logging").getLogger("lineaje.gr_client").error("gr_stub_client.py predates aenforce (STUB_API 5): this site is NOT enforced; replace gr_stub_client.py with the current companion")
                        raise _gr_client.GuardrailUnavailableError("stale gr_stub_client.py: no aenforce")
                    resp = await _gr_client.aenforce(_gr_site, resp, content_type='application/json', variable_name='resp', source_file=__file__, before_line=56)
                except _gr_client.GuardrailUnavailableError:
                    pass
                resp.raise_for_status()
                return resp.content.decode("utf-8")
            except Exception as e:
                retry += 1
                _lineaje_payload = f"tika url error :{e}. retrying for the {retry} time..."
                # LINEAJE: runtime guardrail checks `_lineaje_payload` as it flows from the agent to the application log, before it is written to the log (in TikaProcessor._send_parse_tika).
                #   Detected: this statement moves data from the agent to the application log with no runtime policy check (detection confidence: high).
                #   Decision: the Guardrail evaluates AI_DAT_SEC_010; sensitive values in `_lineaje_payload` are masked in place; a policy violation stops the call (fail_mode=BLOCK). If the Guardrail is unreachable, the call continues unchanged.
                #   Do not remove without review. site_id='site:sha256:e3278ed8e92ec19109ebb88abd25cf53e9a09b1aa296607cf60a51ff95bec7c4'
                _gr_client = _lineaje_load_gr_client()
                _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:e3278ed8e92ec19109ebb88abd25cf53e9a09b1aa296607cf60a51ff95bec7c4', phase='log_emit', boundary={'source': 'log', 'sink': 'log'}, fail_mode='BLOCK', source_type='agent', destination_type='log', components={'invocation': {'file': 'core/quivr_core/processor/implementations/tika_processor.py', 'line': 61, 'function': 'TikaProcessor._send_parse_tika'}, 'file': 'core/quivr_core/processor/implementations/tika_processor.py', 'line': 61, 'function': '_send_parse_tika', 'agent_name': 'TikaProcessor', 'agent_name_source': 'inferred_from_class', 'not_on_graph': True})
                try:
                    if not __import__('builtins').hasattr(_gr_client, 'aenforce'):
                        __import__("logging").getLogger("lineaje.gr_client").error("gr_stub_client.py predates aenforce (STUB_API 5): this site is NOT enforced; replace gr_stub_client.py with the current companion")
                        raise _gr_client.GuardrailUnavailableError("stale gr_stub_client.py: no aenforce")
                    _lineaje_payload = await _gr_client.aenforce(_gr_site, _lineaje_payload, content_type='application/json')
                except _gr_client.GuardrailUnavailableError:
                    pass
                except PermissionError:
                    pass
                logger.debug(_lineaje_payload)
        raise RuntimeError("can't send parse request to tika server")

    @property
    def processor_metadata(self):
        return {
            "chunk_overlap": self.splitter_config.chunk_overlap,
        }

    async def process_file_inner(self, file: QuivrFile) -> list[Document]:
        async with file.open() as f:
            txt = await self._send_parse_tika(f)
        document = Document(page_content=txt)
        _lineaje_payload = [document]
        # LINEAJE: runtime guardrail checks `_lineaje_payload` as it flows from rag source to the RAG pipeline, before the tool runs (in TikaProcessor.process_file_inner).
        #   Detected: this statement moves data from rag source to the RAG pipeline with no runtime policy check (detection confidence: high).
        #   Decision: the Guardrail evaluates the policies enabled for this boundary; sensitive values in `_lineaje_payload` are masked in place; a policy violation is logged and the call continues (fail_mode=ALLOW_WITH_AUDIT). If the Guardrail is unreachable, the call continues unchanged.
        #   Do not remove without review. site_id='site:sha256:4e8c14e61065c77f2c38f662eb118dfaadd5912ae64c1e97d453f884442b8029'
        _gr_client = _lineaje_load_gr_client()
        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:4e8c14e61065c77f2c38f662eb118dfaadd5912ae64c1e97d453f884442b8029', phase='pre_tool', boundary={'source': 'rag_source', 'sink': 'rag_pipeline'}, fail_mode='ALLOW_WITH_AUDIT', source_type='rag_source', destination_type='rag_pipeline', components={'invocation': {'file': 'core/quivr_core/processor/implementations/tika_processor.py', 'line': 74, 'function': 'TikaProcessor.process_file_inner'}, 'file': 'core/quivr_core/processor/implementations/tika_processor.py', 'line': 74, 'function': 'process_file_inner', 'agent_name': 'TikaProcessor', 'agent_name_source': 'inferred_from_class', 'not_on_graph': True})
        try:
            if not __import__('builtins').hasattr(_gr_client, 'aenforce'):
                __import__("logging").getLogger("lineaje.gr_client").error("gr_stub_client.py predates aenforce (STUB_API 5): this site is NOT enforced; replace gr_stub_client.py with the current companion")
                raise _gr_client.GuardrailUnavailableError("stale gr_stub_client.py: no aenforce")
            _lineaje_payload = await _gr_client.aenforce(_gr_site, _lineaje_payload, content_type='application/json', variable_name='_lineaje_payload', source_file=__file__, before_line=74)
        except _gr_client.GuardrailUnavailableError:
            pass
        docs = self.text_splitter.split_documents(_lineaje_payload)

        # LINEAJE: runtime guardrail checks `docs` as it flows from the agent to the user interface, before it leaves the application (in TikaProcessor.process_file_inner).
        #   Detected: this statement moves data from the agent to the user interface with no runtime policy check (detection confidence: high).
        #   Decision: the Guardrail evaluates AI_DAT_SEC_012; sensitive values in `docs` are masked in place; a policy violation stops the call (fail_mode=BLOCK). If the Guardrail is unreachable, the call continues unchanged.
        #   Do not remove without review. site_id='site:sha256:89419f9b39af977f2d1f56e5b0100282f718a1c02646d216c78910148aa822bf'
        _gr_client = _lineaje_load_gr_client()
        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:89419f9b39af977f2d1f56e5b0100282f718a1c02646d216c78910148aa822bf', phase='data_egress', boundary={'source': 'agent_message', 'sink': 'user_interface'}, fail_mode='BLOCK', source_type='agent', destination_type='user_interface', components={'invocation': {'file': 'core/quivr_core/processor/implementations/tika_processor.py', 'line': 76, 'function': 'TikaProcessor.process_file_inner'}, 'file': 'core/quivr_core/processor/implementations/tika_processor.py', 'line': 76, 'function': 'process_file_inner', 'agent_name': 'TikaProcessor', 'agent_name_source': 'inferred_from_class', 'not_on_graph': True})
        try:
            if not __import__('builtins').hasattr(_gr_client, 'aenforce'):
                __import__("logging").getLogger("lineaje.gr_client").error("gr_stub_client.py predates aenforce (STUB_API 5): this site is NOT enforced; replace gr_stub_client.py with the current companion")
                raise _gr_client.GuardrailUnavailableError("stale gr_stub_client.py: no aenforce")
            docs = await _gr_client.aenforce(_gr_site, docs, content_type='text/plain')
        except _gr_client.GuardrailUnavailableError:
            pass
        except PermissionError:
            pass
        return docs
