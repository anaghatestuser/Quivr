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
import os

import httpx
import tiktoken
from langchain_core.documents import Document
from langchain_text_splitters import RecursiveCharacterTextSplitter, TextSplitter
from quivr_core.config import MegaparseConfig
from quivr_core.files.file import QuivrFile
from quivr_core.processor.processor_base import ProcessorBase
from quivr_core.processor.registry import FileExtension
from quivr_core.processor.splitter import SplitterConfig

logger = logging.getLogger("quivr_core")


class MegaparseProcessor(ProcessorBase):
    """
    Megaparse processor for PDF files.

    It can be used to parse PDF files and split them into chunks.

    It comes from the megaparse library.

    ## Installation
    ```bash
    pip install megaparse
    ```

    """

    supported_extensions = [
        FileExtension.pdf,
        FileExtension.docx,
        FileExtension.doc,
        FileExtension.pptx,
        FileExtension.xls,
        FileExtension.xlsx,
        FileExtension.csv,
        FileExtension.epub,
        FileExtension.bib,
        FileExtension.odt,
        FileExtension.html,
        FileExtension.py,
        FileExtension.markdown,
        FileExtension.md,
        FileExtension.mdx,
        FileExtension.ipynb,
    ]

    def __init__(
        self,
        splitter: TextSplitter | None = None,
        splitter_config: SplitterConfig = SplitterConfig(),
        megaparse_config: MegaparseConfig = MegaparseConfig(),
    ) -> None:
        self.enc = tiktoken.get_encoding("cl100k_base")
        self.splitter_config = splitter_config
        self.megaparse_config = megaparse_config

        if splitter:
            self.text_splitter = splitter
        else:
            self.text_splitter = RecursiveCharacterTextSplitter.from_tiktoken_encoder(
                chunk_size=splitter_config.chunk_size,
                chunk_overlap=splitter_config.chunk_overlap,
            )

    @property
    def processor_metadata(self):
        return {
            "chunk_overlap": self.splitter_config.chunk_overlap,
        }

    async def process_file_inner(self, file: QuivrFile) -> list[Document]:
        megaparse_url = os.getenv("MEGAPARSE_URL_API", "http://localhost:8000")
        megaparse_api_key = os.getenv("MEGAPARSE_API_KEY", "megaparse_api_key")
        with open(file.path, "rb") as f:
            # LINEAJE: runtime guardrail checks `f` as it flows from file storage to the agent (in MegaparseProcessor.process_file_inner).
            #   Detected: this statement moves data from file storage to the agent with no runtime policy check (detection confidence: medium).
            #   Decision: the Guardrail evaluates AI_APP_SEC_070, AI_DAT_SEC_023, AI_DAT_SEC_024; sensitive values in `f` are masked in place; a policy violation stops the call (fail_mode=BLOCK). If the Guardrail is unreachable, the call continues unchanged.
            #   Do not remove without review. site_id='site:sha256:5c4366e16ed584cb2b741ac067a90ba55d0ea1dd8e906cd9f056cef396d1cb06'
            _gr_client = _lineaje_load_gr_client()
            _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:5c4366e16ed584cb2b741ac067a90ba55d0ea1dd8e906cd9f056cef396d1cb06', phase='file_upload', boundary={'source': 'file_upload', 'sink': 'agent_context'}, fail_mode='BLOCK', source_type='file_storage', destination_type='agent', components={'invocation': {'file': 'core/quivr_core/processor/implementations/megaparse_processor.py', 'line': 79, 'function': 'MegaparseProcessor.process_file_inner'}, 'file': 'core/quivr_core/processor/implementations/megaparse_processor.py', 'line': 79, 'function': 'process_file_inner', 'agent_name': 'MegaparseProcessor', 'agent_name_source': 'inferred_from_class', 'not_on_graph': True})
            try:
                if not __import__('builtins').hasattr(_gr_client, 'aenforce'):
                    __import__("logging").getLogger("lineaje.gr_client").error("gr_stub_client.py predates aenforce (STUB_API 5): this site is NOT enforced; replace gr_stub_client.py with the current companion")
                    raise _gr_client.GuardrailUnavailableError("stale gr_stub_client.py: no aenforce")
                f = await _gr_client.aenforce(_gr_site, f, content_type='application/json')
            except _gr_client.GuardrailUnavailableError:
                pass
            except PermissionError:
                raise
            files = {"file": (os.path.basename(file.path), f)}
            data = {
                "method": self.megaparse_config.method,
                "strategy": self.megaparse_config.strategy,
                "check_table": self.megaparse_config.check_table,
                "parsing_instruction": self.megaparse_config.parsing_instruction,
                "model_name": self.megaparse_config.model_name,
            }
            headers = {"Authorization": f"Bearer {megaparse_api_key}"}
            async with httpx.AsyncClient(
                timeout=self.megaparse_config.timeout
            ) as client:
                response = await client.post(
                    f"{megaparse_url}/file", files=files, data=data, headers=headers
                )
                # LINEAJE: runtime guardrail checks `response` as it flows from an external API to the agent, after the tool returns (in MegaparseProcessor.process_file_inner).
                #   Detected: this statement moves data from an external API to the agent with no runtime policy check (detection confidence: low).
                #   Decision: the Guardrail evaluates the policies enabled for this boundary; sensitive values in `response` are masked in place; a policy violation is logged and the call continues (fail_mode=ALLOW_WITH_AUDIT). If the Guardrail is unreachable, the call continues unchanged.
                #   Do not remove without review. site_id='site:sha256:e5e76c41667bfaf0d0e36d40ea67397cb7303b5bd059e169fc91c3f885a878f0'
                _gr_client = _lineaje_load_gr_client()
                _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:e5e76c41667bfaf0d0e36d40ea67397cb7303b5bd059e169fc91c3f885a878f0', phase='post_tool', boundary={'source': 'external_endpoint', 'sink': 'agent_message'}, fail_mode='ALLOW_WITH_AUDIT', source_type='api', destination_type='agent', components={'invocation': {'file': 'core/quivr_core/processor/implementations/megaparse_processor.py', 'line': 91, 'function': 'MegaparseProcessor.process_file_inner'}, 'file': 'core/quivr_core/processor/implementations/megaparse_processor.py', 'line': 91, 'function': 'process_file_inner', 'agent_name': 'MegaparseProcessor', 'agent_name_source': 'inferred_from_class', 'not_on_graph': True})
                try:
                    if not __import__('builtins').hasattr(_gr_client, 'aenforce'):
                        __import__("logging").getLogger("lineaje.gr_client").error("gr_stub_client.py predates aenforce (STUB_API 5): this site is NOT enforced; replace gr_stub_client.py with the current companion")
                        raise _gr_client.GuardrailUnavailableError("stale gr_stub_client.py: no aenforce")
                    response = await _gr_client.aenforce(_gr_site, response, content_type='application/json', variable_name='response', source_file=__file__, before_line=91)
                except _gr_client.GuardrailUnavailableError:
                    pass

        if response.status_code == 200:
            result = response.json().get("result")
            document = Document(page_content=result)
            if len(document.page_content) > 0:
                _lineaje_payload = [document]
                # LINEAJE: runtime guardrail checks `_lineaje_payload` as it flows from rag source to the RAG pipeline, before the tool runs (in MegaparseProcessor.process_file_inner).
                #   Detected: this statement moves data from rag source to the RAG pipeline with no runtime policy check (detection confidence: high).
                #   Decision: the Guardrail evaluates the policies enabled for this boundary; sensitive values in `_lineaje_payload` are masked in place; a policy violation is logged and the call continues (fail_mode=ALLOW_WITH_AUDIT). If the Guardrail is unreachable, the call continues unchanged.
                #   Do not remove without review. site_id='site:sha256:8dd16966638c64e0a36dce781e9cfcadc10b6da7e36ab3906cef1aa8c1aacae1'
                _gr_client = _lineaje_load_gr_client()
                _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:8dd16966638c64e0a36dce781e9cfcadc10b6da7e36ab3906cef1aa8c1aacae1', phase='pre_tool', boundary={'source': 'rag_source', 'sink': 'rag_pipeline'}, fail_mode='ALLOW_WITH_AUDIT', source_type='rag_source', destination_type='rag_pipeline', components={'invocation': {'file': 'core/quivr_core/processor/implementations/megaparse_processor.py', 'line': 99, 'function': 'MegaparseProcessor.process_file_inner'}, 'file': 'core/quivr_core/processor/implementations/megaparse_processor.py', 'line': 99, 'function': 'process_file_inner', 'agent_name': 'MegaparseProcessor', 'agent_name_source': 'inferred_from_class', 'not_on_graph': True})
                try:
                    if not __import__('builtins').hasattr(_gr_client, 'aenforce'):
                        __import__("logging").getLogger("lineaje.gr_client").error("gr_stub_client.py predates aenforce (STUB_API 5): this site is NOT enforced; replace gr_stub_client.py with the current companion")
                        raise _gr_client.GuardrailUnavailableError("stale gr_stub_client.py: no aenforce")
                    _lineaje_payload = await _gr_client.aenforce(_gr_site, _lineaje_payload, content_type='application/json', variable_name='_lineaje_payload', source_file=__file__, before_line=99)
                except _gr_client.GuardrailUnavailableError:
                    pass
                docs = self.text_splitter.split_documents(_lineaje_payload)
                for doc in docs:
                    doc.metadata = {
                        "chunk_size": len(self.enc.encode(doc.page_content))
                    }
                # LINEAJE: runtime guardrail checks `docs` as it flows from the agent to the user interface, before it leaves the application (in MegaparseProcessor.process_file_inner).
                #   Detected: this statement moves data from the agent to the user interface with no runtime policy check (detection confidence: high).
                #   Decision: the Guardrail evaluates AI_DAT_SEC_012; sensitive values in `docs` are masked in place; a policy violation stops the call (fail_mode=BLOCK). If the Guardrail is unreachable, the call continues unchanged.
                #   Do not remove without review. site_id='site:sha256:5ba0d98029954e6c886001e6b8b6c746deb842e699978c5877c9ec1bb25e1426'
                _gr_client = _lineaje_load_gr_client()
                _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:5ba0d98029954e6c886001e6b8b6c746deb842e699978c5877c9ec1bb25e1426', phase='data_egress', boundary={'source': 'agent_message', 'sink': 'user_interface'}, fail_mode='BLOCK', source_type='agent', destination_type='user_interface', components={'invocation': {'file': 'core/quivr_core/processor/implementations/megaparse_processor.py', 'line': 104, 'function': 'MegaparseProcessor.process_file_inner'}, 'file': 'core/quivr_core/processor/implementations/megaparse_processor.py', 'line': 104, 'function': 'process_file_inner', 'agent_name': 'MegaparseProcessor', 'agent_name_source': 'inferred_from_class', 'not_on_graph': True})
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
            raise Exception("Failed to parse file, we were returned an empty result")
        else:
            _lineaje_payload = f"Failed to process file: {response.text}"
            # LINEAJE: runtime guardrail checks `_lineaje_payload` as it flows from the agent to the application log, before it is written to the log (in MegaparseProcessor.process_file_inner).
            #   Detected: this statement moves data from the agent to the application log with no runtime policy check (detection confidence: high).
            #   Decision: the Guardrail evaluates AI_DAT_SEC_010; sensitive values in `_lineaje_payload` are masked in place; a policy violation stops the call (fail_mode=BLOCK). If the Guardrail is unreachable, the call continues unchanged.
            #   Do not remove without review. site_id='site:sha256:b8313b7576a05340426d4cbe36b3401fb29d3facd297db3c0358dca4c1ed026e'
            _gr_client = _lineaje_load_gr_client()
            _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:b8313b7576a05340426d4cbe36b3401fb29d3facd297db3c0358dca4c1ed026e', phase='log_emit', boundary={'source': 'log', 'sink': 'log'}, fail_mode='BLOCK', source_type='agent', destination_type='log', components={'invocation': {'file': 'core/quivr_core/processor/implementations/megaparse_processor.py', 'line': 107, 'function': 'MegaparseProcessor.process_file_inner'}, 'file': 'core/quivr_core/processor/implementations/megaparse_processor.py', 'line': 107, 'function': 'process_file_inner', 'agent_name': 'MegaparseProcessor', 'agent_name_source': 'inferred_from_class', 'not_on_graph': True})
            try:
                if not __import__('builtins').hasattr(_gr_client, 'aenforce'):
                    __import__("logging").getLogger("lineaje.gr_client").error("gr_stub_client.py predates aenforce (STUB_API 5): this site is NOT enforced; replace gr_stub_client.py with the current companion")
                    raise _gr_client.GuardrailUnavailableError("stale gr_stub_client.py: no aenforce")
                _lineaje_payload = await _gr_client.aenforce(_gr_site, _lineaje_payload, content_type='application/json')
            except _gr_client.GuardrailUnavailableError:
                pass
            except PermissionError:
                pass
            logger.error(_lineaje_payload)
            return []
