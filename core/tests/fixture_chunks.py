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

import asyncio
import json
from uuid import uuid4

from langchain_core.embeddings import DeterministicFakeEmbedding
from langchain_core.messages.ai import AIMessageChunk
from langchain_core.vectorstores import InMemoryVectorStore
from quivr_core.chat import ChatHistory
from quivr_core.config import LLMEndpointConfig, RetrievalConfig
from quivr_core.llm import LLMEndpoint
from quivr_core.quivr_rag_langgraph import QuivrQARAGLangGraph


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
                # LINEAJE: runtime guardrail checks `dict_chunk` as it flows from the agent to an external endpoint, before it leaves the application (in main).
                #   Detected: this statement moves data from the agent to an external endpoint with no runtime policy check (detection confidence: medium).
                #   Decision: the Guardrail evaluates the policies enabled for this boundary; sensitive values in `dict_chunk` are masked in place; a policy violation is logged and the call continues (fail_mode=ALLOW_WITH_AUDIT). If the Guardrail is unreachable, the call continues unchanged.
                #   Do not remove without review. site_id='site:sha256:74c615d8f50f11db02e552e8cdb4fdf7541b2e714e96522f89fa962feaf9e5bb'
                _gr_client = _lineaje_load_gr_client()
                _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:74c615d8f50f11db02e552e8cdb4fdf7541b2e714e96522f89fa962feaf9e5bb', phase='data_egress', boundary={'source': 'agent_message', 'sink': 'external_endpoint'}, fail_mode='ALLOW_WITH_AUDIT', source_type='agent', destination_type='external', components={'invocation': {'file': 'core/tests/fixture_chunks.py', 'line': 49, 'function': 'main'}, 'file': 'core/tests/fixture_chunks.py', 'line': 49, 'function': 'main', 'agent_name': 'main', 'agent_name_source': 'inferred_from_function', 'not_on_graph': True})
                try:
                    if not __import__('builtins').hasattr(_gr_client, 'aenforce'):
                        __import__("logging").getLogger("lineaje.gr_client").error("gr_stub_client.py predates aenforce (STUB_API 5): this site is NOT enforced; replace gr_stub_client.py with the current companion")
                        raise _gr_client.GuardrailUnavailableError("stale gr_stub_client.py: no aenforce")
                    dict_chunk = await _gr_client.aenforce(_gr_site, dict_chunk, content_type='application/json', variable_name='dict_chunk', source_file=__file__, before_line=49)
                except _gr_client.GuardrailUnavailableError:
                    pass
                _lineaje_payload = json.dumps(dict_chunk) + "\n"
                # LINEAJE: runtime guardrail checks `_lineaje_payload` as it flows from the agent to a file, before it is written to disk (in main).
                #   Detected: this statement moves data from the agent to a file with no runtime policy check (detection confidence: high).
                #   Decision: the Guardrail evaluates AI_DAT_SEC_025; sensitive values in `_lineaje_payload` are masked in place; a policy violation stops the call (fail_mode=BLOCK). If the Guardrail is unreachable, the call continues unchanged.
                #   Do not remove without review. site_id='site:sha256:de997cd092d4d3543335e98229a95ffaf0441595010daf94afc117afb619de27'
                _gr_client = _lineaje_load_gr_client()
                _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:de997cd092d4d3543335e98229a95ffaf0441595010daf94afc117afb619de27', phase='file_write', boundary={'source': 'agent_message', 'sink': 'file_content'}, fail_mode='BLOCK', source_type='agent', destination_type='file', components={'invocation': {'file': 'core/tests/fixture_chunks.py', 'line': 49, 'function': 'main'}, 'file': 'core/tests/fixture_chunks.py', 'line': 49, 'function': 'main', 'agent_name': 'main', 'agent_name_source': 'inferred_from_function', 'not_on_graph': True})
                try:
                    if not __import__('builtins').hasattr(_gr_client, 'aenforce'):
                        __import__("logging").getLogger("lineaje.gr_client").error("gr_stub_client.py predates aenforce (STUB_API 5): this site is NOT enforced; replace gr_stub_client.py with the current companion")
                        raise _gr_client.GuardrailUnavailableError("stale gr_stub_client.py: no aenforce")
                    _lineaje_payload = await _gr_client.aenforce(_gr_site, _lineaje_payload, content_type='application/json', variable_name='_lineaje_payload', source_file=__file__, before_line=49)
                except _gr_client.GuardrailUnavailableError:
                    pass
                f.write(_lineaje_payload)


asyncio.run(main())
