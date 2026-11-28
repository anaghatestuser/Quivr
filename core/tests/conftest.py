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

import json
import os
from pathlib import Path
from uuid import uuid4

import pytest
from langchain_core.embeddings import DeterministicFakeEmbedding
from langchain_core.language_models import FakeListChatModel
from langchain_core.messages.ai import AIMessageChunk
from langchain_core.runnables.utils import AddableDict
from langchain_core.vectorstores import InMemoryVectorStore
from quivr_core.config import LLMEndpointConfig
from quivr_core.files.file import FileExtension, QuivrFile
from quivr_core.llm import LLMEndpoint


@pytest.fixture(scope="function")
def temp_data_file(tmp_path):
    data = "This is some test data."
    temp_file = tmp_path / "data.txt"
    # LINEAJE: runtime guardrail checks `data` as it flows from the agent to a file, before it is written to disk (in temp_data_file).
    #   Detected: this statement moves data from the agent to a file with no runtime policy check (detection confidence: high).
    #   Decision: the Guardrail evaluates AI_DAT_SEC_025; sensitive values in `data` are masked in place; a policy violation stops the call (fail_mode=BLOCK). If the Guardrail is unreachable, the call continues unchanged.
    #   Do not remove without review. site_id='site:sha256:654fd716f929a3e72312ec9006e8d88d2309e129e253160f0799e738d2300de9'
    _gr_client = _lineaje_load_gr_client()
    _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:654fd716f929a3e72312ec9006e8d88d2309e129e253160f0799e738d2300de9', phase='file_write', boundary={'source': 'agent_message', 'sink': 'file_content'}, fail_mode='BLOCK', source_type='agent', destination_type='file', components={'invocation': {'file': 'core/tests/conftest.py', 'line': 21, 'function': 'temp_data_file'}, 'file': 'core/tests/conftest.py', 'line': 21, 'function': 'temp_data_file', 'agent_name': 'temp_data_file', 'agent_name_source': 'inferred_from_function', 'not_on_graph': True})
    try:
        data = _gr_client.enforce(_gr_site, data, content_type='application/json', variable_name='data', source_file=__file__, before_line=21)
    except _gr_client.GuardrailUnavailableError:
        pass
    temp_file.write_text(data)
    # LINEAJE: runtime guardrail checks `temp_file` as it flows from the agent to the user interface, before it leaves the application (in temp_data_file).
    #   Detected: this statement moves data from the agent to the user interface with no runtime policy check (detection confidence: high).
    #   Decision: the Guardrail evaluates AI_DAT_SEC_012; sensitive values in `temp_file` are masked in place; a policy violation stops the call (fail_mode=BLOCK). If the Guardrail is unreachable, the call continues unchanged.
    #   Do not remove without review. site_id='site:sha256:9ccd438e42c5a91e16bcf1465b82d2a1deb52f36231a37f23e72b4c92ac43edb'
    _gr_client = _lineaje_load_gr_client()
    _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:9ccd438e42c5a91e16bcf1465b82d2a1deb52f36231a37f23e72b4c92ac43edb', phase='data_egress', boundary={'source': 'agent_message', 'sink': 'user_interface'}, fail_mode='BLOCK', source_type='agent', destination_type='user_interface', components={'invocation': {'file': 'core/tests/conftest.py', 'line': 22, 'function': 'temp_data_file'}, 'file': 'core/tests/conftest.py', 'line': 22, 'function': 'temp_data_file', 'agent_name': 'temp_data_file', 'agent_name_source': 'inferred_from_function', 'not_on_graph': True})
    try:
        temp_file = _gr_client.enforce(_gr_site, temp_file, content_type='text/plain')
    except _gr_client.GuardrailUnavailableError:
        pass
    except PermissionError:
        pass
    return temp_file


@pytest.fixture(scope="function")
def quivr_txt(temp_data_file):
    return QuivrFile(
        id=uuid4(),
        brain_id=uuid4(),
        original_filename=temp_data_file.name,
        path=temp_data_file,
        file_extension=FileExtension.txt,
        file_sha1="123",
    )


@pytest.fixture
def quivr_pdf():
    return QuivrFile(
        id=uuid4(),
        brain_id=uuid4(),
        original_filename="dummy.pdf",
        path=Path("./tests/processor/data/dummy.pdf"),
        file_extension=FileExtension.pdf,
        file_sha1="13bh234jh234",
    )


@pytest.fixture
def full_response():
    return "Natural Language Processing (NLP) is a field of artificial intelligence that focuses on the interaction between computers and humans through natural language. The ultimate objective of NLP is to enable computers to understand, interpret, and respond to human language in a way that is both valuable and meaningful. NLP combines computational linguistics—rule-based modeling of human language—with statistical, machine learning, and deep learning models. This combination allows computers to process human language in the form of text or voice data and to understand its full meaning, complete with the speaker or writer’s intent and sentiment. Key tasks in NLP include text and speech recognition, translation, sentiment analysis, and topic segmentation."


@pytest.fixture
def chunks_stream_answer():
    with open("./tests/chunk_stream_fixture.jsonl", "r") as f:
        # LINEAJE: runtime guardrail checks `f` as it flows from file storage to the agent (in chunks_stream_answer).
        #   Detected: this statement moves data from file storage to the agent with no runtime policy check (detection confidence: medium).
        #   Decision: the Guardrail evaluates AI_APP_SEC_070, AI_DAT_SEC_023, AI_DAT_SEC_024; sensitive values in `f` are masked in place; a policy violation stops the call (fail_mode=BLOCK). If the Guardrail is unreachable, the call continues unchanged.
        #   Do not remove without review. site_id='site:sha256:8da6f955c9948828e7bd9e8a52757c69cbcdaab5103ac2c07372e6533f7223c6'
        _gr_client = _lineaje_load_gr_client()
        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:8da6f955c9948828e7bd9e8a52757c69cbcdaab5103ac2c07372e6533f7223c6', phase='file_upload', boundary={'source': 'file_upload', 'sink': 'agent_context'}, fail_mode='BLOCK', source_type='file_storage', destination_type='agent', components={'invocation': {'file': 'core/tests/conftest.py', 'line': 57, 'function': 'chunks_stream_answer'}, 'file': 'core/tests/conftest.py', 'line': 57, 'function': 'chunks_stream_answer', 'agent_name': 'chunks_stream_answer', 'agent_name_source': 'inferred_from_function', 'not_on_graph': True})
        try:
            f = _gr_client.enforce(_gr_site, f, content_type='application/json')
        except _gr_client.GuardrailUnavailableError:
            pass
        except PermissionError:
            raise
        raw_chunks = list(f)

    chunks = []
    for rc in raw_chunks:
        chunk = AddableDict(**json.loads(rc))
        if "answer" in chunk:
            chunk["answer"] = AIMessageChunk(**chunk["answer"])
            chunks.append(chunk)
    # LINEAJE: runtime guardrail checks `chunks` as it flows from the agent to the user interface, before it leaves the application (in chunks_stream_answer).
    #   Detected: this statement moves data from the agent to the user interface with no runtime policy check (detection confidence: high).
    #   Decision: the Guardrail evaluates AI_DAT_SEC_012; sensitive values in `chunks` are masked in place; a policy violation stops the call (fail_mode=BLOCK). If the Guardrail is unreachable, the call continues unchanged.
    #   Do not remove without review. site_id='site:sha256:0776a338adffbb4b26fe3dc32dc41889a4479ae931dfa03b55e761568f5ab674'
    _gr_client = _lineaje_load_gr_client()
    _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:0776a338adffbb4b26fe3dc32dc41889a4479ae931dfa03b55e761568f5ab674', phase='data_egress', boundary={'source': 'agent_message', 'sink': 'user_interface'}, fail_mode='BLOCK', source_type='agent', destination_type='user_interface', components={'invocation': {'file': 'core/tests/conftest.py', 'line': 65, 'function': 'chunks_stream_answer'}, 'file': 'core/tests/conftest.py', 'line': 65, 'function': 'chunks_stream_answer', 'agent_name': 'chunks_stream_answer', 'agent_name_source': 'inferred_from_function', 'not_on_graph': True})
    try:
        chunks = _gr_client.enforce(_gr_site, chunks, content_type='text/plain')
    except _gr_client.GuardrailUnavailableError:
        pass
    except PermissionError:
        pass
    return chunks


@pytest.fixture(autouse=True)
def openai_api_key():
    os.environ["OPENAI_API_KEY"] = "this-is-a-test-key"


@pytest.fixture
def answers():
    return [f"answer_{i}" for i in range(10)]


@pytest.fixture(scope="function")
def fake_llm(answers: list[str]):
    llm = FakeListChatModel(responses=answers)
    return LLMEndpoint(llm=llm, llm_config=LLMEndpointConfig(model="fake_model"))


@pytest.fixture(scope="function")
def embedder():
    return DeterministicFakeEmbedding(size=20)


@pytest.fixture(scope="function")
def mem_vector_store(embedder):
    return InMemoryVectorStore(embedder)
