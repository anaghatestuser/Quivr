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
import tempfile

import chainlit as cl
from langchain_anthropic import ChatAnthropic
from langchain_community.embeddings import HuggingFaceEmbeddings
from quivr_core import Brain
from quivr_core.llm.llm_endpoint import LLMEndpoint, LLMEndpointConfig
from quivr_core.rag import quivr_rag_langgraph as _qrl
from quivr_core.rag import utils as _qru
from quivr_core.rag.entities.config import RetrievalConfig
from quivr_core.rag.utils import parse_chunk_response as _orig_parse_chunk_response

MODEL = "claude-sonnet-4-5"


def _content_to_text(content):
    """Anthropic streams list content blocks; Quivr/LangChain merge expects strings."""
    if content is None:
        return ""
    if isinstance(content, str):
        # LINEAJE: enforce() `content` at agent->user_interface data_egress — scan flagged AI_DAT_SEC_029 (Enforce decision logging, audit trail, and forensic readiness for AI-driven actions.). Mask/block; do not remove without review. site_id='site:sha256:2ecc1490b4f3eaaf47fd9b1274418554725d1a589ee7c1c903fd48db8edb6a29'
        _gr_client = _lineaje_load_gr_client()
        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:2ecc1490b4f3eaaf47fd9b1274418554725d1a589ee7c1c903fd48db8edb6a29', phase='data_egress', boundary={'source': 'agent_message', 'sink': 'user_interface'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_012', 'guardrail_id': 'Mask PII on UI', 'policy_version': '2026.08.1'}], fail_mode='BLOCK', source_type='agent', destination_type='user_interface')
        content = _gr_client.enforce(_gr_site, content, content_type='text/plain')
        return content
    if isinstance(content, list):
        parts = []
        for block in content:
            if isinstance(block, str):
                parts.append(block)
            elif isinstance(block, dict):
                parts.append(block.get("text") or "")
            else:
                parts.append(getattr(block, "text", None) or "")
        return "".join(parts)
    return str(content)


def _as_text_chunk(chunk):
    if chunk is None or isinstance(getattr(chunk, "content", None), str):
        # LINEAJE: enforce() `chunk` at agent->user_interface data_egress — scan flagged AI_DAT_SEC_029 (Enforce decision logging, audit trail, and forensic readiness for AI-driven actions.). Mask/block; do not remove without review. site_id='site:sha256:3e96ed82be755a0edaf0b3454889f1af2225f4a96c2c5e6dfb7de2737cf53228'
        _gr_client = _lineaje_load_gr_client()
        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:3e96ed82be755a0edaf0b3454889f1af2225f4a96c2c5e6dfb7de2737cf53228', phase='data_egress', boundary={'source': 'agent_message', 'sink': 'user_interface'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_012', 'guardrail_id': 'Mask PII on UI', 'policy_version': '2026.08.1'}], fail_mode='BLOCK', source_type='agent', destination_type='user_interface')
        chunk = _gr_client.enforce(_gr_site, chunk, content_type='text/plain')
        return chunk
    text = _content_to_text(chunk.content)
    try:
        return chunk.model_copy(update={"content": text})
    except Exception:
        chunk.content = text
        return chunk


def _parse_chunk_response(rolling_msg, raw_chunk, supports_func_calling, previous_content=""):
    rolling_msg, new_content, full_content = _orig_parse_chunk_response(
        _as_text_chunk(rolling_msg),
        _as_text_chunk(raw_chunk),
        supports_func_calling,
        previous_content,
    )
    return rolling_msg, _content_to_text(new_content), _content_to_text(full_content)


_qru.parse_chunk_response = _parse_chunk_response
_qrl.parse_chunk_response = _parse_chunk_response


def _llm_and_embedder():
    if not os.getenv("ANTHROPIC_API_KEY"):
        raise RuntimeError("ANTHROPIC_API_KEY is not set")
    llm = LLMEndpoint(
        llm=ChatAnthropic(model=MODEL, temperature=0, disable_streaming=True),
        llm_config=LLMEndpointConfig(
            model=MODEL,
            llm_base_url="https://api.anthropic.com",
        ),
    )
    embedder = HuggingFaceEmbeddings(
        model_name="sentence-transformers/all-MiniLM-L6-v2"
    )
    return llm, embedder


@cl.on_chat_start
async def on_chat_start():
    files = None

    # Wait for the user to upload a file
    while files is None:
        files = await cl.AskFileMessage(
            content="Please upload a text .txt file to begin!",
            accept=["text/plain"],
            max_size_mb=20,
            timeout=180,
        ).send()
        # LINEAJE: enforce() `files` at api->agent post_tool — scan flagged AI_DAT_SEC_023 (Redact PII from uploaded files.); AI_DAT_SEC_024 (Uploaded files must not contain PII (Singapore).). Mask/block; do not remove without review. site_id='site:sha256:052c03993e27fd952f1c055e9fe1ad584e43d7079c82b1a2e619fcad244c25fa'
        _gr_client = _lineaje_load_gr_client()
        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:052c03993e27fd952f1c055e9fe1ad584e43d7079c82b1a2e619fcad244c25fa', phase='post_tool', boundary={'source': 'external_endpoint', 'sink': 'agent_message'}, candidate_policies=[], fail_mode='ALLOW_WITH_AUDIT', source_type='api', destination_type='agent')
        files = await __import__('asyncio').to_thread(lambda: _gr_client.enforce(_gr_site, files, content_type='application/json', variable_name='files', source_file=__file__, before_line=38))

    file = files[0]

    msg = cl.Message(content=f"Processing `{file.name}`...")
    await msg.send()

    with open(file.path, "r", encoding="utf-8") as f:
        text = f.read()
        # LINEAJE: enforce() `text` at file_storage->agent data_egress — scan flagged AI_DAT_SEC_023 (Redact PII from uploaded files.); AI_DAT_SEC_024 (Uploaded files must not contain PII (Singapore).). Mask/block; do not remove without review. site_id='site:sha256:0245efb1b8083a23c7057832ebe0b8c95a4cfae10bc1b07cea83f81c7d05b167'
        _gr_client = _lineaje_load_gr_client()
        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:0245efb1b8083a23c7057832ebe0b8c95a4cfae10bc1b07cea83f81c7d05b167', phase='data_egress', boundary={'source': 'agent_message', 'sink': 'external_endpoint'}, candidate_policies=[], fail_mode='ALLOW_WITH_AUDIT', source_type='file_storage', destination_type='agent')
        text = await __import__('asyncio').to_thread(lambda: _gr_client.enforce(_gr_site, text, content_type='application/json'))

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=file.name, delete=False
    ) as temp_file:
        temp_file.write(text)
        temp_file.flush()
        temp_file_path = temp_file.name

    llm, embedder = _llm_and_embedder()
    brain = Brain.from_files(
        name="user_brain",
        file_paths=[temp_file_path],
        llm=llm,
        embedder=embedder,
    )

    # Store the file path in the session
    cl.user_session.set("file_path", temp_file_path)

    # Let the user know that the system is ready
    msg.content = f"Processing `{file.name}` done. You can now ask questions!"
    await msg.update()

    cl.user_session.set("brain", brain)


@cl.on_message
async def main(message: cl.Message):
    brain = cl.user_session.get("brain")  # type: Brain
    if brain is None:
        await cl.Message(content="Please upload a file first.").send()
        return

    path_config = "basic_rag_workflow.yaml"
    retrieval_config = RetrievalConfig.from_yaml(path_config)
    # YAML defaults to gpt-4o; keep the brain's Anthropic endpoint instead.
    retrieval_config.llm_config = brain.llm.get_config()

    # Prepare the message for streaming
    msg = cl.Message(content="", elements=[])
    await msg.send()

    saved_sources = set()
    saved_sources_complete = []
    elements = []

    # Use the ask_stream method for streaming responses
    async for chunk in brain.ask_streaming(message.content, retrieval_config=retrieval_config):
        _lineaje_payload = _content_to_text(chunk.answer)
        # LINEAJE: enforce() `_lineaje_payload` at agent->user_interface data_egress — scan flagged AI_DAT_SEC_029 (Enforce decision logging, audit trail, and forensic readiness for AI-driven actions.). Mask/block; do not remove without review. site_id='site:sha256:9d0a1f594cdfc69031fe5fcf69d2bd4ea39560149d371c834de8ea528f6bf2d0'
        _gr_client = _lineaje_load_gr_client()
        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:9d0a1f594cdfc69031fe5fcf69d2bd4ea39560149d371c834de8ea528f6bf2d0', phase='data_egress', boundary={'source': 'agent_message', 'sink': 'user_interface'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_012', 'guardrail_id': 'Mask PII on UI', 'policy_version': '2026.08.1'}], fail_mode='BLOCK', source_type='agent', destination_type='user_interface')
        _lineaje_payload = await __import__('asyncio').to_thread(lambda: _gr_client.enforce(_gr_site, _lineaje_payload, content_type='text/plain'))
        await msg.stream_token(_lineaje_payload)
        for source in chunk.metadata.sources:
            if source.page_content not in saved_sources:
                saved_sources.add(source.page_content)
                saved_sources_complete.append(source)
                # LINEAJE: enforce() `source` at agent->log log_emit — scan flagged AI_DAT_SEC_029 (Enforce decision logging, audit trail, and forensic readiness for AI-driven actions.). Mask/block; do not remove without review. site_id='site:sha256:01afb9678aa0a77e776cbb68efa070c8591dd7b10e30033e36ccd9b944684605'
                _gr_client = _lineaje_load_gr_client()
                _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:01afb9678aa0a77e776cbb68efa070c8591dd7b10e30033e36ccd9b944684605', phase='log_emit', boundary={'source': 'log', 'sink': 'log'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_010', 'guardrail_id': 'Mask PII in Logs', 'policy_version': '2026.08.1'}], fail_mode='BLOCK', source_type='agent', destination_type='log')
                source = await __import__('asyncio').to_thread(lambda: _gr_client.enforce(_gr_site, source, content_type='application/json'))
                print(source)
                _lineaje_content = source.page_content
                # LINEAJE: enforce() `_lineaje_content` at agent->user_interface data_egress — scan flagged AI_DAT_SEC_023 (Redact PII from uploaded files.); AI_DAT_SEC_024 (Uploaded files must not contain PII (Singapore).); AI_DAT_SEC_029 (Enforce decision logging, audit trail, and forensic readiness for AI-driven actions.). Mask/block; do not remove without review. site_id='site:sha256:3c4555acb89d4e45efe9e0287975987e5c462f69f571a80f93e67d0d07f44eaa'
                _gr_client = _lineaje_load_gr_client()
                _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:3c4555acb89d4e45efe9e0287975987e5c462f69f571a80f93e67d0d07f44eaa', phase='data_egress', boundary={'source': 'agent_message', 'sink': 'user_interface'}, candidate_policies=[{'policy_id': 'AI_DAT_SEC_012', 'guardrail_id': 'Mask PII on UI', 'policy_version': '2026.08.1'}], fail_mode='BLOCK', source_type='agent', destination_type='user_interface')
                _lineaje_content = await __import__('asyncio').to_thread(lambda: _gr_client.enforce(_gr_site, _lineaje_content, content_type='text/plain'))
                elements.append(cl.Text(name=source.metadata["original_file_name"], content=_lineaje_content, display="side"))

    
    await msg.send()
    sources = ""
    for source in saved_sources_complete:
        sources += f"- {source.metadata['original_file_name']}\n"
    msg.elements = elements
    msg.content = msg.content + f"\n\nSources:\n{sources}"
    await msg.update()
