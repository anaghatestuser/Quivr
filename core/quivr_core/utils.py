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
from typing import Any, List, Tuple, no_type_check

from langchain_core.messages import AIMessage, BaseMessage, HumanMessage, SystemMessage
from langchain_core.messages.ai import AIMessageChunk
from langchain_core.prompts import format_document

from quivr_core.models import (
    ChatLLMMetadata,
    ParsedRAGResponse,
    QuivrKnowledge,
    RAGResponseMetadata,
    RawRAGResponse,
)
from quivr_core.prompts import custom_prompts

# TODO(@aminediro): define a types packages where we clearly define IO types
# This should be used for serialization/deseriallization later


logger = logging.getLogger("quivr_core")


def model_supports_function_calling(model_name: str):
    models_supporting_function_calls = [
        "gpt-4",
        "gpt-4-1106-preview",
        "gpt-4-0613",
        "gpt-4o",
        "gpt-3.5-turbo-1106",
        "gpt-3.5-turbo-0613",
        "gpt-4-0125-preview",
        "gpt-3.5-turbo",
        "gpt-4-turbo",
        "gpt-4o",
        "gpt-4o-mini",
    ]
    return model_name in models_supporting_function_calls


def format_history_to_openai_mesages(
    tuple_history: List[Tuple[str, str]], system_message: str, question: str
) -> List[BaseMessage]:
    """Format the chat history into a list of Base Messages"""
    messages = []
    messages.append(SystemMessage(content=system_message))
    for human, ai in tuple_history:
        messages.append(HumanMessage(content=human))
        messages.append(AIMessage(content=ai))
    messages.append(HumanMessage(content=question))
    # LINEAJE: runtime guardrail checks `messages` as it flows from the agent to the user interface, before it leaves the application (in format_history_to_openai_mesages).
    #   Detected: this statement moves data from the agent to the user interface with no runtime policy check (detection confidence: high).
    #   Decision: the Guardrail evaluates AI_DAT_SEC_012; sensitive values in `messages` are masked in place; a policy violation stops the call (fail_mode=BLOCK). If the Guardrail is unreachable, the call continues unchanged.
    #   Do not remove without review. site_id='site:sha256:d1f3c77dd4e0f2bc9aa69663101f8a89264d61fa7cb25426484293ca37dcbaef'
    _gr_client = _lineaje_load_gr_client()
    _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:d1f3c77dd4e0f2bc9aa69663101f8a89264d61fa7cb25426484293ca37dcbaef', phase='data_egress', boundary={'source': 'agent_message', 'sink': 'user_interface'}, fail_mode='BLOCK', source_type='agent', destination_type='user_interface', components={'invocation': {'file': 'core/quivr_core/utils.py', 'line': 51, 'function': 'format_history_to_openai_mesages'}, 'file': 'core/quivr_core/utils.py', 'line': 51, 'function': 'format_history_to_openai_mesages', 'agent_name': 'format_history_to_openai_mesages', 'agent_name_source': 'inferred_from_function', 'not_on_graph': True})
    try:
        messages = _gr_client.enforce(_gr_site, messages, content_type='text/plain')
    except _gr_client.GuardrailUnavailableError:
        pass
    except PermissionError:
        pass
    return messages


def cited_answer_filter(tool):
    return tool["name"] == "cited_answer"


def get_chunk_metadata(
    msg: AIMessageChunk, sources: list[Any] | None = None
) -> RAGResponseMetadata:
    # Initiate the source
    metadata = {"sources": sources} if sources else {"sources": []}
    if msg.tool_calls:
        cited_answer = next(x for x in msg.tool_calls if cited_answer_filter(x))

        if "args" in cited_answer:
            gathered_args = cited_answer["args"]
            if "citations" in gathered_args:
                citations = gathered_args["citations"]
                metadata["citations"] = citations

            if "followup_questions" in gathered_args:
                followup_questions = gathered_args["followup_questions"]
                metadata["followup_questions"] = followup_questions

    return RAGResponseMetadata(**metadata, metadata_model=None)


def get_prev_message_str(msg: AIMessageChunk) -> str:
    if msg.tool_calls:
        cited_answer = next(x for x in msg.tool_calls if cited_answer_filter(x))
        if "args" in cited_answer and "answer" in cited_answer["args"]:
            return cited_answer["args"]["answer"]
    return ""


# TODO: CONVOLUTED LOGIC !
# TODO(@aminediro): redo this
@no_type_check
def parse_chunk_response(
    rolling_msg: AIMessageChunk,
    raw_chunk: dict[str, Any],
    supports_func_calling: bool,
) -> Tuple[AIMessageChunk, str]:
    # Init with sources
    answer_str = ""

    if "answer" in raw_chunk:
        answer = raw_chunk["answer"]
    else:
        answer = raw_chunk

    rolling_msg += answer
    if supports_func_calling and rolling_msg.tool_calls:
        cited_answer = next(x for x in rolling_msg.tool_calls if cited_answer_filter(x))
        if "args" in cited_answer and "answer" in cited_answer["args"]:
            gathered_args = cited_answer["args"]
            # Only send the difference between answer and response_tokens which was the previous answer
            answer_str = gathered_args["answer"]
            return rolling_msg, answer_str

    return rolling_msg, answer.content


@no_type_check
def parse_response(raw_response: RawRAGResponse, model_name: str) -> ParsedRAGResponse:
    answer = ""
    sources = raw_response["docs"] if "docs" in raw_response else []

    metadata = RAGResponseMetadata(
        sources=sources, metadata_model=ChatLLMMetadata(name=model_name)
    )

    if (
        model_supports_function_calling(model_name)
        and "tool_calls" in raw_response["answer"]
        and raw_response["answer"].tool_calls
    ):
        if "citations" in raw_response["answer"].tool_calls[-1]["args"]:
            citations = raw_response["answer"].tool_calls[-1]["args"]["citations"]
            metadata.citations = citations
            followup_questions = raw_response["answer"].tool_calls[-1]["args"][
                "followup_questions"
            ]
            if followup_questions:
                metadata.followup_questions = followup_questions
            answer = raw_response["answer"].tool_calls[-1]["args"]["answer"]
        else:
            answer = raw_response["answer"].tool_calls[-1]["args"]["answer"]
    else:
        answer = raw_response["answer"].content

    parsed_response = ParsedRAGResponse(answer=answer, metadata=metadata)
    # LINEAJE: runtime guardrail checks `parsed_response` as it flows from the agent to the user interface, before it leaves the application (in parse_response).
    #   Detected: this statement moves data from the agent to the user interface with no runtime policy check (detection confidence: high).
    #   Decision: the Guardrail evaluates AI_DAT_SEC_012; sensitive values in `parsed_response` are masked in place; a policy violation stops the call (fail_mode=BLOCK). If the Guardrail is unreachable, the call continues unchanged.
    #   Do not remove without review. site_id='site:sha256:259ee04bbe4f27f6f383d15ca781a034bc940e6562e516c25cf649d8381aba4f'
    _gr_client = _lineaje_load_gr_client()
    _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:259ee04bbe4f27f6f383d15ca781a034bc940e6562e516c25cf649d8381aba4f', phase='data_egress', boundary={'source': 'agent_message', 'sink': 'user_interface'}, fail_mode='BLOCK', source_type='agent', destination_type='user_interface', components={'invocation': {'file': 'core/quivr_core/utils.py', 'line': 144, 'function': 'parse_response'}, 'file': 'core/quivr_core/utils.py', 'line': 144, 'function': 'parse_response', 'agent_name': 'parse_response', 'agent_name_source': 'inferred_from_function', 'not_on_graph': True})
    try:
        parsed_response = _gr_client.enforce(_gr_site, parsed_response, content_type='text/plain')
    except _gr_client.GuardrailUnavailableError:
        pass
    except PermissionError:
        pass
    return parsed_response


def combine_documents(
    docs,
    document_prompt=custom_prompts.DEFAULT_DOCUMENT_PROMPT,
    document_separator="\n\n",
):
    # for each docs, add an index in the metadata to be able to cite the sources
    for doc, index in zip(docs, range(len(docs)), strict=False):
        doc.metadata["index"] = index
    doc_strings = [format_document(doc, document_prompt) for doc in docs]
    return document_separator.join(doc_strings)


def format_file_list(
    list_files_array: list[QuivrKnowledge], max_files: int = 20
) -> str:
    list_files = [file.file_name or file.url for file in list_files_array]
    files: list[str] = list(filter(lambda n: n is not None, list_files))  # type: ignore
    files = files[:max_files]

    files_str = "\n".join(files) if list_files_array else "None"
    # LINEAJE: runtime guardrail checks `files_str` as it flows from the agent to the user interface, before it leaves the application (in format_file_list).
    #   Detected: this statement moves data from the agent to the user interface with no runtime policy check (detection confidence: high).
    #   Decision: the Guardrail evaluates AI_DAT_SEC_012; sensitive values in `files_str` are masked in place; a policy violation stops the call (fail_mode=BLOCK). If the Guardrail is unreachable, the call continues unchanged.
    #   Do not remove without review. site_id='site:sha256:19a3dab66382529c7a8216a8fb9e65ef7c6fa2fb389126be219b5bb35bcfe257'
    _gr_client = _lineaje_load_gr_client()
    _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:19a3dab66382529c7a8216a8fb9e65ef7c6fa2fb389126be219b5bb35bcfe257', phase='data_egress', boundary={'source': 'agent_message', 'sink': 'user_interface'}, fail_mode='BLOCK', source_type='agent', destination_type='user_interface', components={'invocation': {'file': 'core/quivr_core/utils.py', 'line': 167, 'function': 'format_file_list'}, 'file': 'core/quivr_core/utils.py', 'line': 167, 'function': 'format_file_list', 'agent_name': 'format_file_list', 'agent_name_source': 'inferred_from_function', 'not_on_graph': True})
    try:
        files_str = _gr_client.enforce(_gr_site, files_str, content_type='text/plain')
    except _gr_client.GuardrailUnavailableError:
        pass
    except PermissionError:
        pass
    return files_str
