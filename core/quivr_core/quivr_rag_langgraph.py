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
from enum import Enum
from typing import Annotated, AsyncGenerator, Optional, Sequence, TypedDict
from uuid import uuid4

# TODO(@aminediro): this is the only dependency to langchain package, we should remove it
from langchain.retrievers import ContextualCompressionRetriever
from langchain_cohere import CohereRerank
from langchain_community.document_compressors import JinaRerank
from langchain_core.callbacks import Callbacks
from langchain_core.documents import BaseDocumentCompressor, Document
from langchain_core.messages import BaseMessage
from langchain_core.messages.ai import AIMessageChunk
from langchain_core.vectorstores import VectorStore
from langgraph.graph import END, START, StateGraph
from langgraph.graph.message import add_messages

from quivr_core.chat import ChatHistory
from quivr_core.config import DefaultRerankers, RetrievalConfig
from quivr_core.llm import LLMEndpoint
from quivr_core.models import (
    ParsedRAGChunkResponse,
    ParsedRAGResponse,
    QuivrKnowledge,
    RAGResponseMetadata,
    cited_answer,
)
from quivr_core.prompts import custom_prompts
from quivr_core.utils import (
    combine_documents,
    format_file_list,
    get_chunk_metadata,
    parse_chunk_response,
    parse_response,
)

logger = logging.getLogger("quivr_core")


class SpecialEdges(str, Enum):
    START = "START"
    END = "END"


class AgentState(TypedDict):
    # The add_messages function defines how an update should be processed
    # Default is to replace. add_messages says "append"
    messages: Annotated[Sequence[BaseMessage], add_messages]
    chat_history: ChatHistory
    docs: list[Document]
    files: str
    final_response: dict


class IdempotentCompressor(BaseDocumentCompressor):
    def compress_documents(
        self,
        documents: Sequence[Document],
        query: str,
        callbacks: Optional[Callbacks] = None,
    ) -> Sequence[Document]:
        """
        A no-op document compressor that simply returns the documents it is given.

        This is a placeholder until a more sophisticated document compression
        algorithm is implemented.
        """
        # LINEAJE: runtime guardrail checks `documents` as it flows from the agent to the user interface, before it leaves the application (in IdempotentCompressor.compress_documents).
        #   Detected: this statement moves data from the agent to the user interface with no runtime policy check (detection confidence: high).
        #   Decision: the Guardrail evaluates AI_DAT_SEC_012; sensitive values in `documents` are masked in place; a policy violation stops the call (fail_mode=BLOCK). If the Guardrail is unreachable, the call continues unchanged.
        #   Do not remove without review. site_id='site:sha256:101b3a5e650aff65f86e2ab90c23cb104a80c615c110a6e4780fe0d55a7ca5ae'
        _gr_client = _lineaje_load_gr_client()
        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:101b3a5e650aff65f86e2ab90c23cb104a80c615c110a6e4780fe0d55a7ca5ae', phase='data_egress', boundary={'source': 'agent_message', 'sink': 'user_interface'}, fail_mode='BLOCK', source_type='agent', destination_type='user_interface', components={'source': {'entity_type': 'agent', 'unique_org_id': 'vdna_NWg3gzBQkFkwoxLV', 'repository_uri': 'https://github.com/anaghatestuser/quivr', 'file_path': 'core/quivr_core/quivr_rag_langgraph.py', 'line': 71, 'name': 'QuivrQARAGLangGraph'}, 'invocation': {'file': 'core/quivr_core/quivr_rag_langgraph.py', 'line': 68, 'function': 'IdempotentCompressor.compress_documents'}, 'file': 'core/quivr_core/quivr_rag_langgraph.py', 'line': 68, 'function': 'compress_documents', 'agent_name': 'IdempotentCompressor', 'agent_name_source': 'inferred_from_class', 'not_on_graph': True})
        try:
            documents = _gr_client.enforce(_gr_site, documents, content_type='text/plain')
        except _gr_client.GuardrailUnavailableError:
            pass
        except PermissionError:
            pass
        return documents


class QuivrQARAGLangGraph:
    def __init__(
        self,
        *,
        retrieval_config: RetrievalConfig,
        llm: LLMEndpoint,
        vector_store: VectorStore | None = None,
        reranker: BaseDocumentCompressor | None = None,
    ):
        """
        Construct a QuivrQARAGLangGraph object.

        Args:
            retrieval_config (RetrievalConfig): The configuration for the RAG model.
            llm (LLMEndpoint): The LLM to use for generating text.
            vector_store (VectorStore): The vector store to use for storing and retrieving documents.
            reranker (BaseDocumentCompressor | None): The document compressor to use for re-ranking documents. Defaults to IdempotentCompressor if not provided.
        """
        self.retrieval_config = retrieval_config
        self.vector_store = vector_store
        self.llm_endpoint = llm

        self.graph = None

        if reranker is not None:
            self.reranker = reranker
        elif self.retrieval_config.reranker_config.supplier == DefaultRerankers.COHERE:
            self.reranker = CohereRerank(
                model=self.retrieval_config.reranker_config.model,
                top_n=self.retrieval_config.reranker_config.top_n,
                cohere_api_key=self.retrieval_config.reranker_config.api_key,
            )
        elif self.retrieval_config.reranker_config.supplier == DefaultRerankers.JINA:
            self.reranker = JinaRerank(
                model=self.retrieval_config.reranker_config.model,
                top_n=self.retrieval_config.reranker_config.top_n,
                jina_api_key=self.retrieval_config.reranker_config.api_key,
            )
        else:
            self.reranker = IdempotentCompressor()

        if self.vector_store:
            self.compression_retriever = ContextualCompressionRetriever(
                base_compressor=self.reranker, base_retriever=self.retriever
            )

    @property
    def retriever(self):
        """
        Returns a retriever that can retrieve documents from the vector store.

        Returns:
            VectorStoreRetriever: The retriever.
        """
        if self.vector_store:
            return self.vector_store.as_retriever()
        else:
            raise ValueError("No vector store provided")

    def filter_history(self, state: AgentState) -> dict:
        """
        Filter out the chat history to only include the messages that are relevant to the current question

        Takes in a chat_history= [HumanMessage(content='Qui est Chloé ? '),
        AIMessage(content="Chloé est une salariée travaillant pour l'entreprise Quivr en tant qu'AI Engineer,
        sous la direction de son supérieur hiérarchique, Stanislas Girard."),
        HumanMessage(content='Dis moi en plus sur elle'), AIMessage(content=''),
        HumanMessage(content='Dis moi en plus sur elle'),
        AIMessage(content="Désolé, je n'ai pas d'autres informations sur Chloé à partir des fichiers fournis.")]
        Returns a filtered chat_history with in priority: first max_tokens, then max_history where a Human message and an AI message count as one pair
        a token is 4 characters
        """
        chat_history = state["chat_history"]
        total_tokens = 0
        total_pairs = 0
        _chat_id = uuid4()
        _chat_history = ChatHistory(chat_id=_chat_id, brain_id=chat_history.brain_id)
        for human_message, ai_message in reversed(list(chat_history.iter_pairs())):
            # TODO: replace with tiktoken
            message_tokens = self.llm_endpoint.count_tokens(
                human_message.content
            ) + self.llm_endpoint.count_tokens(ai_message.content)
            if (
                total_tokens + message_tokens
                > self.retrieval_config.llm_config.max_output_tokens
                or total_pairs >= self.retrieval_config.max_history
            ):
                break
            _chat_history.append(human_message)
            _chat_history.append(ai_message)
            total_tokens += message_tokens
            total_pairs += 1

        return {"chat_history": _chat_history}

    ### Nodes
    def rewrite(self, state):
        """
        Transform the query to produce a better question.

        Args:
            state (messages): The current state

        Returns:
            dict: The updated state with re-phrased question
        """

        # Grader
        msg = custom_prompts.CONDENSE_QUESTION_PROMPT.format(
            chat_history=state["chat_history"],
            question=state["messages"][0].content,
        )

        try:
            _lineaje_obs = _lineaje_load_gr_client()
            _lineaje_obs_site = _lineaje_obs.SiteDescriptor(site_id='site:sha256:b5d91c838ff8901e4260a065dd5ee5f4f6ac7ed158e5fec74b0a41575103709e', phase='', boundary={}, fail_mode='ALLOW', source_type='agent', destination_type='llm', components={'file': 'core/quivr_core/quivr_rag_langgraph.py', 'line': 184, 'function': 'rewrite', 'agent_name': 'QuivrQARAGLangGraph', 'agent_name_source': 'inferred_from_class', 'source': {'entity_type': 'agent', 'file_path': 'core/quivr_core/quivr_rag_langgraph.py', 'line': 71, 'name': 'QuivrQARAGLangGraph', 'repository_uri': 'https://github.com/anaghatestuser/quivr', 'unique_org_id': 'vdna_NWg3gzBQkFkwoxLV'}, 'invocation': {'file': 'core/quivr_core/quivr_rag_langgraph.py', 'function': 'QuivrQARAGLangGraph.rewrite', 'line': 184}, 'destination': {'entity_type': 'llm', 'name': 'gpt-3.5-turbo-0613', 'provider': 'openai', 'version': ''}, 'boundary_id': 'bnd:060f48db90b3df41'}, observe_only=True)
            _lineaje_obs.enforce(_lineaje_obs_site, {'activity': 'agent_to_llm'}, content_type='application/json')
        except Exception as _lineaje_obs_err:
            [__import__('sys').__dict__.setdefault('_lineaje_gr_logged', set()).add(_k) or __import__('logging').getLogger('lineaje.guardrail').warning('Lineaje guardrail: an observe-only report failed (%s); later failures of this kind are not logged', _k[1]) for _k in [('observe', type(_lineaje_obs_err).__name__)] if _k not in __import__('sys').__dict__.setdefault('_lineaje_gr_logged', set())]
        model = self.llm_endpoint._llm
        # LINEAJE: runtime guardrail checks `msg` as it flows from the agent to the LLM, before it is sent to the model (in QuivrQARAGLangGraph.rewrite).
        #   Detected: this statement moves data from the agent to the LLM with no runtime policy check (detection confidence: medium).
        #   Decision: the Guardrail evaluates AI_AGENT_ACTIVITY_LOG, AI_APP_SEC_006, AI_APP_SEC_028, AI_APP_SEC_070 (+2 more); sensitive values in `msg` are masked in place; a policy violation stops the call (fail_mode=BLOCK). If the Guardrail is unreachable, the call continues unchanged.
        #   Do not remove without review. site_id='site:sha256:976af3d7a0f93954427c20194615346faa20b8f81fbbff15ca847950cbee8354'
        _lineaje_msg_evidence = {'msg': msg, 'model': getattr(_lineaje_load_gr_client(), 'current_model', lambda _f: '')(__file__)}
        _gr_client = _lineaje_load_gr_client()
        _lineaje_interaction_id = _gr_client.new_interaction_id()
        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:976af3d7a0f93954427c20194615346faa20b8f81fbbff15ca847950cbee8354', phase='pre_model', boundary={'source': 'agent_message', 'sink': 'model'}, fail_mode='BLOCK', source_type='agent', destination_type='llm', components={'source': {'entity_type': 'agent', 'file_path': 'core/quivr_core/quivr_rag_langgraph.py', 'line': 71, 'name': 'QuivrQARAGLangGraph', 'repository_uri': 'https://github.com/anaghatestuser/quivr', 'unique_org_id': 'vdna_NWg3gzBQkFkwoxLV'}, 'invocation': {'file': 'core/quivr_core/quivr_rag_langgraph.py', 'function': 'QuivrQARAGLangGraph.rewrite', 'line': 185}, 'destination': {'entity_type': 'llm', 'name': 'mistral-small', 'provider': 'mistral', 'version': ''}, 'file': 'core/quivr_core/quivr_rag_langgraph.py', 'line': 185, 'function': 'rewrite', 'agent_name': 'QuivrQARAGLangGraph', 'agent_name_source': 'inferred_from_class', 'boundary_id': 'bnd:7602f393b906fb06'}, interaction_id=_lineaje_interaction_id)
        try:
            _lineaje_msg_evidence = _gr_client.enforce(_gr_site, _lineaje_msg_evidence, content_type='application/json')
            msg = _lineaje_msg_evidence.get('msg', msg) if isinstance(_lineaje_msg_evidence, dict) else msg
        except _gr_client.GuardrailUnavailableError:
            pass
        except PermissionError:
            raise
        response = model.invoke(msg)
        # LINEAJE: runtime guardrail checks `response` as it flows from the LLM to the agent, after the model replies (in QuivrQARAGLangGraph.rewrite).
        #   Detected: this statement moves data from the LLM to the agent with no runtime policy check (detection confidence: medium).
        #   Decision: the Guardrail evaluates AI_DAT_SEC_011, AI_DAT_SEC_025, AI_DAT_SEC_027, AI_DAT_SEC_029; sensitive values in `response` are masked in place; a policy violation stops the call (fail_mode=BLOCK). If the Guardrail is unreachable, the call continues unchanged.
        #   Do not remove without review. site_id='site:sha256:917ce0c77a46a6d84b1ff7e4f00c24772c27151ea2bde64f027c81c82513203d'
        _gr_client = _lineaje_load_gr_client()
        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:917ce0c77a46a6d84b1ff7e4f00c24772c27151ea2bde64f027c81c82513203d', phase='post_model', boundary={'source': 'model', 'sink': 'agent_message'}, fail_mode='BLOCK', source_type='llm', destination_type='agent', components={'source': {'entity_type': 'agent', 'file_path': 'core/quivr_core/quivr_rag_langgraph.py', 'line': 71, 'name': 'QuivrQARAGLangGraph', 'repository_uri': 'https://github.com/anaghatestuser/quivr', 'unique_org_id': 'vdna_NWg3gzBQkFkwoxLV'}, 'invocation': {'file': 'core/quivr_core/quivr_rag_langgraph.py', 'function': 'QuivrQARAGLangGraph.rewrite', 'line': 185}, 'destination': {'entity_type': 'llm', 'name': 'rerank-multilingual-v3.0', 'provider': '', 'version': ''}, 'file': 'core/quivr_core/quivr_rag_langgraph.py', 'line': 185, 'function': 'rewrite', 'agent_name': 'QuivrQARAGLangGraph', 'agent_name_source': 'inferred_from_class', 'boundary_id': 'bnd:01e25f1bbd2fa7e5'}, interaction_id=locals().get('_lineaje_interaction_id'))
        try:
            response = _gr_client.enforce(_gr_site, response, content_type='application/json', variable_name='response', source_file=__file__, before_line=185)
        except _gr_client.GuardrailUnavailableError:
            pass
        return {"messages": [response]}

    def retrieve(self, state):
        """
        Retrieve relevent chunks

        Args:
            state (messages): The current state

        Returns:
            dict: The retrieved chunks
        """
        question = state["messages"][-1].content
        docs = self.compression_retriever.invoke(question)
        # LINEAJE: runtime guardrail checks `docs` as it flows from a vector store to the agent, after the tool returns (in QuivrQARAGLangGraph.retrieve).
        #   Detected: this statement moves data from a vector store to the agent with no runtime policy check (detection confidence: medium).
        #   Decision: the Guardrail evaluates the policies enabled for this boundary; sensitive values in `docs` are masked in place; a policy violation is logged and the call continues (fail_mode=ALLOW_WITH_AUDIT). If the Guardrail is unreachable, the call continues unchanged.
        #   Do not remove without review. site_id='site:sha256:b52e2b240d205cf4a52110a76221285b6991b830e182ac24214138b8a16bc18b'
        _gr_client = _lineaje_load_gr_client()
        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:b52e2b240d205cf4a52110a76221285b6991b830e182ac24214138b8a16bc18b', phase='post_tool', boundary={'source': 'vector_store', 'sink': 'agent_context'}, fail_mode='ALLOW_WITH_AUDIT', source_type='vector_store', destination_type='agent', components={'source': {'entity_type': 'agent', 'file_path': 'core/quivr_core/quivr_rag_langgraph.py', 'line': 71, 'name': 'QuivrQARAGLangGraph', 'repository_uri': 'https://github.com/anaghatestuser/quivr', 'unique_org_id': 'vdna_NWg3gzBQkFkwoxLV'}, 'invocation': {'file': 'core/quivr_core/quivr_rag_langgraph.py', 'function': 'QuivrQARAGLangGraph.retrieve', 'line': 199}, 'destination': {'entity_type': 'rag', 'file_path': 'core/quivr_core/brain/brain.py', 'line': 203, 'name': 'FAISS', 'repository_uri': 'https://github.com/anaghatestuser/quivr', 'unique_org_id': 'vdna_NWg3gzBQkFkwoxLV'}, 'file': 'core/quivr_core/quivr_rag_langgraph.py', 'line': 199, 'function': 'retrieve', 'agent_name': 'QuivrQARAGLangGraph', 'agent_name_source': 'inferred_from_class', 'boundary_id': 'bnd:d2cb5789b91af591'})
        try:
            docs = _gr_client.enforce(_gr_site, docs, content_type='application/json', variable_name='docs', source_file=__file__, before_line=199)
        except _gr_client.GuardrailUnavailableError:
            pass
        return {"docs": docs}

    def generate_rag(self, state):
        """
        Generate answer

        Args:
            state (messages): The current state

        Returns:
            dict: The updated state with re-phrased question
        """
        messages = state["messages"]
        user_question = messages[0].content
        files = state["files"]

        docs = state["docs"]

        # Prompt
        prompt = self.retrieval_config.prompt

        final_inputs = {}
        final_inputs["context"] = combine_documents(docs) if docs else "None"
        final_inputs["question"] = user_question
        final_inputs["custom_instructions"] = prompt if prompt else "None"
        final_inputs["files"] = files if files else "None"

        # LLM
        llm = self.llm_endpoint._llm
        if self.llm_endpoint.supports_func_calling():
            llm = self.llm_endpoint._llm.bind_tools(
                [cited_answer],
                tool_choice="any",
            )

        # Chain
        rag_chain = custom_prompts.RAG_ANSWER_PROMPT | llm

        # Run
        # LINEAJE: runtime guardrail checks `final_inputs` as it flows from the agent to the LLM, before it is sent to the model (in QuivrQARAGLangGraph.generate_rag).
        #   Detected: this statement moves data from the agent to the LLM with no runtime policy check (detection confidence: medium).
        #   Decision: the Guardrail evaluates AI_AGENT_ACTIVITY_LOG, AI_APP_SEC_006, AI_APP_SEC_028, AI_APP_SEC_070 (+2 more); sensitive values in `final_inputs` are masked in place; a policy violation stops the call (fail_mode=BLOCK). If the Guardrail is unreachable, the call continues unchanged.
        #   Do not remove without review. site_id='site:sha256:263a854a83d8bb6af9e1f2f1b47ab7226ec7cc4fbfb1c95c55804e22b947bbee'
        _lineaje_final_inputs_evidence = {'final_inputs': final_inputs, 'model': getattr(_lineaje_load_gr_client(), 'current_model', lambda _f: '')(__file__)}
        _gr_client = _lineaje_load_gr_client()
        _lineaje_interaction_id = _gr_client.new_interaction_id()
        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:263a854a83d8bb6af9e1f2f1b47ab7226ec7cc4fbfb1c95c55804e22b947bbee', phase='pre_model', boundary={'source': 'agent_message', 'sink': 'model'}, fail_mode='BLOCK', source_type='agent', destination_type='llm', components={'source': {'entity_type': 'agent', 'file_path': 'core/quivr_core/quivr_rag_langgraph.py', 'line': 71, 'name': 'QuivrQARAGLangGraph', 'repository_uri': 'https://github.com/anaghatestuser/quivr', 'unique_org_id': 'vdna_NWg3gzBQkFkwoxLV'}, 'invocation': {'file': 'core/quivr_core/quivr_rag_langgraph.py', 'function': 'QuivrQARAGLangGraph.generate_rag', 'line': 239}, 'destination': {'entity_type': 'llm', 'name': 'gpt-3.5-turbo', 'provider': 'openai', 'version': ''}, 'file': 'core/quivr_core/quivr_rag_langgraph.py', 'line': 239, 'function': 'generate_rag', 'agent_name': 'QuivrQARAGLangGraph', 'agent_name_source': 'inferred_from_class', 'boundary_id': 'bnd:c3962e84795768da'}, interaction_id=_lineaje_interaction_id)
        try:
            _lineaje_final_inputs_evidence = _gr_client.enforce(_gr_site, _lineaje_final_inputs_evidence, content_type='application/json')
            final_inputs = _lineaje_final_inputs_evidence.get('final_inputs', final_inputs) if isinstance(_lineaje_final_inputs_evidence, dict) else final_inputs
        except _gr_client.GuardrailUnavailableError:
            pass
        except PermissionError:
            raise
        response = rag_chain.invoke(final_inputs)
        # LINEAJE: runtime guardrail checks `response` as it flows from the LLM to the agent, after the model replies (in QuivrQARAGLangGraph.generate_rag).
        #   Detected: this statement moves data from the LLM to the agent with no runtime policy check (detection confidence: medium).
        #   Decision: the Guardrail evaluates AI_DAT_SEC_011, AI_DAT_SEC_025, AI_DAT_SEC_027, AI_DAT_SEC_029; sensitive values in `response` are masked in place; a policy violation stops the call (fail_mode=BLOCK). If the Guardrail is unreachable, the call continues unchanged.
        #   Do not remove without review. site_id='site:sha256:ac81a5f01e28bf77adb377f4a2ff7c5e5d28ca59a539510e22fb124646702319'
        _gr_client = _lineaje_load_gr_client()
        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:ac81a5f01e28bf77adb377f4a2ff7c5e5d28ca59a539510e22fb124646702319', phase='post_model', boundary={'source': 'model', 'sink': 'agent_message'}, fail_mode='BLOCK', source_type='llm', destination_type='agent', components={'source': {'entity_type': 'agent', 'unique_org_id': 'vdna_NWg3gzBQkFkwoxLV', 'repository_uri': 'https://github.com/anaghatestuser/quivr', 'file_path': 'core/quivr_core/quivr_rag_langgraph.py', 'line': 71, 'name': 'QuivrQARAGLangGraph'}, 'invocation': {'file': 'core/quivr_core/quivr_rag_langgraph.py', 'line': 239, 'function': 'QuivrQARAGLangGraph.generate_rag'}, 'file': 'core/quivr_core/quivr_rag_langgraph.py', 'line': 239, 'function': 'generate_rag', 'agent_name': 'QuivrQARAGLangGraph', 'agent_name_source': 'inferred_from_class', 'not_on_graph': True}, interaction_id=locals().get('_lineaje_interaction_id'))
        try:
            response = _gr_client.enforce(_gr_site, response, content_type='application/json', variable_name='response', source_file=__file__, before_line=239)
        except _gr_client.GuardrailUnavailableError:
            pass
        formatted_response = {
            "answer": response,  # Assuming the last message contains the final answer
            "docs": docs,
        }
        return {"messages": [response], "final_response": formatted_response}

    def generate_chat_llm(self, state):
        """
        Generate answer

        Args:
            state (messages): The current state

        Returns:
            dict: The updated state with re-phrased question
        """
        messages = state["messages"]
        user_question = messages[0].content

        # Prompt
        prompt = self.retrieval_config.prompt

        final_inputs = {}
        final_inputs["question"] = user_question
        final_inputs["custom_instructions"] = prompt if prompt else "None"
        final_inputs["chat_history"] = state["chat_history"].to_list()

        # LLM
        llm = self.llm_endpoint._llm

        # Chain
        rag_chain = custom_prompts.CHAT_LLM_PROMPT | llm

        # Run
        # LINEAJE: runtime guardrail checks `final_inputs` as it flows from the agent to the LLM, before it is sent to the model (in QuivrQARAGLangGraph.generate_chat_llm).
        #   Detected: this statement moves data from the agent to the LLM with no runtime policy check (detection confidence: medium).
        #   Decision: the Guardrail evaluates AI_AGENT_ACTIVITY_LOG, AI_APP_SEC_006, AI_APP_SEC_028, AI_APP_SEC_070 (+2 more); sensitive values in `final_inputs` are masked in place; a policy violation stops the call (fail_mode=BLOCK). If the Guardrail is unreachable, the call continues unchanged.
        #   Do not remove without review. site_id='site:sha256:33abc89f31ad81a983e2839ab27158773cdd68de110f669458030b4202f6344b'
        _lineaje_final_inputs_evidence = {'final_inputs': final_inputs, 'model': getattr(_lineaje_load_gr_client(), 'current_model', lambda _f: '')(__file__)}
        _gr_client = _lineaje_load_gr_client()
        _lineaje_interaction_id = _gr_client.new_interaction_id()
        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:33abc89f31ad81a983e2839ab27158773cdd68de110f669458030b4202f6344b', phase='pre_model', boundary={'source': 'agent_message', 'sink': 'model'}, fail_mode='BLOCK', source_type='agent', destination_type='llm', components={'source': {'entity_type': 'agent', 'unique_org_id': 'vdna_NWg3gzBQkFkwoxLV', 'repository_uri': 'https://github.com/anaghatestuser/quivr', 'file_path': 'core/quivr_core/quivr_rag_langgraph.py', 'line': 71, 'name': 'QuivrQARAGLangGraph'}, 'invocation': {'file': 'core/quivr_core/quivr_rag_langgraph.py', 'line': 274, 'function': 'QuivrQARAGLangGraph.generate_chat_llm'}, 'file': 'core/quivr_core/quivr_rag_langgraph.py', 'line': 274, 'function': 'generate_chat_llm', 'agent_name': 'QuivrQARAGLangGraph', 'agent_name_source': 'inferred_from_class', 'not_on_graph': True}, interaction_id=_lineaje_interaction_id)
        try:
            _lineaje_final_inputs_evidence = _gr_client.enforce(_gr_site, _lineaje_final_inputs_evidence, content_type='application/json')
            final_inputs = _lineaje_final_inputs_evidence.get('final_inputs', final_inputs) if isinstance(_lineaje_final_inputs_evidence, dict) else final_inputs
        except _gr_client.GuardrailUnavailableError:
            pass
        except PermissionError:
            raise
        response = rag_chain.invoke(final_inputs)
        # LINEAJE: runtime guardrail checks `response` as it flows from the LLM to the agent, after the model replies (in QuivrQARAGLangGraph.generate_chat_llm).
        #   Detected: this statement moves data from the LLM to the agent with no runtime policy check (detection confidence: medium).
        #   Decision: the Guardrail evaluates AI_DAT_SEC_011, AI_DAT_SEC_025, AI_DAT_SEC_027, AI_DAT_SEC_029; sensitive values in `response` are masked in place; a policy violation stops the call (fail_mode=BLOCK). If the Guardrail is unreachable, the call continues unchanged.
        #   Do not remove without review. site_id='site:sha256:a09e4de643fe14a3d0447ca78551f4ef67c0c8515589fda8973161a487d99949'
        _gr_client = _lineaje_load_gr_client()
        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:a09e4de643fe14a3d0447ca78551f4ef67c0c8515589fda8973161a487d99949', phase='post_model', boundary={'source': 'model', 'sink': 'agent_message'}, fail_mode='BLOCK', source_type='llm', destination_type='agent', components={'source': {'entity_type': 'agent', 'unique_org_id': 'vdna_NWg3gzBQkFkwoxLV', 'repository_uri': 'https://github.com/anaghatestuser/quivr', 'file_path': 'core/quivr_core/quivr_rag_langgraph.py', 'line': 71, 'name': 'QuivrQARAGLangGraph'}, 'invocation': {'file': 'core/quivr_core/quivr_rag_langgraph.py', 'line': 274, 'function': 'QuivrQARAGLangGraph.generate_chat_llm'}, 'file': 'core/quivr_core/quivr_rag_langgraph.py', 'line': 274, 'function': 'generate_chat_llm', 'agent_name': 'QuivrQARAGLangGraph', 'agent_name_source': 'inferred_from_class', 'not_on_graph': True}, interaction_id=locals().get('_lineaje_interaction_id'))
        try:
            response = _gr_client.enforce(_gr_site, response, content_type='application/json', variable_name='response', source_file=__file__, before_line=274)
        except _gr_client.GuardrailUnavailableError:
            pass
        formatted_response = {
            "answer": response,  # Assuming the last message contains the final answer
        }
        return {"messages": [response], "final_response": formatted_response}

    def build_chain(self):
        """
        Builds the langchain chain for the given configuration.

        Returns:
            Callable[[Dict], Dict]: The langchain chain.
        """
        if not self.graph:
            self.graph = self.create_graph()

        return self.graph

    def create_graph(self):
        """
        Builds the langchain chain for the given configuration.

        This function creates a state machine which takes a chat history and a question
        and produces an answer. The state machine consists of the following states:

        - filter_history: Filter the chat history (i.e., remove the last message)
        - rewrite: Re-write the question using the filtered history
        - retrieve: Retrieve documents related to the re-written question
        - generate: Generate an answer using the retrieved documents

        The state machine starts in the filter_history state and transitions as follows:
        filter_history -> rewrite -> retrieve -> generate -> END

        The final answer is returned as a dictionary with the answer and the list of documents
        used to generate the answer.

        Returns:
            Callable[[Dict], Dict]: The langchain chain.
        """
        workflow = StateGraph(AgentState)

        if self.retrieval_config.workflow_config:
            if SpecialEdges.START not in [
                node.name for node in self.retrieval_config.workflow_config.nodes
            ]:
                raise ValueError("The workflow should contain a 'START' node")
            for node in self.retrieval_config.workflow_config.nodes:
                if node.name not in SpecialEdges._value2member_map_:
                    workflow.add_node(node.name, getattr(self, node.name))

            for node in self.retrieval_config.workflow_config.nodes:
                for edge in node.edges:
                    if node.name == SpecialEdges.START:
                        workflow.add_edge(START, edge)
                    elif edge == SpecialEdges.END:
                        workflow.add_edge(node.name, END)
                    else:
                        workflow.add_edge(node.name, edge)
        else:
            # Define the nodes we will cycle between
            workflow.add_node("filter_history", self.filter_history)
            workflow.add_node("rewrite", self.rewrite)  # Re-writing the question
            workflow.add_node("retrieve", self.retrieve)  # retrieval
            workflow.add_node("generate", self.generate_rag)

            # Add node for filtering history

            workflow.set_entry_point("filter_history")
            workflow.add_edge("filter_history", "rewrite")
            workflow.add_edge("rewrite", "retrieve")
            workflow.add_edge("retrieve", "generate")
            workflow.add_edge(
                "generate", END
            )  # Add edge from generate to format_response

        # Compile
        graph = workflow.compile()
        # LINEAJE: runtime guardrail checks `graph` as it flows from the agent to the user interface, before it leaves the application (in QuivrQARAGLangGraph.create_graph).
        #   Detected: this statement moves data from the agent to the user interface with no runtime policy check (detection confidence: high).
        #   Decision: the Guardrail evaluates AI_DAT_SEC_012; sensitive values in `graph` are masked in place; a policy violation stops the call (fail_mode=BLOCK). If the Guardrail is unreachable, the call continues unchanged.
        #   Do not remove without review. site_id='site:sha256:c3071522f9d2de3a783da448bfa70b46121cd1410d00b1a820fb941d444c13df'
        _gr_client = _lineaje_load_gr_client()
        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:c3071522f9d2de3a783da448bfa70b46121cd1410d00b1a820fb941d444c13df', phase='data_egress', boundary={'source': 'agent_message', 'sink': 'user_interface'}, fail_mode='BLOCK', source_type='agent', destination_type='user_interface', components={'source': {'entity_type': 'agent', 'unique_org_id': 'vdna_NWg3gzBQkFkwoxLV', 'repository_uri': 'https://github.com/anaghatestuser/quivr', 'file_path': 'core/quivr_core/quivr_rag_langgraph.py', 'line': 71, 'name': 'QuivrQARAGLangGraph'}, 'invocation': {'file': 'core/quivr_core/quivr_rag_langgraph.py', 'line': 351, 'function': 'QuivrQARAGLangGraph.create_graph'}, 'file': 'core/quivr_core/quivr_rag_langgraph.py', 'line': 351, 'function': 'create_graph', 'agent_name': 'QuivrQARAGLangGraph', 'agent_name_source': 'inferred_from_class', 'not_on_graph': True})
        try:
            graph = _gr_client.enforce(_gr_site, graph, content_type='text/plain')
        except _gr_client.GuardrailUnavailableError:
            pass
        except PermissionError:
            pass
        return graph

    def answer(
        self,
        question: str,
        history: ChatHistory,
        list_files: list[QuivrKnowledge],
        metadata: dict[str, str] = {},
    ) -> ParsedRAGResponse:
        """
        Answer a question using the langgraph chain.

        Args:
            question (str): The question to answer.
            history (ChatHistory): The chat history to use for context.
            list_files (list[QuivrKnowledge]): The list of files to use for retrieval.
            metadata (dict[str, str], optional): The metadata to pass to the langchain invocation. Defaults to {}.

        Returns:
            ParsedRAGResponse: The answer to the question.
        """
        concat_list_files = format_file_list(
            list_files, self.retrieval_config.max_files
        )
        conversational_qa_chain = self.build_chain()
        inputs = {
            "messages": [
                ("user", question),
            ],
            "chat_history": history,
            "files": concat_list_files,
        }
        # LINEAJE: runtime guardrail checks `inputs` as it flows from the agent to the LLM, before it is sent to the model (in QuivrQARAGLangGraph.answer).
        #   Detected: this statement moves data from the agent to the LLM with no runtime policy check (detection confidence: medium).
        #   Decision: the Guardrail evaluates AI_AGENT_ACTIVITY_LOG, AI_APP_SEC_006, AI_APP_SEC_028, AI_APP_SEC_070 (+2 more); sensitive values in `inputs` are masked in place; a policy violation stops the call (fail_mode=BLOCK). If the Guardrail is unreachable, the call continues unchanged.
        #   Do not remove without review. site_id='site:sha256:63cfafbd3725b75e16651f4e5b53e218a0ff7fced2c018fe6544e54c0c39b421'
        _gr_client = _lineaje_load_gr_client()
        _lineaje_interaction_id = _gr_client.new_interaction_id()
        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:63cfafbd3725b75e16651f4e5b53e218a0ff7fced2c018fe6544e54c0c39b421', phase='pre_model', boundary={'source': 'agent_message', 'sink': 'model'}, fail_mode='BLOCK', source_type='agent', destination_type='llm', components={'source': {'entity_type': 'agent', 'unique_org_id': 'vdna_NWg3gzBQkFkwoxLV', 'repository_uri': 'https://github.com/anaghatestuser/quivr', 'file_path': 'core/quivr_core/quivr_rag_langgraph.py', 'line': 71, 'name': 'QuivrQARAGLangGraph'}, 'invocation': {'file': 'core/quivr_core/quivr_rag_langgraph.py', 'line': 383, 'function': 'QuivrQARAGLangGraph.answer'}, 'file': 'core/quivr_core/quivr_rag_langgraph.py', 'line': 383, 'function': 'answer', 'agent_name': 'QuivrQARAGLangGraph', 'agent_name_source': 'inferred_from_class', 'not_on_graph': True}, interaction_id=_lineaje_interaction_id)
        try:
            inputs = _gr_client.enforce(_gr_site, inputs, content_type='application/json', variable_name='inputs', source_file=__file__, before_line=383)
        except _gr_client.GuardrailUnavailableError:
            pass
        except PermissionError:
            raise
        raw_llm_response = conversational_qa_chain.invoke(
            inputs,
            config={"metadata": metadata},
        )
        # LINEAJE: runtime guardrail checks `raw_llm_response` as it flows from the LLM to the agent, after the model replies (in QuivrQARAGLangGraph.answer).
        #   Detected: this statement moves data from the LLM to the agent with no runtime policy check (detection confidence: medium).
        #   Decision: the Guardrail evaluates AI_DAT_SEC_011, AI_DAT_SEC_025, AI_DAT_SEC_027, AI_DAT_SEC_029; sensitive values in `raw_llm_response` are masked in place; a policy violation stops the call (fail_mode=BLOCK). If the Guardrail is unreachable, the call continues unchanged.
        #   Do not remove without review. site_id='site:sha256:8cc4cb4df6b7520de6bcde9fc310615e91a0fba8013e67c44664929d36ea581d'
        _gr_client = _lineaje_load_gr_client()
        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:8cc4cb4df6b7520de6bcde9fc310615e91a0fba8013e67c44664929d36ea581d', phase='post_model', boundary={'source': 'model', 'sink': 'agent_message'}, fail_mode='BLOCK', source_type='llm', destination_type='agent', components={'source': {'entity_type': 'agent', 'unique_org_id': 'vdna_NWg3gzBQkFkwoxLV', 'repository_uri': 'https://github.com/anaghatestuser/quivr', 'file_path': 'core/quivr_core/quivr_rag_langgraph.py', 'line': 71, 'name': 'QuivrQARAGLangGraph'}, 'invocation': {'file': 'core/quivr_core/quivr_rag_langgraph.py', 'line': 383, 'function': 'QuivrQARAGLangGraph.answer'}, 'file': 'core/quivr_core/quivr_rag_langgraph.py', 'line': 383, 'function': 'answer', 'agent_name': 'QuivrQARAGLangGraph', 'agent_name_source': 'inferred_from_class', 'not_on_graph': True}, interaction_id=locals().get('_lineaje_interaction_id'))
        try:
            raw_llm_response = _gr_client.enforce(_gr_site, raw_llm_response, content_type='application/json', variable_name='raw_llm_response', source_file=__file__, before_line=383)
        except _gr_client.GuardrailUnavailableError:
            pass
        response = parse_response(
            raw_llm_response["final_response"], self.retrieval_config.llm_config.model
        )
        # LINEAJE: runtime guardrail checks `response` as it flows from the agent to the user interface, before it leaves the application (in QuivrQARAGLangGraph.answer).
        #   Detected: this statement moves data from the agent to the user interface with no runtime policy check (detection confidence: high).
        #   Decision: the Guardrail evaluates AI_DAT_SEC_012; sensitive values in `response` are masked in place; a policy violation stops the call (fail_mode=BLOCK). If the Guardrail is unreachable, the call continues unchanged.
        #   Do not remove without review. site_id='site:sha256:6a95725fd6f3e20b4eeb389c0d16e49504b3584d1d70700ff3022245fc50c018'
        _gr_client = _lineaje_load_gr_client()
        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:6a95725fd6f3e20b4eeb389c0d16e49504b3584d1d70700ff3022245fc50c018', phase='data_egress', boundary={'source': 'agent_message', 'sink': 'user_interface'}, fail_mode='BLOCK', source_type='agent', destination_type='user_interface', components={'source': {'entity_type': 'agent', 'unique_org_id': 'vdna_NWg3gzBQkFkwoxLV', 'repository_uri': 'https://github.com/anaghatestuser/quivr', 'file_path': 'core/quivr_core/quivr_rag_langgraph.py', 'line': 71, 'name': 'QuivrQARAGLangGraph'}, 'invocation': {'file': 'core/quivr_core/quivr_rag_langgraph.py', 'line': 390, 'function': 'QuivrQARAGLangGraph.answer'}, 'file': 'core/quivr_core/quivr_rag_langgraph.py', 'line': 390, 'function': 'answer', 'agent_name': 'QuivrQARAGLangGraph', 'agent_name_source': 'inferred_from_class', 'not_on_graph': True})
        try:
            response = _gr_client.enforce(_gr_site, response, content_type='text/plain')
        except _gr_client.GuardrailUnavailableError:
            pass
        except PermissionError:
            pass
        return response

    async def answer_astream(
        self,
        question: str,
        history: ChatHistory,
        list_files: list[QuivrKnowledge],
        metadata: dict[str, str] = {},
    ) -> AsyncGenerator[ParsedRAGChunkResponse, ParsedRAGChunkResponse]:
        """
        Answer a question using the langgraph chain and yield each chunk of the answer separately.

        Args:
            question (str): The question to answer.
            history (ChatHistory): The chat history to use for context.
            list_files (list[QuivrKnowledge]): The list of files to use for retrieval.
            metadata (dict[str, str], optional): The metadata to pass to the langchain invocation. Defaults to {}.

        Yields:
            ParsedRAGChunkResponse: Each chunk of the answer.
        """
        concat_list_files = format_file_list(
            list_files, self.retrieval_config.max_files
        )
        conversational_qa_chain = self.build_chain()

        rolling_message = AIMessageChunk(content="")
        sources: list[Document] | None = None
        prev_answer = ""
        chunk_id = 0

        try:
            _lineaje_obs = _lineaje_load_gr_client()
            _lineaje_obs_site = _lineaje_obs.SiteDescriptor(site_id='site:sha256:d986572bef0d654d6b09a567fa1ca56ea8b7948c32309842f4c4535d5cee062f', phase='', boundary={}, fail_mode='ALLOW', source_type='agent', destination_type='llm', components={'file': 'core/quivr_core/quivr_rag_langgraph.py', 'line': 421, 'function': 'answer_astream', 'agent_name': 'QuivrQARAGLangGraph', 'agent_name_source': 'inferred_from_class', 'call_target': 'conversational_qa_chain.astream_events', 'not_on_graph': True}, observe_only=True)
            await _lineaje_obs.aenforce(_lineaje_obs_site, {'activity': 'agent_to_llm'}, content_type='application/json')
        except Exception as _lineaje_obs_err:
            [__import__('sys').__dict__.setdefault('_lineaje_gr_logged', set()).add(_k) or __import__('logging').getLogger('lineaje.guardrail').warning('Lineaje guardrail: an observe-only report failed (%s); later failures of this kind are not logged', _k[1]) for _k in [('observe', type(_lineaje_obs_err).__name__)] if _k not in __import__('sys').__dict__.setdefault('_lineaje_gr_logged', set())]
        async for event in conversational_qa_chain.astream_events(
            {
                "messages": [
                    ("user", question),
                ],
                "chat_history": history,
                "files": concat_list_files,
            },
            version="v1",
            config={"metadata": metadata},
        ):
            kind = event["event"]
            if (
                not sources
                and "output" in event["data"]
                and "docs" in event["data"]["output"]
            ):
                sources = event["data"]["output"]["docs"]

            if (
                kind == "on_chat_model_stream"
                and "generate" in event["metadata"]["langgraph_node"]
            ):
                chunk = event["data"]["chunk"]
                rolling_message, answer_str = parse_chunk_response(
                    rolling_message,
                    chunk,
                    self.llm_endpoint.supports_func_calling(),
                )
                if len(answer_str) > 0:
                    if (
                        self.llm_endpoint.supports_func_calling()
                        and rolling_message.tool_calls
                    ):
                        diff_answer = answer_str[len(prev_answer) :]
                        if len(diff_answer) > 0:
                            parsed_chunk = ParsedRAGChunkResponse(
                                answer=diff_answer,
                                metadata=RAGResponseMetadata(),
                            )
                            prev_answer += diff_answer

                            _lineaje_payload = f"answer_astream func_calling=True question={question} rolling_msg={rolling_message} chunk_id={chunk_id}, chunk={parsed_chunk}"
                            # LINEAJE: runtime guardrail checks `_lineaje_payload` as it flows from the agent to the application log, before it is written to the log (in QuivrQARAGLangGraph.answer_astream).
                            #   Detected: this statement moves data from the agent to the application log with no runtime policy check (detection confidence: high).
                            #   Decision: the Guardrail evaluates AI_DAT_SEC_010; sensitive values in `_lineaje_payload` are masked in place; a policy violation stops the call (fail_mode=BLOCK). If the Guardrail is unreachable, the call continues unchanged.
                            #   Do not remove without review. site_id='site:sha256:74f2900f7276762aae842c8f235301747c2da28b24c7a3722a49d6cdd6dc50d1'
                            _gr_client = _lineaje_load_gr_client()
                            _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:74f2900f7276762aae842c8f235301747c2da28b24c7a3722a49d6cdd6dc50d1', phase='log_emit', boundary={'source': 'log', 'sink': 'log'}, fail_mode='BLOCK', source_type='agent', destination_type='log', components={'source': {'entity_type': 'agent', 'unique_org_id': 'vdna_NWg3gzBQkFkwoxLV', 'repository_uri': 'https://github.com/anaghatestuser/quivr', 'file_path': 'core/quivr_core/quivr_rag_langgraph.py', 'line': 71, 'name': 'QuivrQARAGLangGraph'}, 'invocation': {'file': 'core/quivr_core/quivr_rag_langgraph.py', 'line': 463, 'function': 'QuivrQARAGLangGraph.answer_astream'}, 'file': 'core/quivr_core/quivr_rag_langgraph.py', 'line': 463, 'function': 'answer_astream', 'agent_name': 'QuivrQARAGLangGraph', 'agent_name_source': 'inferred_from_class', 'not_on_graph': True})
                            try:
                                if not __import__('builtins').hasattr(_gr_client, 'aenforce'):
                                    __import__("logging").getLogger("lineaje.gr_client").error("gr_stub_client.py predates aenforce (STUB_API 5): this site is NOT enforced; replace gr_stub_client.py with the current companion")
                                    raise _gr_client.GuardrailUnavailableError("stale gr_stub_client.py: no aenforce")
                                _lineaje_payload = await _gr_client.aenforce(_gr_site, _lineaje_payload, content_type='application/json')
                            except _gr_client.GuardrailUnavailableError:
                                pass
                            except PermissionError:
                                pass
                            logger.debug(
                                _lineaje_payload
                            )
                            yield parsed_chunk
                    else:
                        parsed_chunk = ParsedRAGChunkResponse(
                            answer=answer_str,
                            metadata=RAGResponseMetadata(),
                        )
                        _lineaje_payload = f"answer_astream func_calling=False question={question} rolling_msg={rolling_message} chunk_id={chunk_id}, chunk={parsed_chunk}"
                        # LINEAJE: runtime guardrail checks `_lineaje_payload` as it flows from the agent to the application log, before it is written to the log (in QuivrQARAGLangGraph.answer_astream).
                        #   Detected: this statement moves data from the agent to the application log with no runtime policy check (detection confidence: high).
                        #   Decision: the Guardrail evaluates AI_DAT_SEC_010; sensitive values in `_lineaje_payload` are masked in place; a policy violation stops the call (fail_mode=BLOCK). If the Guardrail is unreachable, the call continues unchanged.
                        #   Do not remove without review. site_id='site:sha256:6e2cf09262fbb989c3c16229a72d218fdfbd38ba3401440ce621011086ce288f'
                        _gr_client = _lineaje_load_gr_client()
                        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:6e2cf09262fbb989c3c16229a72d218fdfbd38ba3401440ce621011086ce288f', phase='log_emit', boundary={'source': 'log', 'sink': 'log'}, fail_mode='BLOCK', source_type='agent', destination_type='log', components={'source': {'entity_type': 'agent', 'unique_org_id': 'vdna_NWg3gzBQkFkwoxLV', 'repository_uri': 'https://github.com/anaghatestuser/quivr', 'file_path': 'core/quivr_core/quivr_rag_langgraph.py', 'line': 71, 'name': 'QuivrQARAGLangGraph'}, 'invocation': {'file': 'core/quivr_core/quivr_rag_langgraph.py', 'line': 472, 'function': 'QuivrQARAGLangGraph.answer_astream'}, 'file': 'core/quivr_core/quivr_rag_langgraph.py', 'line': 472, 'function': 'answer_astream', 'agent_name': 'QuivrQARAGLangGraph', 'agent_name_source': 'inferred_from_class', 'not_on_graph': True})
                        try:
                            if not __import__('builtins').hasattr(_gr_client, 'aenforce'):
                                __import__("logging").getLogger("lineaje.gr_client").error("gr_stub_client.py predates aenforce (STUB_API 5): this site is NOT enforced; replace gr_stub_client.py with the current companion")
                                raise _gr_client.GuardrailUnavailableError("stale gr_stub_client.py: no aenforce")
                            _lineaje_payload = await _gr_client.aenforce(_gr_site, _lineaje_payload, content_type='application/json')
                        except _gr_client.GuardrailUnavailableError:
                            pass
                        except PermissionError:
                            pass
                        logger.debug(
                            _lineaje_payload
                        )
                        yield parsed_chunk

                    chunk_id += 1

        # Last chunk provides metadata
        last_chunk = ParsedRAGChunkResponse(
            answer="",
            metadata=get_chunk_metadata(rolling_message, sources),
            last_chunk=True,
        )
        _lineaje_payload = f"answer_astream last_chunk={last_chunk} question={question} rolling_msg={rolling_message} chunk_id={chunk_id}"
        # LINEAJE: runtime guardrail checks `_lineaje_payload` as it flows from the agent to the application log, before it is written to the log (in QuivrQARAGLangGraph.answer_astream).
        #   Detected: this statement moves data from the agent to the application log with no runtime policy check (detection confidence: high).
        #   Decision: the Guardrail evaluates AI_DAT_SEC_010; sensitive values in `_lineaje_payload` are masked in place; a policy violation stops the call (fail_mode=BLOCK). If the Guardrail is unreachable, the call continues unchanged.
        #   Do not remove without review. site_id='site:sha256:4686471cbc05d304a839162bd5350127e35fcdb3bda7b85e0853d21a3cf5cd7d'
        _gr_client = _lineaje_load_gr_client()
        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:4686471cbc05d304a839162bd5350127e35fcdb3bda7b85e0853d21a3cf5cd7d', phase='log_emit', boundary={'source': 'log', 'sink': 'log'}, fail_mode='BLOCK', source_type='agent', destination_type='log', components={'source': {'entity_type': 'agent', 'unique_org_id': 'vdna_NWg3gzBQkFkwoxLV', 'repository_uri': 'https://github.com/anaghatestuser/quivr', 'file_path': 'core/quivr_core/quivr_rag_langgraph.py', 'line': 71, 'name': 'QuivrQARAGLangGraph'}, 'invocation': {'file': 'core/quivr_core/quivr_rag_langgraph.py', 'line': 485, 'function': 'QuivrQARAGLangGraph.answer_astream'}, 'file': 'core/quivr_core/quivr_rag_langgraph.py', 'line': 485, 'function': 'answer_astream', 'agent_name': 'QuivrQARAGLangGraph', 'agent_name_source': 'inferred_from_class', 'not_on_graph': True})
        try:
            if not __import__('builtins').hasattr(_gr_client, 'aenforce'):
                __import__("logging").getLogger("lineaje.gr_client").error("gr_stub_client.py predates aenforce (STUB_API 5): this site is NOT enforced; replace gr_stub_client.py with the current companion")
                raise _gr_client.GuardrailUnavailableError("stale gr_stub_client.py: no aenforce")
            _lineaje_payload = await _gr_client.aenforce(_gr_site, _lineaje_payload, content_type='application/json')
        except _gr_client.GuardrailUnavailableError:
            pass
        except PermissionError:
            pass
        logger.debug(
            _lineaje_payload
        )
        yield last_chunk
