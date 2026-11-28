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
import logging
import os
from pathlib import Path
from pprint import PrettyPrinter
from typing import Any, AsyncGenerator, Callable, Dict, Self, Type, Union
from uuid import UUID, uuid4

from langchain_core.documents import Document
from langchain_core.embeddings import Embeddings
from langchain_core.messages import AIMessage, HumanMessage
from langchain_core.vectorstores import VectorStore
from langchain_openai import OpenAIEmbeddings
from rich.console import Console
from rich.panel import Panel

from quivr_core.brain.info import BrainInfo, ChatHistoryInfo
from quivr_core.brain.serialization import (
    BrainSerialized,
    EmbedderConfig,
    FAISSConfig,
    LocalStorageConfig,
    TransparentStorageConfig,
)
from quivr_core.chat import ChatHistory
from quivr_core.config import RetrievalConfig
from quivr_core.files.file import load_qfile
from quivr_core.llm import LLMEndpoint
from quivr_core.models import (
    ParsedRAGChunkResponse,
    ParsedRAGResponse,
    QuivrKnowledge,
    SearchResult,
)
from quivr_core.processor.registry import get_processor_class
from quivr_core.quivr_rag import QuivrQARAG
from quivr_core.quivr_rag_langgraph import QuivrQARAGLangGraph
from quivr_core.storage.local_storage import LocalStorage, TransparentStorage
from quivr_core.storage.storage_base import StorageBase

from .brain_defaults import build_default_vectordb, default_embedder, default_llm

logger = logging.getLogger("quivr_core")


async def process_files(
    storage: StorageBase, skip_file_error: bool, **processor_kwargs: dict[str, Any]
) -> list[Document]:
    """
    Process files in storage.
    This function takes a StorageBase and return a list of langchain documents.

    Args:
        storage (StorageBase): The storage containing the files to process.
        skip_file_error (bool): Whether to skip files that cannot be processed.
        processor_kwargs (dict[str, Any]): Additional arguments for the processor.

    Returns:
        list[Document]: List of processed documents in the Langchain Document format.

    Raises:
        ValueError: If a file cannot be processed and skip_file_error is False.
        Exception: If no processor is found for a file of a specific type and skip_file_error is False.

    """

    knowledge = []
    for file in await storage.get_files():
        try:
            if file.file_extension:
                processor_cls = get_processor_class(file.file_extension)
                _lineaje_payload = f"processing {file} using class {processor_cls.__name__}"
                # LINEAJE: runtime guardrail checks `_lineaje_payload` as it flows from the agent to the application log, before it is written to the log (in process_files).
                #   Detected: this statement moves data from the agent to the application log with no runtime policy check (detection confidence: high).
                #   Decision: the Guardrail evaluates AI_DAT_SEC_010; sensitive values in `_lineaje_payload` are masked in place; a policy violation stops the call (fail_mode=BLOCK). If the Guardrail is unreachable, the call continues unchanged.
                #   Do not remove without review. site_id='site:sha256:f2691307f34833bb0a19cc007a6ae256946125c32bbecde051672c42abd5483f'
                _gr_client = _lineaje_load_gr_client()
                _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:f2691307f34833bb0a19cc007a6ae256946125c32bbecde051672c42abd5483f', phase='log_emit', boundary={'source': 'log', 'sink': 'log'}, fail_mode='BLOCK', source_type='agent', destination_type='log', components={'invocation': {'file': 'core/quivr_core/brain/brain.py', 'line': 72, 'function': 'process_files'}, 'file': 'core/quivr_core/brain/brain.py', 'line': 72, 'function': 'process_files', 'agent_name': 'process_files', 'agent_name_source': 'inferred_from_function', 'not_on_graph': True})
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
                processor = processor_cls(**processor_kwargs)
                docs = await processor.process_file(file)
                knowledge.extend(docs)
            else:
                _lineaje_payload = f"can't find processor for {file}"
                # LINEAJE: runtime guardrail checks `_lineaje_payload` as it flows from the agent to the application log, before it is written to the log (in process_files).
                #   Detected: this statement moves data from the agent to the application log with no runtime policy check (detection confidence: high).
                #   Decision: the Guardrail evaluates AI_DAT_SEC_010; sensitive values in `_lineaje_payload` are masked in place; a policy violation stops the call (fail_mode=BLOCK). If the Guardrail is unreachable, the call continues unchanged.
                #   Do not remove without review. site_id='site:sha256:29d7a3e92f2def825dfd36011afa5f09d9b2c0a5cec8e364ded2bd062b644ac8'
                _gr_client = _lineaje_load_gr_client()
                _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:29d7a3e92f2def825dfd36011afa5f09d9b2c0a5cec8e364ded2bd062b644ac8', phase='log_emit', boundary={'source': 'log', 'sink': 'log'}, fail_mode='BLOCK', source_type='agent', destination_type='log', components={'invocation': {'file': 'core/quivr_core/brain/brain.py', 'line': 77, 'function': 'process_files'}, 'file': 'core/quivr_core/brain/brain.py', 'line': 77, 'function': 'process_files', 'agent_name': 'process_files', 'agent_name_source': 'inferred_from_function', 'not_on_graph': True})
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
                if skip_file_error:
                    continue
                else:
                    raise ValueError(f"can't parse {file}. can't find file extension")
        except KeyError as e:
            if skip_file_error:
                continue
            else:
                raise Exception(f"Can't parse {file}. No available processor") from e

    # LINEAJE: runtime guardrail checks `knowledge` as it flows from the agent to the user interface, before it leaves the application (in process_files).
    #   Detected: this statement moves data from the agent to the user interface with no runtime policy check (detection confidence: high).
    #   Decision: the Guardrail evaluates AI_DAT_SEC_012; sensitive values in `knowledge` are masked in place; a policy violation stops the call (fail_mode=BLOCK). If the Guardrail is unreachable, the call continues unchanged.
    #   Do not remove without review. site_id='site:sha256:f1f7dc277ae27ca95a324dd6853d1b8b4448161abf5fa588f627119f2235244e'
    _gr_client = _lineaje_load_gr_client()
    _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:f1f7dc277ae27ca95a324dd6853d1b8b4448161abf5fa588f627119f2235244e', phase='data_egress', boundary={'source': 'agent_message', 'sink': 'user_interface'}, fail_mode='BLOCK', source_type='agent', destination_type='user_interface', components={'invocation': {'file': 'core/quivr_core/brain/brain.py', 'line': 88, 'function': 'process_files'}, 'file': 'core/quivr_core/brain/brain.py', 'line': 88, 'function': 'process_files', 'agent_name': 'process_files', 'agent_name_source': 'inferred_from_function', 'not_on_graph': True})
    try:
        if not __import__('builtins').hasattr(_gr_client, 'aenforce'):
            __import__("logging").getLogger("lineaje.gr_client").error("gr_stub_client.py predates aenforce (STUB_API 5): this site is NOT enforced; replace gr_stub_client.py with the current companion")
            raise _gr_client.GuardrailUnavailableError("stale gr_stub_client.py: no aenforce")
        knowledge = await _gr_client.aenforce(_gr_site, knowledge, content_type='text/plain')
    except _gr_client.GuardrailUnavailableError:
        pass
    except PermissionError:
        pass
    return knowledge


class Brain:
    """
    A class representing a Brain.

    This class allows for the creation of a Brain, which is a collection of knowledge one wants to retrieve information from.

    A Brain is set to:

    * Store files in the storage of your choice (local, S3, etc.)
    * Process the files in the storage to extract text and metadata in a wide range of format.
    * Store the processed files in the vector store of your choice (FAISS, PGVector, etc.) - default to FAISS.
    * Create an index of the processed files.
    * Use the *Quivr* workflow for the retrieval augmented generation.

    A Brain is able to:

    * Search for information in the vector store.
    * Answer questions about the knowledges in the Brain.
    * Stream the answer to the question.

    Attributes:
        name (str): The name of the brain.
        id (UUID): The unique identifier of the brain.
        storage (StorageBase): The storage used to store the files.
        llm (LLMEndpoint): The language model used to generate the answer.
        vector_db (VectorStore): The vector store used to store the processed files.
        embedder (Embeddings): The embeddings used to create the index of the processed files.


    """

    def __init__(
        self,
        *,
        name: str,
        id: UUID,
        llm: LLMEndpoint,
        vector_db: VectorStore | None = None,
        embedder: Embeddings | None = None,
        storage: StorageBase | None = None,
    ):
        self.id = id
        self.name = name
        self.storage = storage

        # Chat history
        self._chats = self._init_chats()
        self.default_chat = list(self._chats.values())[0]

        # RAG dependencies:
        self.llm = llm
        self.vector_db = vector_db
        self.embedder = embedder

    def __repr__(self) -> str:
        pp = PrettyPrinter(width=80, depth=None, compact=False, sort_dicts=False)
        return pp.pformat(self.info())

    def print_info(self):
        console = Console()
        tree = self.info().to_tree()
        panel = Panel(tree, title="Brain Info", expand=False, border_style="bold")
        # LINEAJE: runtime guardrail checks `panel` as it flows from the agent to the application log, before it is written to the log (in Brain.print_info).
        #   Detected: this statement moves data from the agent to the application log with no runtime policy check (detection confidence: high).
        #   Decision: the Guardrail evaluates AI_DAT_SEC_010; sensitive values in `panel` are masked in place; a policy violation stops the call (fail_mode=BLOCK). If the Guardrail is unreachable, the call continues unchanged.
        #   Do not remove without review. site_id='site:sha256:845dd4959d03f2dce6585f53bef1241c8924547cacb9d53a311946e2b662a2c3'
        _gr_client = _lineaje_load_gr_client()
        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:845dd4959d03f2dce6585f53bef1241c8924547cacb9d53a311946e2b662a2c3', phase='log_emit', boundary={'source': 'log', 'sink': 'log'}, fail_mode='BLOCK', source_type='agent', destination_type='log', components={'invocation': {'file': 'core/quivr_core/brain/brain.py', 'line': 153, 'function': 'Brain.print_info'}, 'file': 'core/quivr_core/brain/brain.py', 'line': 153, 'function': 'print_info', 'agent_name': 'Brain', 'agent_name_source': 'inferred_from_class', 'not_on_graph': True})
        try:
            panel = _gr_client.enforce(_gr_site, panel, content_type='application/json')
        except _gr_client.GuardrailUnavailableError:
            pass
        except PermissionError:
            pass
        console.print(panel)

    @classmethod
    def load(cls, folder_path: str | Path) -> Self:
        """
        Load a brain from a folder path.

        Args:
            folder_path (str | Path): The path to the folder containing the brain.

        Returns:
            Brain: The brain loaded from the folder path.

        Example:
        ```python
        brain_loaded = Brain.load("path/to/brain")
        brain_loaded.print_info()
        ```

        """
        if isinstance(folder_path, str):
            folder_path = Path(folder_path)
        if not folder_path.exists():
            raise ValueError(f"path {folder_path} doesn't exist")

        # Load brainserialized
        with open(os.path.join(folder_path, "config.json"), "r") as f:
            bserialized = BrainSerialized.model_validate_json(f.read())

        storage: StorageBase | None = None
        # Loading storage
        if bserialized.storage_config.storage_type == "transparent_storage":
            storage = TransparentStorage.load(bserialized.storage_config)
        elif bserialized.storage_config.storage_type == "local_storage":
            storage = LocalStorage.load(bserialized.storage_config)
        else:
            raise ValueError("unknown storage")

        # Load Embedder
        if bserialized.embedding_config.embedder_type == "openai_embedding":
            from langchain_openai import OpenAIEmbeddings

            embedder = OpenAIEmbeddings(**bserialized.embedding_config.config)
        else:
            raise ValueError("unknown embedder")

        # Load vector db
        if bserialized.vectordb_config.vectordb_type == "faiss":
            from langchain_community.vectorstores import FAISS

            vector_db = FAISS.load_local(
                folder_path=bserialized.vectordb_config.vectordb_folder_path,
                embeddings=embedder,
                allow_dangerous_deserialization=True,
            )
        else:
            raise ValueError("Unsupported vectordb")

        return cls(
            id=bserialized.id,
            name=bserialized.name,
            embedder=embedder,
            llm=LLMEndpoint.from_config(bserialized.llm_config),
            storage=storage,
            vector_db=vector_db,
        )

    async def save(self, folder_path: str | Path) -> str:
        """
        Save the brain to a folder path.

        Args:
            folder_path (str | Path): The path to the folder where the brain will be saved.

        Returns:
            str: The path to the folder where the brain was saved.

        Example:
        ```python
        await brain.save("path/to/brain")
        ```
        """
        if isinstance(folder_path, str):
            folder_path = Path(folder_path)

        brain_path = os.path.join(folder_path, f"brain_{self.id}")
        os.makedirs(brain_path, exist_ok=True)

        from langchain_community.vectorstores import FAISS

        if isinstance(self.vector_db, FAISS):
            vectordb_path = os.path.join(brain_path, "vector_store")
            os.makedirs(vectordb_path, exist_ok=True)
            self.vector_db.save_local(folder_path=vectordb_path)
            vector_store = FAISSConfig(vectordb_folder_path=vectordb_path)
        else:
            raise Exception("can't serialize other vector stores for now")

        if isinstance(self.embedder, OpenAIEmbeddings):
            embedder_config = EmbedderConfig(
                config=self.embedder.dict(exclude={"openai_api_key"})
            )
        else:
            raise Exception("can't serialize embedder other than openai for now")

        storage_config: Union[LocalStorageConfig, TransparentStorageConfig]
        # TODO : each instance should know how to serialize/deserialize itself
        if isinstance(self.storage, LocalStorage):
            serialized_files = {
                f.id: f.serialize() for f in await self.storage.get_files()
            }
            storage_config = LocalStorageConfig(
                storage_path=self.storage.dir_path, files=serialized_files
            )
        elif isinstance(self.storage, TransparentStorage):
            serialized_files = {
                f.id: f.serialize() for f in await self.storage.get_files()
            }
            storage_config = TransparentStorageConfig(files=serialized_files)
        else:
            raise Exception("can't serialize storage. not supported for now")

        bserialized = BrainSerialized(
            id=self.id,
            name=self.name,
            chat_history=self.chat_history.get_chat_history(),
            llm_config=self.llm.get_config(),
            vectordb_config=vector_store,
            embedding_config=embedder_config,
            storage_config=storage_config,
        )

        with open(os.path.join(brain_path, "config.json"), "w") as f:
            _lineaje_payload = bserialized.model_dump_json()
            # LINEAJE: runtime guardrail checks `_lineaje_payload` as it flows from the agent to a file, before it is written to disk (in Brain.save).
            #   Detected: this statement moves data from the agent to a file with no runtime policy check (detection confidence: high).
            #   Decision: the Guardrail evaluates AI_DAT_SEC_025; sensitive values in `_lineaje_payload` are masked in place; a policy violation stops the call (fail_mode=BLOCK). If the Guardrail is unreachable, the call continues unchanged.
            #   Do not remove without review. site_id='site:sha256:87683b6b1a4f0a293731b39b2ae0867b1f05c57cda01349be83c9eb41189b5a8'
            _gr_client = _lineaje_load_gr_client()
            _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:87683b6b1a4f0a293731b39b2ae0867b1f05c57cda01349be83c9eb41189b5a8', phase='file_write', boundary={'source': 'agent_message', 'sink': 'file_content'}, fail_mode='BLOCK', source_type='agent', destination_type='file', components={'invocation': {'file': 'core/quivr_core/brain/brain.py', 'line': 286, 'function': 'Brain.save'}, 'file': 'core/quivr_core/brain/brain.py', 'line': 286, 'function': 'save', 'agent_name': 'Brain', 'agent_name_source': 'inferred_from_class', 'not_on_graph': True})
            try:
                if not __import__('builtins').hasattr(_gr_client, 'aenforce'):
                    __import__("logging").getLogger("lineaje.gr_client").error("gr_stub_client.py predates aenforce (STUB_API 5): this site is NOT enforced; replace gr_stub_client.py with the current companion")
                    raise _gr_client.GuardrailUnavailableError("stale gr_stub_client.py: no aenforce")
                _lineaje_payload = await _gr_client.aenforce(_gr_site, _lineaje_payload, content_type='application/json', variable_name='_lineaje_payload', source_file=__file__, before_line=286)
            except _gr_client.GuardrailUnavailableError:
                pass
            f.write(_lineaje_payload)
        # LINEAJE: runtime guardrail checks `brain_path` as it flows from the agent to the user interface, before it leaves the application (in Brain.save).
        #   Detected: this statement moves data from the agent to the user interface with no runtime policy check (detection confidence: high).
        #   Decision: the Guardrail evaluates AI_DAT_SEC_012; sensitive values in `brain_path` are masked in place; a policy violation stops the call (fail_mode=BLOCK). If the Guardrail is unreachable, the call continues unchanged.
        #   Do not remove without review. site_id='site:sha256:9164ca246d5e66e207c4f47febb7a28670e505a1420b76f4d13cd69eb5e5c882'
        _gr_client = _lineaje_load_gr_client()
        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:9164ca246d5e66e207c4f47febb7a28670e505a1420b76f4d13cd69eb5e5c882', phase='data_egress', boundary={'source': 'agent_message', 'sink': 'user_interface'}, fail_mode='BLOCK', source_type='agent', destination_type='user_interface', components={'invocation': {'file': 'core/quivr_core/brain/brain.py', 'line': 287, 'function': 'Brain.save'}, 'file': 'core/quivr_core/brain/brain.py', 'line': 287, 'function': 'save', 'agent_name': 'Brain', 'agent_name_source': 'inferred_from_class', 'not_on_graph': True})
        try:
            if not __import__('builtins').hasattr(_gr_client, 'aenforce'):
                __import__("logging").getLogger("lineaje.gr_client").error("gr_stub_client.py predates aenforce (STUB_API 5): this site is NOT enforced; replace gr_stub_client.py with the current companion")
                raise _gr_client.GuardrailUnavailableError("stale gr_stub_client.py: no aenforce")
            brain_path = await _gr_client.aenforce(_gr_site, brain_path, content_type='text/plain')
        except _gr_client.GuardrailUnavailableError:
            pass
        except PermissionError:
            pass
        return brain_path

    def info(self) -> BrainInfo:
        # TODO: dim of embedding
        # "embedder": {},
        chats_info = ChatHistoryInfo(
            nb_chats=len(self._chats),
            current_default_chat=self.default_chat.id,
            current_chat_history_length=len(self.default_chat),
        )

        return BrainInfo(
            brain_id=self.id,
            brain_name=self.name,
            files_info=self.storage.info() if self.storage else None,
            chats_info=chats_info,
            llm_info=self.llm.info(),
        )

    @property
    def chat_history(self) -> ChatHistory:
        return self.default_chat

    def _init_chats(self) -> Dict[UUID, ChatHistory]:
        chat_id = uuid4()
        default_chat = ChatHistory(chat_id=chat_id, brain_id=self.id)
        return {chat_id: default_chat}

    @classmethod
    async def afrom_files(
        cls,
        *,
        name: str,
        file_paths: list[str | Path],
        vector_db: VectorStore | None = None,
        storage: StorageBase = TransparentStorage(),
        llm: LLMEndpoint | None = None,
        embedder: Embeddings | None = None,
        skip_file_error: bool = False,
        processor_kwargs: dict[str, Any] | None = None,
    ) -> Self:
        """
        Create a brain from a list of file paths.

        Args:
            name (str): The name of the brain.
            file_paths (list[str | Path]): The list of file paths to add to the brain.
            vector_db (VectorStore | None): The vector store used to store the processed files.
            storage (StorageBase): The storage used to store the files.
            llm (LLMEndpoint | None): The language model used to generate the answer.
            embedder (Embeddings | None): The embeddings used to create the index of the processed files.
            skip_file_error (bool): Whether to skip files that cannot be processed.
            processor_kwargs (dict[str, Any] | None): Additional arguments for the processor.

        Returns:
            Brain: The brain created from the file paths.

        Example:
        ```python
        brain = await Brain.afrom_files(name="My Brain", file_paths=["file1.pdf", "file2.pdf"])
        brain.print_info()
        ```
        """
        if llm is None:
            llm = default_llm()

        if embedder is None:
            embedder = default_embedder()

        processor_kwargs = processor_kwargs or {}

        brain_id = uuid4()

        # TODO: run in parallel using tasks

        for path in file_paths:
            file = await load_qfile(brain_id, path)
            await storage.upload_file(file)

        _lineaje_payload = f"uploaded all files to {storage}"
        # LINEAJE: runtime guardrail checks `_lineaje_payload` as it flows from the agent to the application log, before it is written to the log (in Brain.afrom_files).
        #   Detected: this statement moves data from the agent to the application log with no runtime policy check (detection confidence: high).
        #   Decision: the Guardrail evaluates AI_DAT_SEC_010; sensitive values in `_lineaje_payload` are masked in place; a policy violation stops the call (fail_mode=BLOCK). If the Guardrail is unreachable, the call continues unchanged.
        #   Do not remove without review. site_id='site:sha256:9e8c4ba7bfa74eb2a9279c72bd250bc8f92b86675b4f77898639b31fd41553b6'
        _gr_client = _lineaje_load_gr_client()
        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:9e8c4ba7bfa74eb2a9279c72bd250bc8f92b86675b4f77898639b31fd41553b6', phase='log_emit', boundary={'source': 'log', 'sink': 'log'}, fail_mode='BLOCK', source_type='agent', destination_type='log', components={'invocation': {'file': 'core/quivr_core/brain/brain.py', 'line': 366, 'function': 'Brain.afrom_files'}, 'file': 'core/quivr_core/brain/brain.py', 'line': 366, 'function': 'afrom_files', 'agent_name': 'Brain', 'agent_name_source': 'inferred_from_class', 'not_on_graph': True})
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

        # Parse files
        docs = await process_files(
            storage=storage,
            skip_file_error=skip_file_error,
            **processor_kwargs,
        )

        # Building brain's vectordb
        if vector_db is None:
            vector_db = await build_default_vectordb(docs, embedder)
        else:
            # LINEAJE: runtime guardrail checks `docs` as it flows from the RAG pipeline to a vector store, before the tool runs (in Brain.afrom_files).
            #   Detected: this statement moves data from the RAG pipeline to a vector store with no runtime policy check (detection confidence: high).
            #   Decision: the Guardrail evaluates the policies enabled for this boundary; sensitive values in `docs` are masked in place; a policy violation is logged and the call continues (fail_mode=ALLOW_WITH_AUDIT). If the Guardrail is unreachable, the call continues unchanged.
            #   Do not remove without review. site_id='site:sha256:c347c4d0b54401dcea07e39c22ee26350edcb1cd17d20b5810fc494a18bef3e4'
            _gr_client = _lineaje_load_gr_client()
            _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:c347c4d0b54401dcea07e39c22ee26350edcb1cd17d20b5810fc494a18bef3e4', phase='pre_tool', boundary={'source': 'rag_pipeline', 'sink': 'vector_store'}, fail_mode='ALLOW_WITH_AUDIT', source_type='rag_pipeline', destination_type='vector_store', components={'invocation': {'file': 'core/quivr_core/brain/brain.py', 'line': 379, 'function': 'Brain.afrom_files'}, 'file': 'core/quivr_core/brain/brain.py', 'line': 379, 'function': 'afrom_files', 'agent_name': 'Brain', 'agent_name_source': 'inferred_from_class', 'not_on_graph': True})
            try:
                if not __import__('builtins').hasattr(_gr_client, 'aenforce'):
                    __import__("logging").getLogger("lineaje.gr_client").error("gr_stub_client.py predates aenforce (STUB_API 5): this site is NOT enforced; replace gr_stub_client.py with the current companion")
                    raise _gr_client.GuardrailUnavailableError("stale gr_stub_client.py: no aenforce")
                docs = await _gr_client.aenforce(_gr_site, docs, content_type='application/json', variable_name='docs', source_file=__file__, before_line=379)
            except _gr_client.GuardrailUnavailableError:
                pass
            await vector_db.aadd_documents(docs)

        _lineaje_payload = f"added {len(docs)} chunks to vectordb"
        # LINEAJE: runtime guardrail checks `_lineaje_payload` as it flows from the agent to the application log, before it is written to the log (in Brain.afrom_files).
        #   Detected: this statement moves data from the agent to the application log with no runtime policy check (detection confidence: high).
        #   Decision: the Guardrail evaluates AI_DAT_SEC_010; sensitive values in `_lineaje_payload` are masked in place; a policy violation stops the call (fail_mode=BLOCK). If the Guardrail is unreachable, the call continues unchanged.
        #   Do not remove without review. site_id='site:sha256:9ec5307255e0f9ad9284be09a004d251b1bd9de36a21d89589b2dbdee4b82a66'
        _gr_client = _lineaje_load_gr_client()
        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:9ec5307255e0f9ad9284be09a004d251b1bd9de36a21d89589b2dbdee4b82a66', phase='log_emit', boundary={'source': 'log', 'sink': 'log'}, fail_mode='BLOCK', source_type='agent', destination_type='log', components={'invocation': {'file': 'core/quivr_core/brain/brain.py', 'line': 381, 'function': 'Brain.afrom_files'}, 'file': 'core/quivr_core/brain/brain.py', 'line': 381, 'function': 'afrom_files', 'agent_name': 'Brain', 'agent_name_source': 'inferred_from_class', 'not_on_graph': True})
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

        return cls(
            id=brain_id,
            name=name,
            storage=storage,
            llm=llm,
            embedder=embedder,
            vector_db=vector_db,
        )

    @classmethod
    def from_files(
        cls,
        *,
        name: str,
        file_paths: list[str | Path],
        vector_db: VectorStore | None = None,
        storage: StorageBase = TransparentStorage(),
        llm: LLMEndpoint | None = None,
        embedder: Embeddings | None = None,
        skip_file_error: bool = False,
        processor_kwargs: dict[str, Any] | None = None,
    ) -> Self:
        loop = asyncio.get_event_loop()
        return loop.run_until_complete(
            cls.afrom_files(
                name=name,
                file_paths=file_paths,
                vector_db=vector_db,
                storage=storage,
                llm=llm,
                embedder=embedder,
                skip_file_error=skip_file_error,
                processor_kwargs=processor_kwargs,
            )
        )

    @classmethod
    async def afrom_langchain_documents(
        cls,
        *,
        name: str,
        langchain_documents: list[Document],
        vector_db: VectorStore | None = None,
        storage: StorageBase = TransparentStorage(),
        llm: LLMEndpoint | None = None,
        embedder: Embeddings | None = None,
    ) -> Self:
        """
        Create a brain from a list of langchain documents.

        Args:
            name (str): The name of the brain.
            langchain_documents (list[Document]): The list of langchain documents to add to the brain.
            vector_db (VectorStore | None): The vector store used to store the processed files.
            storage (StorageBase): The storage used to store the files.
            llm (LLMEndpoint | None): The language model used to generate the answer.
            embedder (Embeddings | None): The embeddings used to create the index of the processed files.

        Returns:
            Brain: The brain created from the langchain documents.

        Example:
        ```python
        from langchain_core.documents import Document
        documents = [Document(page_content="Hello, world!")]
        brain = await Brain.afrom_langchain_documents(name="My Brain", langchain_documents=documents)
        brain.print_info()
        ```
        """
        if llm is None:
            llm = default_llm()

        if embedder is None:
            embedder = default_embedder()

        brain_id = uuid4()

        # Building brain's vectordb
        if vector_db is None:
            vector_db = await build_default_vectordb(langchain_documents, embedder)
        else:
            # LINEAJE: runtime guardrail checks `langchain_documents` as it flows from the RAG pipeline to a vector store, before the tool runs (in Brain.afrom_langchain_documents).
            #   Detected: this statement moves data from the RAG pipeline to a vector store with no runtime policy check (detection confidence: high).
            #   Decision: the Guardrail evaluates the policies enabled for this boundary; sensitive values in `langchain_documents` are masked in place; a policy violation is logged and the call continues (fail_mode=ALLOW_WITH_AUDIT). If the Guardrail is unreachable, the call continues unchanged.
            #   Do not remove without review. site_id='site:sha256:7a7bf7778338d99d7a547dc5bc5e9dde5c34db2ade774c8a7140a17f12455d7d'
            _gr_client = _lineaje_load_gr_client()
            _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:7a7bf7778338d99d7a547dc5bc5e9dde5c34db2ade774c8a7140a17f12455d7d', phase='pre_tool', boundary={'source': 'rag_pipeline', 'sink': 'vector_store'}, fail_mode='ALLOW_WITH_AUDIT', source_type='rag_pipeline', destination_type='vector_store', components={'invocation': {'file': 'core/quivr_core/brain/brain.py', 'line': 464, 'function': 'Brain.afrom_langchain_documents'}, 'file': 'core/quivr_core/brain/brain.py', 'line': 464, 'function': 'afrom_langchain_documents', 'agent_name': 'Brain', 'agent_name_source': 'inferred_from_class', 'not_on_graph': True})
            try:
                if not __import__('builtins').hasattr(_gr_client, 'aenforce'):
                    __import__("logging").getLogger("lineaje.gr_client").error("gr_stub_client.py predates aenforce (STUB_API 5): this site is NOT enforced; replace gr_stub_client.py with the current companion")
                    raise _gr_client.GuardrailUnavailableError("stale gr_stub_client.py: no aenforce")
                langchain_documents = await _gr_client.aenforce(_gr_site, langchain_documents, content_type='application/json', variable_name='langchain_documents', source_file=__file__, before_line=464)
            except _gr_client.GuardrailUnavailableError:
                pass
            await vector_db.aadd_documents(langchain_documents)

        return cls(
            id=brain_id,
            name=name,
            storage=storage,
            llm=llm,
            embedder=embedder,
            vector_db=vector_db,
        )

    async def asearch(
        self,
        query: str | Document,
        n_results: int = 5,
        filter: Callable | Dict[str, Any] | None = None,
        fetch_n_neighbors: int = 20,
    ) -> list[SearchResult]:
        """
        Search for relevant documents in the brain based on a query.

        Args:
            query (str | Document): The query to search for.
            n_results (int): The number of results to return.
            filter (Callable | Dict[str, Any] | None): The filter to apply to the search.
            fetch_n_neighbors (int): The number of neighbors to fetch.

        Returns:
            list[SearchResult]: The list of retrieved chunks.

        Example:
        ```python
        brain = Brain.from_files(name="My Brain", file_paths=["file1.pdf", "file2.pdf"])
        results = await brain.asearch("Why everybody loves Quivr?")
        for result in results:
            print(result.chunk.page_content)
        ```
        """
        if not self.vector_db:
            raise ValueError("No vector db configured for this brain")

        result = await self.vector_db.asimilarity_search_with_score(
            query, k=n_results, filter=filter, fetch_k=fetch_n_neighbors
        )
        # LINEAJE: runtime guardrail checks `result` as it flows from a vector store to the agent, after the tool returns (in Brain.asearch).
        #   Detected: this statement moves data from a vector store to the agent with no runtime policy check (detection confidence: high).
        #   Decision: the Guardrail evaluates the policies enabled for this boundary; sensitive values in `result` are masked in place; a policy violation is logged and the call continues (fail_mode=ALLOW_WITH_AUDIT). If the Guardrail is unreachable, the call continues unchanged.
        #   Do not remove without review. site_id='site:sha256:ae1aad6c610e718a7c20228ab14682be985a534ec571c9b4650fda8030408618'
        _gr_client = _lineaje_load_gr_client()
        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:ae1aad6c610e718a7c20228ab14682be985a534ec571c9b4650fda8030408618', phase='post_tool', boundary={'source': 'vector_store', 'sink': 'agent_context'}, fail_mode='ALLOW_WITH_AUDIT', source_type='vector_store', destination_type='agent', components={'destination': {'entity_type': 'rag', 'unique_org_id': 'vdna_bZcmCGXlYYCbRBtl', 'repository_uri': 'https://github.com/anaghatestuser/quivr', 'file_path': 'core/quivr_core/brain/brain.py', 'line': 203, 'name': 'FAISS'}, 'invocation': {'file': 'core/quivr_core/brain/brain.py', 'line': 505, 'function': 'Brain.asearch'}, 'file': 'core/quivr_core/brain/brain.py', 'line': 505, 'function': 'asearch', 'agent_name': 'Brain', 'agent_name_source': 'inferred_from_class', 'not_on_graph': True})
        try:
            if not __import__('builtins').hasattr(_gr_client, 'aenforce'):
                __import__("logging").getLogger("lineaje.gr_client").error("gr_stub_client.py predates aenforce (STUB_API 5): this site is NOT enforced; replace gr_stub_client.py with the current companion")
                raise _gr_client.GuardrailUnavailableError("stale gr_stub_client.py: no aenforce")
            result = await _gr_client.aenforce(_gr_site, result, content_type='application/json', variable_name='result', source_file=__file__, before_line=505)
        except _gr_client.GuardrailUnavailableError:
            pass

        return [SearchResult(chunk=d, distance=s) for d, s in result]

    def get_chat_history(self, chat_id: UUID):
        return self._chats[chat_id]

    # TODO(@aminediro)
    def add_file(self) -> None:
        # add it to storage
        # add it to vectorstore
        raise NotImplementedError

    def ask(
        self,
        question: str,
        retrieval_config: RetrievalConfig | None = None,
        rag_pipeline: Type[Union[QuivrQARAG, QuivrQARAGLangGraph]] | None = None,
        list_files: list[QuivrKnowledge] | None = None,
        chat_history: ChatHistory | None = None,
    ) -> ParsedRAGResponse:
        """
        Ask a question to the brain and get a generated answer.

        Args:
            question (str): The question to ask.
            retrieval_config (RetrievalConfig | None): The retrieval configuration (see RetrievalConfig docs).
            rag_pipeline (Type[Union[QuivrQARAG, QuivrQARAGLangGraph]] | None): The RAG pipeline to use.
            list_files (list[QuivrKnowledge] | None): The list of files to include in the RAG pipeline.
            chat_history (ChatHistory | None): The chat history to use.

        Returns:
            ParsedRAGResponse: The generated answer.

        Example:
        ```python
        brain = Brain.from_files(name="My Brain", file_paths=["file1.pdf", "file2.pdf"])
        answer = brain.ask("What is the meaning of life?")
        print(answer.answer)
        ```
        """
        async def collect_streamed_response():
            full_answer = ""
            async for response in self.ask_streaming(
                question=question,
                retrieval_config=retrieval_config,
                rag_pipeline=rag_pipeline,
                list_files=list_files,
                chat_history=chat_history
            ):
                full_answer += response.answer
            # LINEAJE: runtime guardrail checks `full_answer` as it flows from the agent to the user interface, before it leaves the application (in Brain.collect_streamed_response).
            #   Detected: this statement moves data from the agent to the user interface with no runtime policy check (detection confidence: high).
            #   Decision: the Guardrail evaluates AI_DAT_SEC_012; sensitive values in `full_answer` are masked in place; a policy violation stops the call (fail_mode=BLOCK). If the Guardrail is unreachable, the call continues unchanged.
            #   Do not remove without review. site_id='site:sha256:758bc7108508df135dfa057c8e964fdf3a3253aaf5b4cce4d0136c4367a082f3'
            _gr_client = _lineaje_load_gr_client()
            _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:758bc7108508df135dfa057c8e964fdf3a3253aaf5b4cce4d0136c4367a082f3', phase='data_egress', boundary={'source': 'agent_message', 'sink': 'user_interface'}, fail_mode='BLOCK', source_type='agent', destination_type='user_interface', components={'invocation': {'file': 'core/quivr_core/brain/brain.py', 'line': 558, 'function': 'Brain.ask.collect_streamed_response'}, 'file': 'core/quivr_core/brain/brain.py', 'line': 558, 'function': 'collect_streamed_response', 'agent_name': 'Brain', 'agent_name_source': 'inferred_from_class', 'not_on_graph': True})
            try:
                if not __import__('builtins').hasattr(_gr_client, 'aenforce'):
                    __import__("logging").getLogger("lineaje.gr_client").error("gr_stub_client.py predates aenforce (STUB_API 5): this site is NOT enforced; replace gr_stub_client.py with the current companion")
                    raise _gr_client.GuardrailUnavailableError("stale gr_stub_client.py: no aenforce")
                full_answer = await _gr_client.aenforce(_gr_site, full_answer, content_type='text/plain')
            except _gr_client.GuardrailUnavailableError:
                pass
            except PermissionError:
                pass
            return full_answer

        # Run the async function in the event loop
        loop = asyncio.get_event_loop()
        full_answer = loop.run_until_complete(collect_streamed_response())

        chat_history = self.default_chat if chat_history is None else chat_history
        chat_history.append(HumanMessage(content=question))
        chat_history.append(AIMessage(content=full_answer))

        # Return the final response
        return ParsedRAGResponse(answer=full_answer)

    async def ask_streaming(
        self,
        question: str,
        retrieval_config: RetrievalConfig | None = None,
        rag_pipeline: Type[Union[QuivrQARAG, QuivrQARAGLangGraph]] | None = None,
        list_files: list[QuivrKnowledge] | None = None,
        chat_history: ChatHistory | None = None,
    ) -> AsyncGenerator[ParsedRAGChunkResponse, ParsedRAGChunkResponse]:
        """
        Ask a question to the brain and get a streamed generated answer.

        Args:
            question (str): The question to ask.
            retrieval_config (RetrievalConfig | None): The retrieval configuration (see RetrievalConfig docs).
            rag_pipeline (Type[Union[QuivrQARAG, QuivrQARAGLangGraph]] | None): The RAG pipeline to use.
            list_files (list[QuivrKnowledge] | None): The list of files to include in the RAG pipeline.
            chat_history (ChatHistory | None): The chat history to use.

        Returns:
            AsyncGenerator[ParsedRAGChunkResponse, ParsedRAGChunkResponse]: The streamed generated answer.

        Example:
        ```python
        brain = Brain.from_files(name="My Brain", file_paths=["file1.pdf", "file2.pdf"])
        async for chunk in brain.ask_streaming("What is the meaning of life?"):
            print(chunk.answer)
        ```

        """
        llm = self.llm

        # If you passed a different llm model we'll override the brain  one
        if retrieval_config:
            if retrieval_config.llm_config != self.llm.get_config():
                llm = LLMEndpoint.from_config(config=retrieval_config.llm_config)
        else:
            retrieval_config = RetrievalConfig(llm_config=self.llm.get_config())

        if rag_pipeline is None:
            rag_pipeline = QuivrQARAGLangGraph

        rag_instance = rag_pipeline(
            retrieval_config=retrieval_config, llm=llm, vector_store=self.vector_db
        )

        chat_history = self.default_chat if chat_history is None else chat_history
        list_files = [] if list_files is None else list_files

        full_answer = ""
        async for response in rag_instance.answer_astream(
            question=question, history=chat_history, list_files=list_files
        ):
            # Format output to be correct servicedf;j
            if not response.last_chunk:
                yield response
            full_answer += response.answer

        # TODO : add sources, metdata etc  ...
        chat_history.append(HumanMessage(content=question))
        chat_history.append(AIMessage(content=full_answer))
        yield response

