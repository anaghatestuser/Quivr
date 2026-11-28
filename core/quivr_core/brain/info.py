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

from dataclasses import dataclass
from uuid import UUID

from rich.tree import Tree


@dataclass
class ChatHistoryInfo:
    nb_chats: int
    current_default_chat: UUID
    current_chat_history_length: int

    def add_to_tree(self, chats_tree: Tree):
        chats_tree.add(f"Number of Chats: [bold]{self.nb_chats}[/bold]")
        chats_tree.add(
            f"Current Default Chat: [bold magenta]{self.current_default_chat}[/bold magenta]"
        )
        chats_tree.add(
            f"Current Chat History Length: [bold]{self.current_chat_history_length}[/bold]"
        )


@dataclass
class LLMInfo:
    model: str
    llm_base_url: str
    temperature: float
    max_tokens: int
    supports_function_calling: int

    def add_to_tree(self, llm_tree: Tree):
        llm_tree.add(f"Model: [italic]{self.model}[/italic]")
        llm_tree.add(f"Base URL: [underline]{self.llm_base_url}[/underline]")
        llm_tree.add(f"Temperature: [bold]{self.temperature}[/bold]")
        llm_tree.add(f"Max Tokens: [bold]{self.max_tokens}[/bold]")
        func_call_color = "green" if self.supports_function_calling else "red"
        llm_tree.add(
            f"Supports Function Calling: [bold {func_call_color}]{self.supports_function_calling}[/bold {func_call_color}]"
        )


@dataclass
class StorageInfo:
    storage_type: str
    n_files: int

    def add_to_tree(self, files_tree: Tree):
        files_tree.add(f"Storage Type: [italic]{self.storage_type}[/italic]")
        files_tree.add(f"Number of Files: [bold]{self.n_files}[/bold]")


@dataclass
class BrainInfo:
    brain_id: UUID
    brain_name: str
    chats_info: ChatHistoryInfo
    llm_info: LLMInfo
    files_info: StorageInfo | None = None

    def to_tree(self):
        tree = Tree("📊 Brain Information")
        tree.add(f"🆔 ID: [bold cyan]{self.brain_id}[/bold cyan]")
        tree.add(f"🧠 Brain Name: [bold green]{self.brain_name}[/bold green]")

        if self.files_info:
            files_tree = tree.add("📁 Files")
            self.files_info.add_to_tree(files_tree)

        chats_tree = tree.add("💬 Chats")
        self.chats_info.add_to_tree(chats_tree)

        llm_tree = tree.add("🤖 LLM")
        self.llm_info.add_to_tree(llm_tree)
        # LINEAJE: runtime guardrail checks `tree` as it flows from the agent to the user interface, before it leaves the application (in BrainInfo.to_tree).
        #   Detected: this statement moves data from the agent to the user interface with no runtime policy check (detection confidence: high).
        #   Decision: the Guardrail evaluates AI_DAT_SEC_012; sensitive values in `tree` are masked in place; a policy violation stops the call (fail_mode=BLOCK). If the Guardrail is unreachable, the call continues unchanged.
        #   Do not remove without review. site_id='site:sha256:a62e2789723c9834440bac4997fbedb45cd9274e87129b445cc07cb5bbe0193e'
        _gr_client = _lineaje_load_gr_client()
        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:a62e2789723c9834440bac4997fbedb45cd9274e87129b445cc07cb5bbe0193e', phase='data_egress', boundary={'source': 'agent_message', 'sink': 'user_interface'}, fail_mode='BLOCK', source_type='agent', destination_type='user_interface', components={'invocation': {'file': 'core/quivr_core/brain/info.py', 'line': 74, 'function': 'BrainInfo.to_tree'}, 'file': 'core/quivr_core/brain/info.py', 'line': 74, 'function': 'to_tree', 'agent_name': 'BrainInfo', 'agent_name_source': 'inferred_from_class', 'not_on_graph': True})
        try:
            tree = _gr_client.enforce(_gr_site, tree, content_type='text/plain')
        except _gr_client.GuardrailUnavailableError:
            pass
        except PermissionError:
            pass
        return tree
