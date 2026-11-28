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
from typing import Union
from urllib.parse import parse_qs, urlparse

import tiktoken
from langchain_anthropic import ChatAnthropic
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_openai import AzureChatOpenAI, ChatOpenAI
from pydantic.v1 import SecretStr

from quivr_core.brain.info import LLMInfo
from quivr_core.config import DefaultModelSuppliers, LLMEndpointConfig
from quivr_core.utils import model_supports_function_calling

logger = logging.getLogger("quivr_core")


class LLMEndpoint:
    def __init__(self, llm_config: LLMEndpointConfig, llm: BaseChatModel):
        self._config = llm_config
        self._llm = llm
        self._supports_func_calling = model_supports_function_calling(
            self._config.model
        )

        if llm_config.tokenizer_hub:
            # To prevent the warning
            # huggingface/tokenizers: The current process just got forked, after parallelism has already been used. Disabling parallelism to avoid deadlocks...
            os.environ["TOKENIZERS_PARALLELISM"] = (
                "false"
                if not os.environ.get("TOKENIZERS_PARALLELISM")
                else os.environ["TOKENIZERS_PARALLELISM"]
            )
            try:
                from transformers import AutoTokenizer

                self.tokenizer = AutoTokenizer.from_pretrained(llm_config.tokenizer_hub)
            except OSError:  # if we don't manage to connect to huggingface and/or no cached models are present
                _lineaje_payload = f"Cannot acces the configured tokenizer from {llm_config.tokenizer_hub}, using the default tokenizer {llm_config.fallback_tokenizer}"
                # LINEAJE: runtime guardrail checks `_lineaje_payload` as it flows from the agent to the application log, before it is written to the log (in LLMEndpoint.__init__).
                #   Detected: this statement moves data from the agent to the application log with no runtime policy check (detection confidence: high).
                #   Decision: the Guardrail evaluates AI_DAT_SEC_010; sensitive values in `_lineaje_payload` are masked in place; a policy violation stops the call (fail_mode=BLOCK). If the Guardrail is unreachable, the call continues unchanged.
                #   Do not remove without review. site_id='site:sha256:5c6a6c5e82edb580ed4cab54a9cb7ba4af17657e237d98a84ab76e14ad6a4a90'
                _gr_client = _lineaje_load_gr_client()
                _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:5c6a6c5e82edb580ed4cab54a9cb7ba4af17657e237d98a84ab76e14ad6a4a90', phase='log_emit', boundary={'source': 'log', 'sink': 'log'}, fail_mode='BLOCK', source_type='agent', destination_type='log', components={'invocation': {'file': 'core/quivr_core/llm/llm_endpoint.py', 'line': 40, 'function': 'LLMEndpoint.__init__'}, 'file': 'core/quivr_core/llm/llm_endpoint.py', 'line': 40, 'function': '__init__', 'agent_name': 'LLMEndpoint', 'agent_name_source': 'inferred_from_class', 'not_on_graph': True})
                try:
                    _lineaje_payload = _gr_client.enforce(_gr_site, _lineaje_payload, content_type='application/json')
                except _gr_client.GuardrailUnavailableError:
                    pass
                except PermissionError:
                    pass
                logger.warning(
                    _lineaje_payload
                )
                self.tokenizer = tiktoken.get_encoding(llm_config.fallback_tokenizer)
        else:
            self.tokenizer = tiktoken.get_encoding(llm_config.fallback_tokenizer)

    def count_tokens(self, text: str) -> int:
        # Tokenize the input text and return the token count
        encoding = self.tokenizer.encode(text)
        return len(encoding)

    def get_config(self):
        return self._config

    @classmethod
    def from_config(cls, config: LLMEndpointConfig = LLMEndpointConfig()):
        _llm: Union[AzureChatOpenAI, ChatOpenAI, ChatAnthropic]
        try:
            if config.supplier == DefaultModelSuppliers.AZURE:
                # Parse the URL
                parsed_url = urlparse(config.llm_base_url)
                deployment = parsed_url.path.split("/")[3]  # type: ignore
                api_version = parse_qs(parsed_url.query).get("api-version", [None])[0]  # type: ignore
                azure_endpoint = f"https://{parsed_url.netloc}"  # type: ignore
                # LINEAJE: runtime guardrail checks the model this client is built with as it flows from the agent to the LLM, before it is sent to the model (in LLMEndpoint.from_config).
                #   Detected: this statement moves data from the agent to the LLM with no runtime policy check (detection confidence: medium).
                #   Decision: the Guardrail evaluates AI_AGENT_ACTIVITY_LOG, AI_APP_SEC_006, AI_APP_SEC_028, AI_APP_SEC_070 (+1 more); a model that is not approved is refused before the client is built (fail_mode=BLOCK). If the Guardrail is unreachable, the call continues unchanged.
                #   Do not remove without review. site_id='site:sha256:d27b38d0a00c2b0151c6bc6acb0cdb3baa3d73432c4aa9da4cfc6a826739bb4c'
                _lineaje_model_evidence = {'model': deployment, 'client': 'AzureChatOpenAI', 'provider': 'langchain_openai', 'model_source': 'call_kwarg', 'project': 'quivr'}
                _gr_client = _lineaje_load_gr_client()
                _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:d27b38d0a00c2b0151c6bc6acb0cdb3baa3d73432c4aa9da4cfc6a826739bb4c', phase='pre_model', boundary={'source': 'agent_config', 'sink': 'model'}, fail_mode='BLOCK', source_type='agent', destination_type='llm', components={'invocation': {'file': 'core/quivr_core/llm/llm_endpoint.py', 'function': 'LLMEndpoint.from_config', 'line': 65}, 'destination': {'entity_type': 'llm', 'name': 'gpt-4o', 'provider': 'openai', 'version': ''}, 'file': 'core/quivr_core/llm/llm_endpoint.py', 'line': 65, 'function': 'from_config', 'agent_name': 'LLMEndpoint', 'agent_name_source': 'inferred_from_class', 'boundary_id': 'bnd:30f33d16a8b9aa81'})
                try:
                    _lineaje_model_evidence = _gr_client.enforce(_gr_site, _lineaje_model_evidence, content_type='application/json')
                except _gr_client.GuardrailUnavailableError:
                    pass
                except PermissionError:
                    raise
                _llm = AzureChatOpenAI(
                    azure_deployment=deployment,  # type: ignore
                    api_version=api_version,
                    api_key=SecretStr(config.llm_api_key)
                    if config.llm_api_key
                    else None,
                    azure_endpoint=azure_endpoint,
                    max_tokens=config.max_output_tokens,
                )
            elif config.supplier == DefaultModelSuppliers.ANTHROPIC:
                # LINEAJE: runtime guardrail checks the model this client is built with as it flows from the agent to the LLM, before it is sent to the model (in LLMEndpoint.from_config).
                #   Detected: this statement moves data from the agent to the LLM with no runtime policy check (detection confidence: medium).
                #   Decision: the Guardrail evaluates AI_AGENT_ACTIVITY_LOG, AI_APP_SEC_006, AI_APP_SEC_028, AI_APP_SEC_070 (+1 more); a model that is not approved is refused before the client is built (fail_mode=BLOCK). If the Guardrail is unreachable, the call continues unchanged.
                #   Do not remove without review. site_id='site:sha256:36aa6da871f70b75470e80141a5b5fba0a765501163cdce8d65dd176ef8090ad'
                _lineaje_model_evidence = {'model': config.model, 'client': 'ChatAnthropic', 'provider': 'langchain_anthropic', 'model_source': 'call_kwarg', 'project': 'quivr'}
                _gr_client = _lineaje_load_gr_client()
                _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:36aa6da871f70b75470e80141a5b5fba0a765501163cdce8d65dd176ef8090ad', phase='pre_model', boundary={'source': 'agent_config', 'sink': 'model'}, fail_mode='BLOCK', source_type='agent', destination_type='llm', components={'invocation': {'file': 'core/quivr_core/llm/llm_endpoint.py', 'function': 'LLMEndpoint.from_config', 'line': 75}, 'file': 'core/quivr_core/llm/llm_endpoint.py', 'line': 75, 'function': 'from_config', 'agent_name': 'LLMEndpoint', 'agent_name_source': 'inferred_from_class', 'boundary_id': 'bnd:c2cb65f942b00246'})
                try:
                    _lineaje_model_evidence = _gr_client.enforce(_gr_site, _lineaje_model_evidence, content_type='application/json')
                except _gr_client.GuardrailUnavailableError:
                    pass
                except PermissionError:
                    raise
                _llm = ChatAnthropic(
                    model_name=config.model,
                    api_key=SecretStr(config.llm_api_key)
                    if config.llm_api_key
                    else None,
                    base_url=config.llm_base_url,
                    max_tokens=config.max_output_tokens,
                )
            elif config.supplier == DefaultModelSuppliers.OPENAI:
                # LINEAJE: runtime guardrail checks the model this client is built with as it flows from the agent to the LLM, before it is sent to the model (in LLMEndpoint.from_config).
                #   Detected: this statement moves data from the agent to the LLM with no runtime policy check (detection confidence: medium).
                #   Decision: the Guardrail evaluates AI_AGENT_ACTIVITY_LOG, AI_APP_SEC_006, AI_APP_SEC_028, AI_APP_SEC_070 (+1 more); a model that is not approved is refused before the client is built (fail_mode=BLOCK). If the Guardrail is unreachable, the call continues unchanged.
                #   Do not remove without review. site_id='site:sha256:2be5eda52e70ca204b20759f6264901960440947e8a3c12aae0f318747db0c74'
                _lineaje_model_evidence = {'model': config.model, 'client': 'ChatOpenAI', 'provider': 'langchain_openai', 'model_source': 'call_kwarg', 'project': 'quivr'}
                _gr_client = _lineaje_load_gr_client()
                _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:2be5eda52e70ca204b20759f6264901960440947e8a3c12aae0f318747db0c74', phase='pre_model', boundary={'source': 'agent_config', 'sink': 'model'}, fail_mode='BLOCK', source_type='agent', destination_type='llm', components={'invocation': {'file': 'core/quivr_core/llm/llm_endpoint.py', 'function': 'LLMEndpoint.from_config', 'line': 84}, 'destination': {'entity_type': 'llm', 'name': 'gpt-4o', 'provider': 'openai', 'version': ''}, 'file': 'core/quivr_core/llm/llm_endpoint.py', 'line': 84, 'function': 'from_config', 'agent_name': 'LLMEndpoint', 'agent_name_source': 'inferred_from_class', 'boundary_id': 'bnd:f768e319de54eada'})
                try:
                    _lineaje_model_evidence = _gr_client.enforce(_gr_site, _lineaje_model_evidence, content_type='application/json')
                except _gr_client.GuardrailUnavailableError:
                    pass
                except PermissionError:
                    raise
                _llm = ChatOpenAI(
                    model=config.model,
                    api_key=SecretStr(config.llm_api_key)
                    if config.llm_api_key
                    else None,
                    base_url=config.llm_base_url,
                    max_tokens=config.max_output_tokens,
                )
            else:
                # LINEAJE: runtime guardrail checks the model this client is built with as it flows from the agent to the LLM, before it is sent to the model (in LLMEndpoint.from_config).
                #   Detected: this statement moves data from the agent to the LLM with no runtime policy check (detection confidence: medium).
                #   Decision: the Guardrail evaluates AI_AGENT_ACTIVITY_LOG, AI_APP_SEC_006, AI_APP_SEC_028, AI_APP_SEC_070 (+1 more); a model that is not approved is refused before the client is built (fail_mode=BLOCK). If the Guardrail is unreachable, the call continues unchanged.
                #   Do not remove without review. site_id='site:sha256:614af9bd41e02d822793fed23e7f2194575cbb1f6957e2ab5cb9608f3fc49e90'
                _lineaje_model_evidence = {'model': config.model, 'client': 'ChatOpenAI', 'provider': 'langchain_openai', 'model_source': 'call_kwarg', 'project': 'quivr'}
                _gr_client = _lineaje_load_gr_client()
                _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:614af9bd41e02d822793fed23e7f2194575cbb1f6957e2ab5cb9608f3fc49e90', phase='pre_model', boundary={'source': 'agent_config', 'sink': 'model'}, fail_mode='BLOCK', source_type='agent', destination_type='llm', components={'invocation': {'file': 'core/quivr_core/llm/llm_endpoint.py', 'function': 'LLMEndpoint.from_config', 'line': 93}, 'destination': {'entity_type': 'llm', 'name': 'gpt-4o', 'provider': 'openai', 'version': ''}, 'file': 'core/quivr_core/llm/llm_endpoint.py', 'line': 93, 'function': 'from_config', 'agent_name': 'LLMEndpoint', 'agent_name_source': 'inferred_from_class', 'boundary_id': 'bnd:1133aecb263df379'})
                try:
                    _lineaje_model_evidence = _gr_client.enforce(_gr_site, _lineaje_model_evidence, content_type='application/json')
                except _gr_client.GuardrailUnavailableError:
                    pass
                except PermissionError:
                    raise
                _llm = ChatOpenAI(
                    model=config.model,
                    api_key=SecretStr(config.llm_api_key)
                    if config.llm_api_key
                    else None,
                    base_url=config.llm_base_url,
                    max_tokens=config.max_output_tokens,
                )
            return cls(llm=_llm, llm_config=config)

        except ImportError as e:
            raise ImportError(
                "Please provide a valid BaseLLM or install quivr-core['base'] package"
            ) from e

    def supports_func_calling(self) -> bool:
        return self._supports_func_calling

    def info(self) -> LLMInfo:
        return LLMInfo(
            model=self._config.model,
            llm_base_url=(
                self._config.llm_base_url if self._config.llm_base_url else "openai"
            ),
            temperature=self._config.temperature,
            max_tokens=self._config.max_output_tokens,
            supports_function_calling=self.supports_func_calling(),
        )
