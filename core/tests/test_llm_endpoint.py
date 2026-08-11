import os

import pytest
from langchain_core.language_models import FakeListChatModel
from pydantic import ValidationError
from quivr_core.rag.entities.config import DefaultModelSuppliers, LLMEndpointConfig
from quivr_core.llm import LLMEndpoint


@pytest.mark.base
def test_llm_endpoint_from_config_default():
    from langchain_openai import ChatOpenAI

    del os.environ["OPENAI_API_KEY"]

    with pytest.raises((ValidationError, ValueError)):
        llm = LLMEndpoint.from_config(LLMEndpointConfig())

    # Working default
    config = LLMEndpointConfig(llm_api_key="test")
    llm = LLMEndpoint.from_config(config=config)

    assert llm.supports_func_calling()
    assert isinstance(llm._llm, ChatOpenAI)
    assert llm._llm.model_name in llm.get_config().model


@pytest.mark.base
def test_llm_endpoint_from_config():
    from langchain_openai import ChatOpenAI

    config = LLMEndpointConfig(
        model="llama2", llm_api_key="test", llm_base_url="http://localhost:8441"
    )
    llm = LLMEndpoint.from_config(config)

    assert not llm.supports_func_calling()
    assert isinstance(llm._llm, ChatOpenAI)
    assert llm._llm.model_name in llm.get_config().model


def test_llm_endpoint_constructor():
    llm_endpoint = FakeListChatModel(responses=[])
    llm_endpoint = LLMEndpoint(
        llm=llm_endpoint, llm_config=LLMEndpointConfig(model="test")
    )

    assert not llm_endpoint.supports_func_calling()


@pytest.mark.base
def test_llm_endpoint_minimax_default_base_url():
    from langchain_openai import ChatOpenAI

    config = LLMEndpointConfig(
        supplier=DefaultModelSuppliers.MINIMAX,
        model="MiniMax-M3",
        llm_api_key="test",
        max_context_tokens=2_000_000,
    )
    llm = LLMEndpoint.from_config(config)

    assert isinstance(llm._llm, ChatOpenAI)
    assert llm._llm.model_name == "MiniMax-M3"
    assert str(llm._llm.root_client.base_url).rstrip("/") == "https://api.minimax.io/v1"
    assert config.max_context_tokens == 1_000_000
    assert llm.supports_func_calling()


@pytest.mark.base
def test_llm_endpoint_minimax_custom_base_url():
    from langchain_openai import ChatOpenAI

    config = LLMEndpointConfig(
        supplier=DefaultModelSuppliers.MINIMAX,
        model="MiniMax-M2.7",
        llm_api_key="test",
        llm_base_url="https://api.minimaxi.com/v1",
        max_context_tokens=2_000_000,
    )
    llm = LLMEndpoint.from_config(config)

    assert isinstance(llm._llm, ChatOpenAI)
    assert llm._llm.model_name == "MiniMax-M2.7"
    assert (
        str(llm._llm.root_client.base_url).rstrip("/") == "https://api.minimaxi.com/v1"
    )
    assert config.max_context_tokens == 204_800


@pytest.mark.base
@pytest.mark.parametrize(
    ("model", "base_url"),
    [
        ("MiniMax-M3", "https://api.minimax.io/anthropic"),
        ("MiniMax-M2.7", "https://api.minimaxi.com/anthropic"),
    ],
)
def test_llm_endpoint_minimax_anthropic_base_urls(model: str, base_url: str):
    from langchain_anthropic import ChatAnthropic

    config = LLMEndpointConfig(
        supplier=DefaultModelSuppliers.MINIMAX,
        model=model,
        llm_api_key="test",
        llm_base_url=base_url,
    )
    llm = LLMEndpoint.from_config(config)

    assert isinstance(llm._llm, ChatAnthropic)
    assert llm._llm.model == model
    assert str(llm._llm.anthropic_api_url).rstrip("/") == base_url
