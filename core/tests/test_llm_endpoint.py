import os

import pytest
from langchain_core.language_models import FakeListChatModel
from pydantic import ValidationError
from quivr_core.rag.entities.config import (
    DefaultModelSuppliers,
    LLMEndpointConfig,
    LLMModelConfig,
)
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
def test_llm_endpoint_minimax():
    from langchain_openai import ChatOpenAI

    config = LLMEndpointConfig(
        supplier=DefaultModelSuppliers.MINIMAX,
        model="MiniMax-M2.7",
        llm_api_key="test",
    )
    llm = LLMEndpoint.from_config(config)

    assert isinstance(llm._llm, ChatOpenAI)
    assert llm._llm.model_name == "MiniMax-M2.7"
    assert str(llm._llm.openai_api_base) == "https://api.minimax.io/v1"
    assert llm.supports_func_calling()


@pytest.mark.base
def test_minimax_m27_models_in_config():
    minimax_models = LLMModelConfig._model_defaults[DefaultModelSuppliers.MINIMAX]
    model_names = list(minimax_models.keys())

    # M2.7 models should be present and come first
    assert "MiniMax-M2.7" in model_names
    assert "MiniMax-M2.7-highspeed" in model_names
    assert model_names[0] == "MiniMax-M2.7"
    assert model_names[1] == "MiniMax-M2.7-highspeed"

    # Previous models still available
    assert "MiniMax-M2.5" in model_names
    assert "MiniMax-M2.5-highspeed" in model_names
