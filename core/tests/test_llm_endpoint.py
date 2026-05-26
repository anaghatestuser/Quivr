import os

import pytest
from langchain_core.language_models import FakeListChatModel
from pydantic import ValidationError
from quivr_core.rag.entities.config import LLMEndpointConfig
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


@pytest.mark.base
def test_llm_endpoint_from_config_orcarouter_auto():
    from langchain_openai import ChatOpenAI
    from quivr_core.rag.entities.config import DefaultModelSuppliers

    config = LLMEndpointConfig(
        supplier=DefaultModelSuppliers.ORCAROUTER,
        model="orcarouter/auto",
        llm_api_key="test",
    )
    llm = LLMEndpoint.from_config(config)

    assert isinstance(llm._llm, ChatOpenAI)
    assert llm.get_config().supplier == DefaultModelSuppliers.ORCAROUTER
    assert llm.get_config().model == "orcarouter/auto"
    assert str(llm._llm.openai_api_base) == "https://api.orcarouter.ai/v1"
    assert llm._llm.temperature == config.temperature


@pytest.mark.base
def test_llm_endpoint_from_config_orcarouter_reasoning_drops_temperature():
    from langchain_openai import ChatOpenAI
    from quivr_core.rag.entities.config import DefaultModelSuppliers

    config = LLMEndpointConfig(
        supplier=DefaultModelSuppliers.ORCAROUTER,
        model="anthropic/claude-opus-4.7",
        llm_api_key="test",
    )
    llm = LLMEndpoint.from_config(config)

    assert isinstance(llm._llm, ChatOpenAI)
    assert llm._llm.temperature is None


@pytest.mark.base
def test_llm_endpoint_from_config_orcarouter_custom_base_url():
    from quivr_core.rag.entities.config import DefaultModelSuppliers

    config = LLMEndpointConfig(
        supplier=DefaultModelSuppliers.ORCAROUTER,
        model="openai/gpt-5",
        llm_api_key="test",
        llm_base_url="http://localhost:9999/v1",
    )
    llm = LLMEndpoint.from_config(config)

    assert str(llm._llm.openai_api_base) == "http://localhost:9999/v1"


@pytest.mark.base
def test_llm_endpoint_orcarouter_info_reports_real_base_url():
    from quivr_core.rag.entities.config import DefaultModelSuppliers

    config = LLMEndpointConfig(
        supplier=DefaultModelSuppliers.ORCAROUTER,
        model="orcarouter/auto",
        llm_api_key="test",
    )
    llm = LLMEndpoint.from_config(config)
    info = llm.info()
    assert info.llm_base_url == "https://api.orcarouter.ai/v1"


@pytest.mark.base
def test_llm_endpoint_orcarouter_env_variable_name(monkeypatch):
    """ORCAROUTER_API_KEY should be the resolved env var (not the
    DefaultModelSuppliers.ORCAROUTER repr)."""
    from quivr_core.rag.entities.config import DefaultModelSuppliers

    monkeypatch.setenv("ORCAROUTER_API_KEY", "test-key-from-env")
    config = LLMEndpointConfig(
        supplier=DefaultModelSuppliers.ORCAROUTER,
        model="orcarouter/auto",
    )
    assert config.env_variable_name == "ORCAROUTER_API_KEY"
    assert config.llm_api_key == "test-key-from-env"


@pytest.mark.base
def test_llm_endpoint_orcarouter_does_not_mutate_config():
    """from_config must not mutate the caller's config — mutation after the
    cache hash is computed would corrupt the cache key on subsequent calls."""
    from quivr_core.rag.entities.config import DefaultModelSuppliers

    config = LLMEndpointConfig(
        supplier=DefaultModelSuppliers.ORCAROUTER,
        model="orcarouter/auto",
        llm_api_key="test",
    )
    before_hash = hash(config)
    assert config.llm_base_url is None

    LLMEndpoint.from_config(config)

    assert config.llm_base_url is None
    assert hash(config) == before_hash


def test_llm_endpoint_constructor():
    llm_endpoint = FakeListChatModel(responses=[])
    llm_endpoint = LLMEndpoint(
        llm=llm_endpoint, llm_config=LLMEndpointConfig(model="test")
    )

    assert not llm_endpoint.supports_func_calling()
