import os

import pytest
from quivr_core.files.file import FileExtension
from quivr_core.processor.registry import known_processors


def test_twelvelabs_processor_registered():
    """The Pegasus video processor is registered for video extensions."""
    for ext in [FileExtension.mp4, FileExtension.webm, FileExtension.mpeg]:
        assert ext in known_processors
        assert any(
            "TwelveLabsVideoProcessor" in entry.cls_mod
            for entry in known_processors[ext]
        )


def test_twelvelabs_embeddings_requires_key(monkeypatch):
    """Without a key (and without an explicit one), construction raises."""
    twelvelabs = pytest.importorskip("twelvelabs")  # noqa: F841
    from quivr_core.embeddings.twelvelabs import TwelveLabsEmbeddings

    monkeypatch.delenv("TWELVELABS_API_KEY", raising=False)
    with pytest.raises(ValueError):
        TwelveLabsEmbeddings()


@pytest.mark.skipif(
    not os.getenv("TWELVELABS_API_KEY"),
    reason="TWELVELABS_API_KEY not set",
)
def test_twelvelabs_embeddings_dim():
    """Marengo returns a 512-dimensional embedding for a text query."""
    pytest.importorskip("twelvelabs")
    from quivr_core.embeddings.twelvelabs import TwelveLabsEmbeddings

    embedder = TwelveLabsEmbeddings()
    vec = embedder.embed_query("a red car driving on a highway")
    assert len(vec) == 512
    assert all(isinstance(x, float) for x in vec[:8])
