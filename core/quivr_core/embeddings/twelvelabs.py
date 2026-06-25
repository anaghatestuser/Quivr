"""Marengo multimodal embeddings from TwelveLabs.

This is an *opt-in* embedder. It is not registered as a default; pass an
instance to :class:`~quivr_core.brain.brain.Brain` via the ``embedder``
argument to use it instead of the default OpenAI embeddings.

Marengo produces 512-dimensional embeddings that live in the same vector
space for text and video, which lets a Quivr brain retrieve video segments
(see :class:`~quivr_core.processor.implementations.twelvelabs_processor.TwelveLabsVideoProcessor`)
from natural-language queries.

Requires the ``twelvelabs`` extra::

    pip install quivr-core[twelvelabs]

and a ``TWELVELABS_API_KEY`` (grab a free one at https://twelvelabs.io).
"""

import os
from typing import List

from langchain_core.embeddings import Embeddings


class TwelveLabsEmbeddings(Embeddings):
    """LangChain ``Embeddings`` backed by the TwelveLabs Marengo model.

    Args:
        api_key: TwelveLabs API key. Defaults to the ``TWELVELABS_API_KEY``
            environment variable.
        model_name: Marengo model to use. Defaults to ``"marengo3.0"``.
    """

    def __init__(
        self,
        api_key: str | None = None,
        model_name: str = "marengo3.0",
    ) -> None:
        try:
            from twelvelabs import TwelveLabs
        except ImportError as e:
            raise ImportError(
                "Please install quivr-core[twelvelabs] to use TwelveLabsEmbeddings."
            ) from e

        api_key = api_key or os.getenv("TWELVELABS_API_KEY")
        if not api_key:
            raise ValueError(
                "A TwelveLabs API key is required. Pass `api_key` or set the "
                "TWELVELABS_API_KEY environment variable."
            )

        self.model_name = model_name
        self._client = TwelveLabs(api_key=api_key)

    def _embed_text(self, text: str) -> List[float]:
        resp = self._client.embed.create(model_name=self.model_name, text=text)
        text_embedding = resp.text_embedding
        if text_embedding is None or not text_embedding.segments:
            raise RuntimeError(
                f"TwelveLabs returned no embedding for text "
                f"(error: {getattr(text_embedding, 'error_message', None)})"
            )
        return list(text_embedding.segments[0].float_)

    def embed_documents(self, texts: List[str]) -> List[List[float]]:
        return [self._embed_text(text) for text in texts]

    def embed_query(self, text: str) -> List[float]:
        return self._embed_text(text)
