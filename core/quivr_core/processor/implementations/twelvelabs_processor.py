"""Video ingestion through TwelveLabs Pegasus.

This is an *opt-in* processor: it is not registered by default. Register it
explicitly to ingest video files into a Quivr brain::

    from quivr_core.processor.registry import register_processor
    from quivr_core.processor.implementations.twelvelabs_processor import (
        TwelveLabsVideoProcessor,
    )

    register_processor(".mp4", TwelveLabsVideoProcessor, override=True)

Pegasus watches the whole video (visuals, audio, on-screen text) and returns a
natural-language description, which is then chunked into searchable documents.

Requires the ``twelvelabs`` extra::

    pip install quivr-core[twelvelabs]

and a ``TWELVELABS_API_KEY`` (grab a free one at https://twelvelabs.io).
"""

import asyncio
import logging
import os
from typing import Any

from langchain_core.documents import Document

from quivr_core.files.file import FileExtension, QuivrFile
from quivr_core.processor.implementations.simple_txt_processor import (
    recursive_character_splitter,
)
from quivr_core.processor.processor_base import ProcessedDocument, ProcessorBase
from quivr_core.processor.splitter import SplitterConfig

logger = logging.getLogger("quivr_core")

_DEFAULT_PROMPT = (
    "Describe this video in detail. Include the topics covered, what is shown "
    "on screen, what is said, and any text that appears, so the description can "
    "be used to answer questions about the video."
)


class TwelveLabsVideoProcessor(ProcessorBase):
    """Ingest video files by analyzing them with the TwelveLabs Pegasus model.

    Args:
        api_key: TwelveLabs API key. Defaults to ``TWELVELABS_API_KEY`` env var.
        model_name: Pegasus model to use. Defaults to ``"pegasus1.5"``.
        prompt: Analysis prompt sent to Pegasus.
        max_tokens: Maximum tokens for the generated description.
        splitter_config: How to chunk the generated description.
        poll_interval: Seconds between asset-status polls.
        timeout: Max seconds to wait for the uploaded asset to be ready.
    """

    supported_extensions = [
        FileExtension.mp4,
        FileExtension.webm,
        FileExtension.mpeg,
    ]

    def __init__(
        self,
        api_key: str | None = None,
        model_name: str = "pegasus1.5",
        prompt: str = _DEFAULT_PROMPT,
        max_tokens: int = 2048,
        splitter_config: SplitterConfig = SplitterConfig(),
        poll_interval: float = 5.0,
        timeout: float = 600.0,
        **kwargs,
    ) -> None:
        super().__init__(**kwargs)
        try:
            from twelvelabs import TwelveLabs
        except ImportError as e:
            raise ImportError(
                "Please install quivr-core[twelvelabs] to use TwelveLabsVideoProcessor."
            ) from e

        api_key = api_key or os.getenv("TWELVELABS_API_KEY")
        if not api_key:
            raise ValueError(
                "A TwelveLabs API key is required. Pass `api_key` or set the "
                "TWELVELABS_API_KEY environment variable."
            )

        self.model_name = model_name
        self.prompt = prompt
        self.max_tokens = max_tokens
        self.splitter_config = splitter_config
        self.poll_interval = poll_interval
        self.timeout = timeout
        self._client = TwelveLabs(api_key=api_key)

    @property
    def processor_metadata(self) -> dict[str, Any]:
        return {
            "processor_cls": "TwelveLabsVideoProcessor",
            "model_name": self.model_name,
            "splitter": self.splitter_config.model_dump(),
        }

    def _analyze(self, path: str) -> str:
        """Upload the video as an asset, wait for it, then run Pegasus.

        Runs in a worker thread (the TwelveLabs SDK is synchronous).
        """
        from twelvelabs.types.video_context import VideoContext_AssetId

        with open(path, "rb") as f:
            asset = self._client.assets.create(method="direct", file=f)

        waited = 0.0
        while asset.status != "ready":
            if asset.status == "failed":
                raise RuntimeError(f"TwelveLabs asset {asset.id} failed to process")
            if waited >= self.timeout:
                raise TimeoutError(
                    f"TwelveLabs asset {asset.id} not ready after {self.timeout}s "
                    f"(status: {asset.status})"
                )
            import time

            time.sleep(self.poll_interval)
            waited += self.poll_interval
            asset = self._client.assets.retrieve(asset.id)

        result = self._client.analyze(
            model_name=self.model_name,
            video=VideoContext_AssetId(type="asset_id", asset_id=asset.id),
            prompt=self.prompt,
            max_tokens=self.max_tokens,
        )
        if not result.data:
            raise RuntimeError(
                f"TwelveLabs analysis returned no data (error: {result.error})"
            )
        return result.data

    async def process_file_inner(self, file: QuivrFile) -> ProcessedDocument[str]:
        content = await asyncio.to_thread(self._analyze, str(file.path))

        doc = Document(page_content=content)
        docs = recursive_character_splitter(
            doc,
            self.splitter_config.chunk_size,
            self.splitter_config.chunk_overlap,
        )

        return ProcessedDocument(
            chunks=docs,
            processor_cls="TwelveLabsVideoProcessor",
            processor_response=content,
        )
