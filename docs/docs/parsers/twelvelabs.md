# TwelveLabs (video + multimodal embeddings)

[TwelveLabs](https://twelvelabs.io) provides video-native foundation models.
Two opt-in integrations are available in `quivr-core`:

- **Pegasus** — `TwelveLabsVideoProcessor` ingests video files (`.mp4`,
  `.webm`, `.mpeg`) by generating a natural-language description of the whole
  video (visuals, speech, on-screen text), which is then chunked into
  searchable documents.
- **Marengo** — `TwelveLabsEmbeddings` is a LangChain `Embeddings`
  implementation that produces 512-dimensional multimodal embeddings.

Both require the `twelvelabs` extra and a `TWELVELABS_API_KEY` (there's a
generous free tier at [twelvelabs.io](https://twelvelabs.io)):

```bash
pip install "quivr-core[twelvelabs]"
export TWELVELABS_API_KEY=...
```

## Ingesting videos with Pegasus

The video processor is registered for video extensions but only loads when the
`twelvelabs` extra is installed, so the default behavior of the library is
unchanged. To use it explicitly:

```python
from quivr_core.processor.registry import register_processor
from quivr_core.processor.implementations.twelvelabs_processor import (
    TwelveLabsVideoProcessor,
)

register_processor(".mp4", TwelveLabsVideoProcessor, override=True)
```

## Marengo embeddings

```python
from quivr_core import Brain
from quivr_core.embeddings.twelvelabs import TwelveLabsEmbeddings

brain = Brain.from_files(
    name="my videos",
    file_paths=["intro.mp4"],
    embedder=TwelveLabsEmbeddings(),
)
```

::: quivr_core.processor.implementations.twelvelabs_processor
    options:
      heading_level: 2

::: quivr_core.embeddings.twelvelabs
    options:
      heading_level: 2
