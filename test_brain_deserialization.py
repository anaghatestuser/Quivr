import pytest
import pickle
from pathlib import Path
from core.quivr_core.brain.brain import Brain

class DummyObject:
    def __reduce__(self):
        # harmless payload that would normally execute code
        return (print, ("UNSAFE DESERIALIZATION TRIGGERED",))

def test_brain_load_blocks_unsafe_deserialization(tmp_path: Path):
    # Create a fake pickle file with DummyObject
    payload_path = tmp_path / "vectordb.pkl"
    with open(payload_path, "wb") as f:
        pickle.dump(DummyObject(), f)

    # Try to load using Brain.load
    with pytest.raises(Exception):
        Brain.load(folder_path=tmp_path)
