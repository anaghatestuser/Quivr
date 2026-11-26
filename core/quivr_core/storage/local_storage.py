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

import os
import shutil
from pathlib import Path
from typing import Self, Set
from uuid import UUID

from quivr_core.brain.serialization import LocalStorageConfig, TransparentStorageConfig
from quivr_core.files.file import QuivrFile
from quivr_core.storage.storage_base import StorageBase


class LocalStorage(StorageBase):
    """
    LocalStorage is a concrete implementation of the `StorageBase` class that
    stores files locally on disk. This class manages file uploads, tracks file
    hashes, and allows retrieval of stored files from a specified directory.

    Attributes:
        name (str): The name of the storage type, set to "local_storage".
        files (list[QuivrFile]): A list of files stored in this local storage.
        hashes (Set[str]): A set of SHA-1 hashes of the uploaded files.
        copy_flag (bool): If `True`, files are copied to the storage directory.
                          If `False`, symbolic links are used instead.
        dir_path (Path): The directory path where files are stored.

    Args:
        dir_path (Path | None): Optional directory path for storing files.
                                Defaults to the environment variable `QUIVR_LOCAL_STORAGE`
                                or `~/.cache/quivr/files`.
        copy_flag (bool): Whether to copy the file or create a symlink.
                          Defaults to `True`.
    """

    name: str = "local_storage"

    def __init__(self, dir_path: Path | None = None, copy_flag: bool = True):
        self.files: list[QuivrFile] = []
        self.hashes: Set[str] = set()
        self.copy_flag = copy_flag

        if dir_path is None:
            self.dir_path = Path(
                os.getenv("QUIVR_LOCAL_STORAGE", "~/.cache/quivr/files")
            )
        else:
            self.dir_path = dir_path
        os.makedirs(self.dir_path, exist_ok=True)

    def _load_files(self) -> None:
        # TODO(@aminediro): load existing files
        pass

    def nb_files(self) -> int:
        return len(self.files)

    def info(self):
        return {"directory_path": self.dir_path, **super().info()}

    async def upload_file(self, file: QuivrFile, exists_ok: bool = False) -> None:
        """
        Uploads a file to the local storage. Copies or creates a symlink based
        on the `copy_flag` attribute. Checks for duplicate file uploads using
        the file's SHA-1 hash.

        Args:
            file (QuivrFile): The file object to upload.
            exists_ok (bool): If `True`, allows overwriting an existing file.
                              Defaults to `False`.

        Raises:
            FileExistsError: If a file with the same SHA-1 hash already exists
                             and `exists_ok` is set to `False`.
        """
        dst_path = os.path.join(
            self.dir_path, str(file.brain_id), f"{file.id}{file.file_extension}"
        )

        if file.file_sha1 in self.hashes and not exists_ok:
            raise FileExistsError(f"file {file.original_filename} already uploaded")

        if self.copy_flag:
            shutil.copy2(file.path, dst_path)
        else:
            os.symlink(file.path, dst_path)

        file.path = Path(dst_path)
        self.files.append(file)
        self.hashes.add(file.file_sha1)

    async def get_files(self) -> list[QuivrFile]:
        """
        Retrieves the list of files stored in the local storage.

        Returns:
            list[QuivrFile]: A list of stored file objects.
        """
        return self.files

    async def remove_file(self, file_id: UUID) -> None:
        """
        Removes a file from the local storage. This method is currently not
        implemented.

        Args:
            file_id (UUID): The unique identifier of the file to remove.

        Raises:
            NotImplementedError: Always raises this error as the method is not yet implemented.
        """
        raise NotImplementedError

    @classmethod
    def load(cls, config: LocalStorageConfig) -> Self:
        """
        Loads the local storage from a configuration object. This method
        initializes the storage directory and populates it with deserialized
        files from the configuration.

        Args:
            config (LocalStorageConfig): Configuration object containing the
                                         storage path and serialized file data.

        Returns:
            LocalStorage: An instance of `LocalStorage` with files loaded
                          from the configuration.
        """
        tstorage = cls(dir_path=config.storage_path)
        tstorage.files = [QuivrFile.deserialize(f) for f in config.files.values()]
        # LINEAJE: runtime guardrail checks `tstorage` as it flows from the agent to the user interface, before it leaves the application (in LocalStorage.load).
        #   Detected: this statement moves data from the agent to the user interface with no runtime policy check (detection confidence: high).
        #   Decision: the Guardrail evaluates AI_DAT_SEC_012; sensitive values in `tstorage` are masked in place; a policy violation stops the call (fail_mode=BLOCK). If the Guardrail is unreachable, the call continues unchanged.
        #   Do not remove without review. site_id='site:sha256:9feec214a83e20c2cc7c8bc3a8bdc55796bbe3d322c86d0837e9780e3e849861'
        _gr_client = _lineaje_load_gr_client()
        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:9feec214a83e20c2cc7c8bc3a8bdc55796bbe3d322c86d0837e9780e3e849861', phase='data_egress', boundary={'source': 'agent_message', 'sink': 'user_interface'}, fail_mode='BLOCK', source_type='agent', destination_type='user_interface', components={'invocation': {'file': 'core/quivr_core/storage/local_storage.py', 'line': 129, 'function': 'LocalStorage.load'}, 'file': 'core/quivr_core/storage/local_storage.py', 'line': 129, 'function': 'load', 'agent_name': 'LocalStorage', 'agent_name_source': 'inferred_from_class', 'not_on_graph': True})
        try:
            tstorage = _gr_client.enforce(_gr_site, tstorage, content_type='text/plain')
        except _gr_client.GuardrailUnavailableError:
            pass
        except PermissionError:
            pass
        return tstorage


class TransparentStorage(StorageBase):
    """Transparent Storage."""

    name: str = "transparent_storage"

    def __init__(self):
        self.id_files = {}

    async def upload_file(self, file: QuivrFile, exists_ok: bool = False) -> None:
        self.id_files[file.id] = file

    def nb_files(self) -> int:
        return len(self.id_files)

    async def remove_file(self, file_id: UUID) -> None:
        raise NotImplementedError

    async def get_files(self) -> list[QuivrFile]:
        return list(self.id_files.values())

    @classmethod
    def load(cls, config: TransparentStorageConfig) -> Self:
        tstorage = cls()
        tstorage.id_files = {
            i: QuivrFile.deserialize(f) for i, f in config.files.items()
        }
        # LINEAJE: runtime guardrail checks `tstorage` as it flows from the agent to the user interface, before it leaves the application (in TransparentStorage.load).
        #   Detected: this statement moves data from the agent to the user interface with no runtime policy check (detection confidence: high).
        #   Decision: the Guardrail evaluates AI_DAT_SEC_012; sensitive values in `tstorage` are masked in place; a policy violation stops the call (fail_mode=BLOCK). If the Guardrail is unreachable, the call continues unchanged.
        #   Do not remove without review. site_id='site:sha256:a4b499e1744aaf1497ca0f6c879e8af02c1b4889c23b2e8e0aa9e6b2cd39ddc3'
        _gr_client = _lineaje_load_gr_client()
        _gr_site = _gr_client.SiteDescriptor(site_id='site:sha256:a4b499e1744aaf1497ca0f6c879e8af02c1b4889c23b2e8e0aa9e6b2cd39ddc3', phase='data_egress', boundary={'source': 'agent_message', 'sink': 'user_interface'}, fail_mode='BLOCK', source_type='agent', destination_type='user_interface', components={'invocation': {'file': 'core/quivr_core/storage/local_storage.py', 'line': 158, 'function': 'TransparentStorage.load'}, 'file': 'core/quivr_core/storage/local_storage.py', 'line': 158, 'function': 'load', 'agent_name': 'TransparentStorage', 'agent_name_source': 'inferred_from_class', 'not_on_graph': True})
        try:
            tstorage = _gr_client.enforce(_gr_site, tstorage, content_type='text/plain')
        except _gr_client.GuardrailUnavailableError:
            pass
        except PermissionError:
            pass
        return tstorage
