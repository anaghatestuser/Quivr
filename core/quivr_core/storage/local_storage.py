# Copyright (c) Lineaje, Inc. All rights reserved.
# Lineaje guardrail helper — inlined once per file (see _import_hint); no
# separate package to install. gr_check() POSTs to GR_SERVICE_URL + "/enforce"
# and fails open (returns `data` unchanged) unless a policy deliberately
# blocks it (GRBlockedError, only on GR_BLOCK_MODE=enforce + an HTTP 403).
class GRBlockedError(Exception):
    def __init__(self, policy_id, reason):
        self.policy_id = policy_id
        self.reason = reason
        super().__init__("Guardrail block for policy %r: %s" % (policy_id, reason))


def gr_check(data, source_type, destination_type, tenant_id="", timeout=5.0, **context):
    import json as _lineaje_json
    import logging as _lineaje_logging
    import os as _lineaje_os
    import urllib.error as _lineaje_urlerr
    import urllib.request as _lineaje_urlreq
    _logger = _lineaje_logging.getLogger("lineaje.gr_client")
    url = _lineaje_os.environ.get("GR_SERVICE_URL", "")  # Lineaje: guardrail endpoint
    if not url:
        return data  # Lineaje: fail-open — GR_SERVICE_URL not configured
    tid = tenant_id or _lineaje_os.environ.get("GR_TENANT_ID", "")
    bearer = _lineaje_os.environ.get("GR_BEARER_TOKEN") or _lineaje_os.environ.get("LINEAJE_PAT_TOKEN") or _lineaje_os.environ.get("LINEAJE_PAT", "")
    hop_label = source_type + "->" + destination_type
    params_key = "out_params" if destination_type == "agent" else "in_params"
    try:
        headers = {"Content-Type": "application/json"}
        if bearer:
            headers["Authorization"] = "Bearer " + bearer
        body = {
            "source_type": source_type,
            "destination_type": destination_type,
            params_key: {"data": data},
        }
        for _k, _v in context.items():
            if _v:
                body[_k] = _v
        if tid:
            body["tenant_id"] = tid
        req = _lineaje_urlreq.Request(
            url.rstrip("/") + "/enforce",
            data=_lineaje_json.dumps(body).encode(),
            headers=headers,
            method="POST",
        )
        with _lineaje_urlreq.urlopen(req, timeout=timeout) as resp:
            result = _lineaje_json.loads(resp.read())
    except _lineaje_urlerr.HTTPError as exc:
        if exc.code == 403:
            try:
                detail = _lineaje_json.loads(exc.read()).get("detail", {})
            except Exception:
                detail = {}
            blocked_by = detail.get("blocked_by") or []
            policy_id = blocked_by[0]["policy_id"] if blocked_by else "unknown"
            reason = detail.get("message", "Request denied by policy enforcement.")
            _logger.warning("gr_client[%s]: BLOCKED by policy=%s — %s", hop_label, policy_id, reason)
            if _lineaje_os.environ.get("GR_BLOCK_MODE", "enforce").lower() == "audit":
                return data
            raise GRBlockedError(policy_id, reason)
        _logger.warning("gr_client[%s]: GR service call failed (%s) — failing open", hop_label, exc)
        return data
    except Exception as exc:
        _logger.warning("gr_client[%s]: GR service call failed (%s) — failing open", hop_label, exc)
        return data
    if result.get("status") == "escalate":
        _logger.warning("gr_client[%s]: escalation flagged — passing through for human review", hop_label)
    return result.get("result", {}).get("data", data)
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
        try:
            tstorage = gr_check(tstorage, "agent", "user_interface", site_id='site:sha256:9feec214a83e20c2cc7c8bc3a8bdc55796bbe3d322c86d0837e9780e3e849861')
        except Exception as _gr_exc:
            if type(_gr_exc).__name__ == "GRBlockedError":
                raise
            tstorage = tstorage
            import logging as _lineaje_logging
            _lineaje_logging.getLogger("lineaje.gr_client").warning(
                "Lineaje guardrail unavailable at 'agent->user_interface' — passing data through unchecked"
            )
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
        try:
            tstorage = gr_check(tstorage, "agent", "user_interface", site_id='site:sha256:a4b499e1744aaf1497ca0f6c879e8af02c1b4889c23b2e8e0aa9e6b2cd39ddc3')
        except Exception as _gr_exc:
            if type(_gr_exc).__name__ == "GRBlockedError":
                raise
            tstorage = tstorage
            import logging as _lineaje_logging
            _lineaje_logging.getLogger("lineaje.gr_client").warning(
                "Lineaje guardrail unavailable at 'agent->user_interface' — passing data through unchecked"
            )
        return tstorage
