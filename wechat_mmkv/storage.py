from __future__ import annotations

from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

from .codec import parse_mmkv_history
from .crypto import DEFAULT_IV_OFFSET, decrypt_store
from .discovery import locate_app_directory, validate_store_id
from .errors import MMKVError


@dataclass(frozen=True)
class StorageDump:
    store_id: str
    app_directory: Path
    entries: dict[str, Any]
    entry_types: dict[str, str]
    raw_sizes: dict[str, int]
    sources: dict[str, str]
    source_metadata: tuple["StorageSource", ...]
    records: tuple["StorageRecord", ...]

    @property
    def appid(self) -> str:
        """Compatibility alias for the original AppID-specific model."""
        return self.store_id


@dataclass(frozen=True)
class StorageSource:
    source_index: int
    data_path: Path
    crc_path: Path
    mapped_size: int
    header_actual_size: int
    actual_size: int
    stored_crc32: int
    computed_crc32: int
    crc_matches: bool | None
    meta_version: int
    sequence: int
    iv: bytes
    meta_actual_size: int
    last_actual_size: int | None
    last_crc_digest: int | None
    flags: int | None
    record_offset: int
    record_count: int
    plaintext_prefix: bytes
    plaintext_suffix: bytes


@dataclass(frozen=True)
class StorageRecord:
    source_index: int
    source_path: Path
    record_index: int
    key: str
    value: Any
    data_type: str
    raw_value: bytes
    raw_record: bytes
    raw_size: int
    record_offset: int
    key_offset: int
    value_offset: int
    end_offset: int
    deleted: bool
    is_current: bool = False

    @property
    def record_id(self) -> str:
        return f"{self.source_index}:{self.record_index}"


def _store_files(
    app_directory: Path, store_id: str, include_adapter: bool
) -> list[Path]:
    directories = list(app_directory.glob("usrmmkvstorage*"))
    if include_adapter:
        directories.append(app_directory / "mmkvadapterstorage")
    files: list[Path] = []
    for directory in directories:
        path = directory / store_id
        if directory.is_dir() and path.is_file():
            files.append(path)
    return sorted(files, key=lambda path: (path.stat().st_mtime, str(path)))


def dump_storage(
    store_id: str,
    *,
    app_dir: Path | None = None,
    wechat_users_root: Path | None = None,
    include_adapter: bool = False,
    record_offset: int | None = None,
    iv_offset: int = DEFAULT_IV_OFFSET,
) -> StorageDump:
    store_id = validate_store_id(store_id)
    app_directory = locate_app_directory(
        store_id, app_dir=app_dir, wechat_users_root=wechat_users_root
    )
    files = _store_files(app_directory, store_id, include_adapter)
    if not files:
        raise MMKVError(f"no MMKV stores found for {store_id} in {app_directory}")

    source_metadata: list[StorageSource] = []
    records: list[StorageRecord] = []
    current_record_indexes: dict[str, int] = {}
    for source_index, data_path in enumerate(files):
        decrypted = decrypt_store(
            data_path, store_id=store_id, iv_offset=iv_offset
        )
        if not decrypted.plaintext:
            source_metadata.append(
                StorageSource(
                    source_index=source_index,
                    data_path=decrypted.data_path,
                    crc_path=decrypted.crc_path,
                    mapped_size=decrypted.mapped_size,
                    header_actual_size=decrypted.header_actual_size,
                    actual_size=decrypted.actual_size,
                    stored_crc32=decrypted.metadata.crc_digest,
                    computed_crc32=decrypted.computed_crc32,
                    crc_matches=decrypted.crc_matches,
                    meta_version=decrypted.metadata.version,
                    sequence=decrypted.metadata.sequence,
                    iv=decrypted.metadata.vector,
                    meta_actual_size=decrypted.metadata.actual_size,
                    last_actual_size=decrypted.metadata.last_actual_size,
                    last_crc_digest=decrypted.metadata.last_crc_digest,
                    flags=decrypted.metadata.flags,
                    record_offset=record_offset or 0,
                    record_count=0,
                    plaintext_prefix=decrypted.plaintext,
                    plaintext_suffix=b"",
                )
            )
            continue
        history = parse_mmkv_history(
            decrypted.plaintext, record_offset=record_offset
        )
        source_metadata.append(
            StorageSource(
                source_index=source_index,
                data_path=decrypted.data_path,
                crc_path=decrypted.crc_path,
                mapped_size=decrypted.mapped_size,
                header_actual_size=decrypted.header_actual_size,
                actual_size=decrypted.actual_size,
                stored_crc32=decrypted.metadata.crc_digest,
                computed_crc32=decrypted.computed_crc32,
                crc_matches=decrypted.crc_matches,
                meta_version=decrypted.metadata.version,
                sequence=decrypted.metadata.sequence,
                iv=decrypted.metadata.vector,
                meta_actual_size=decrypted.metadata.actual_size,
                last_actual_size=decrypted.metadata.last_actual_size,
                last_crc_digest=decrypted.metadata.last_crc_digest,
                flags=decrypted.metadata.flags,
                record_offset=history.record_offset,
                record_count=len(history.records),
                plaintext_prefix=decrypted.plaintext[: history.record_offset],
                plaintext_suffix=decrypted.plaintext[
                    history.records[-1].end_offset :
                ],
            )
        )
        for entry in history.records:
            records.append(
                StorageRecord(
                    source_index=source_index,
                    source_path=data_path,
                    record_index=entry.record_index,
                    key=entry.key,
                    value=entry.value,
                    data_type=entry.data_type,
                    raw_value=entry.raw_value,
                    raw_record=entry.raw_record,
                    raw_size=entry.raw_size,
                    record_offset=entry.record_offset,
                    key_offset=entry.key_offset,
                    value_offset=entry.value_offset,
                    end_offset=entry.end_offset,
                    deleted=entry.deleted,
                )
            )
            if entry.deleted:
                current_record_indexes.pop(entry.key, None)
            else:
                current_record_indexes[entry.key] = len(records) - 1

    active_indexes = set(current_record_indexes.values())
    records = [
        replace(record, is_current=index in active_indexes)
        for index, record in enumerate(records)
    ]
    current_records = {
        key: records[index] for key, index in current_record_indexes.items()
    }
    return StorageDump(
        store_id=store_id,
        app_directory=app_directory,
        entries={key: record.value for key, record in current_records.items()},
        entry_types={key: record.data_type for key, record in current_records.items()},
        raw_sizes={key: record.raw_size for key, record in current_records.items()},
        sources={key: str(record.source_path) for key, record in current_records.items()},
        source_metadata=tuple(source_metadata),
        records=tuple(records),
    )


def dump_app_storage(
    appid: str,
    *,
    app_dir: Path | None = None,
    wechat_users_root: Path | None = None,
    include_adapter: bool = False,
    record_offset: int | None = None,
    iv_offset: int = DEFAULT_IV_OFFSET,
) -> StorageDump:
    """Backward-compatible wrapper around :func:`dump_storage`."""
    return dump_storage(
        appid,
        app_dir=app_dir,
        wechat_users_root=wechat_users_root,
        include_adapter=include_adapter,
        record_offset=record_offset,
        iv_offset=iv_offset,
    )

