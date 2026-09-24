from __future__ import annotations

import base64
import json
import os
import tempfile
from pathlib import Path
from typing import Any, Iterable

from .errors import MMKVError
from .storage import StorageDump


SCHEMA_NAME = "radiumwmpf-mmkv-jsonl-mirror"
SCHEMA_VERSION = 1


def _encoded_line(value: dict[str, Any]) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def iter_mirror_lines(storage: StorageDump) -> Iterable[dict[str, Any]]:
    yield {
        "kind": "manifest",
        "schema": SCHEMA_NAME,
        "schema_version": SCHEMA_VERSION,
        "store_id": storage.store_id,
        "app_directory": str(storage.app_directory),
        "source_count": len(storage.source_metadata),
        "record_count": len(storage.records),
        "current_count": len(storage.entries),
    }

    for source in storage.source_metadata:
        yield {
            "kind": "source",
            "source_index": source.source_index,
            "data_path": str(source.data_path),
            "crc_path": str(source.crc_path),
            "mapped_size": source.mapped_size,
            "header_actual_size": source.header_actual_size,
            "actual_size": source.actual_size,
            "stored_crc32": source.stored_crc32,
            "computed_crc32": source.computed_crc32,
            "crc_matches": source.crc_matches,
            "meta_version": source.meta_version,
            "sequence": source.sequence,
            "iv_base64": base64.b64encode(source.iv).decode("ascii"),
            "meta_actual_size": source.meta_actual_size,
            "last_actual_size": source.last_actual_size,
            "last_crc_digest": source.last_crc_digest,
            "flags": source.flags,
            "record_offset": source.record_offset,
            "record_count": source.record_count,
            "plaintext_prefix_base64": base64.b64encode(
                source.plaintext_prefix
            ).decode("ascii"),
            "plaintext_suffix_base64": base64.b64encode(
                source.plaintext_suffix
            ).decode("ascii"),
        }

    for record in storage.records:
        yield {
            "kind": "record",
            "record_id": record.record_id,
            "source_index": record.source_index,
            "source_path": str(record.source_path),
            "record_index": record.record_index,
            "record_offset": record.record_offset,
            "key_offset": record.key_offset,
            "value_offset": record.value_offset,
            "end_offset": record.end_offset,
            "key": record.key,
            "deleted": record.deleted,
            "is_current": record.is_current,
            "raw_size": record.raw_size,
            "raw_value_base64": base64.b64encode(record.raw_value).decode("ascii"),
            "raw_record_base64": base64.b64encode(record.raw_record).decode("ascii"),
            "decoded_type": record.data_type,
            "decoded_value": record.value,
        }

    for record in storage.records:
        if record.is_current:
            yield {
                "kind": "current",
                "key": record.key,
                "record_id": record.record_id,
                "source_index": record.source_index,
                "record_index": record.record_index,
            }


def export_jsonl(
    storage: StorageDump, output: Path, *, overwrite: bool = False
) -> Path:
    target = Path(output).expanduser().resolve()
    if target.exists() and not overwrite:
        raise MMKVError(f"output JSONL already exists: {target}")
    target.parent.mkdir(parents=True, exist_ok=True)

    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{target.name}.", suffix=".tmp", dir=target.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            for line in iter_mirror_lines(storage):
                stream.write(_encoded_line(line))
                stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        if target.exists() and not overwrite:
            raise MMKVError(f"output JSONL already exists: {target}")
        os.replace(temporary, target)
        return target
    except Exception:
        try:
            os.close(descriptor)
        except OSError:
            pass
        temporary.unlink(missing_ok=True)
        raise
