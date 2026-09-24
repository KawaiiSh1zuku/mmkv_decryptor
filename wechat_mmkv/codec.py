from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from .errors import MMKVError


@dataclass(frozen=True)
class DecodedEntry:
    key: str
    value: Any
    data_type: str
    raw_size: int
    raw_value: bytes
    raw_record: bytes
    record_index: int
    record_offset: int
    key_offset: int
    value_offset: int
    end_offset: int
    deleted: bool


@dataclass(frozen=True)
class ParsedMMKVRecords:
    record_offset: int
    records: tuple[DecodedEntry, ...]


def decode_varint(data: bytes, offset: int) -> tuple[int, int]:
    value = 0
    shift = 0
    for _ in range(10):
        if offset >= len(data):
            raise MMKVError("truncated varint")
        byte = data[offset]
        offset += 1
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return value, offset
        shift += 7
    raise MMKVError("varint exceeds 10 bytes")


def encode_varint(value: int) -> bytes:
    if value < 0:
        raise ValueError("varint value must be non-negative")
    output = bytearray()
    while value >= 0x80:
        output.append((value & 0x7F) | 0x80)
        value >>= 7
    output.append(value)
    return bytes(output)


def _decode_length_delimited(data: bytes) -> str | None:
    try:
        length, offset = decode_varint(data, 0)
    except MMKVError:
        return None
    if offset + length != len(data):
        return None
    try:
        return data[offset:].decode("utf-8")
    except UnicodeDecodeError:
        return None


def _coerce_wrapped_value(wrapper: dict[str, Any]) -> tuple[Any, str]:
    data_type = str(wrapper.get("dataType", "JSON"))
    value = wrapper.get("data")
    lowered = data_type.lower()
    if isinstance(value, str) and lowered in {"array", "object", "json"}:
        try:
            value = json.loads(value)
        except json.JSONDecodeError:
            pass
    elif isinstance(value, str) and lowered in {"boolean", "bool"}:
        value = value.lower() == "true"
    elif isinstance(value, str) and lowered in {"number", "int", "float", "double"}:
        try:
            value = float(value) if any(ch in value for ch in ".eE") else int(value)
        except ValueError:
            pass
    return value, data_type


def decode_wechat_value(data: bytes) -> tuple[Any, str]:
    text = _decode_length_delimited(data)
    if text is None:
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            return data.hex(), "bytes"
    try:
        decoded = json.loads(text)
    except json.JSONDecodeError:
        return text, "String"
    if isinstance(decoded, dict) and "data" in decoded and "dataType" in decoded:
        return _coerce_wrapped_value(decoded)
    return decoded, "JSON"


def _parse_from_offset(data: bytes, start: int) -> tuple[list[DecodedEntry], int]:
    offset = start
    entries: list[DecodedEntry] = []
    while offset < len(data):
        if not any(data[offset:]):
            break
        record_start = offset
        key_size, offset = decode_varint(data, offset)
        if key_size <= 0 or key_size > 4096 or offset + key_size > len(data):
            raise MMKVError(f"invalid key size {key_size} at offset {offset}")
        key_offset = offset
        key_bytes = data[offset : offset + key_size]
        offset += key_size
        try:
            key = key_bytes.decode("utf-8")
        except UnicodeDecodeError as error:
            raise MMKVError(f"invalid UTF-8 key at offset {offset - key_size}") from error
        if not key or not all(character.isprintable() for character in key):
            raise MMKVError(f"non-printable MMKV key at offset {offset - key_size}")

        value_size, offset = decode_varint(data, offset)
        if value_size > len(data) - offset:
            raise MMKVError(f"truncated value for key {key!r}")
        value_offset = offset
        raw_value = data[offset : offset + value_size]
        offset += value_size
        deleted = value_size == 0
        value, data_type = (
            (None, "deleted") if deleted else decode_wechat_value(raw_value)
        )
        entries.append(
            DecodedEntry(
                key=key,
                value=value,
                data_type=data_type,
                raw_size=value_size,
                raw_value=raw_value,
                raw_record=data[record_start:offset],
                record_index=len(entries),
                record_offset=record_start,
                key_offset=key_offset,
                value_offset=value_offset,
                end_offset=offset,
                deleted=deleted,
            )
        )
    return entries, offset


def parse_mmkv_history(
    plaintext: bytes, *, record_offset: int | None = None
) -> ParsedMMKVRecords:
    if not plaintext:
        return ParsedMMKVRecords(record_offset=record_offset or 0, records=())
    offsets = [record_offset] if record_offset is not None else [4, 0, 1, 2, 3, 5, 6, 7, 8]
    candidates: list[tuple[int, int, int, list[DecodedEntry]]] = []
    for offset in offsets:
        if offset is None or offset < 0 or offset >= len(plaintext):
            continue
        try:
            entries, consumed = _parse_from_offset(plaintext, offset)
        except MMKVError:
            continue
        if entries:
            candidates.append((len(entries), consumed, offset, entries))
    if not candidates:
        raise MMKVError("no valid MMKV records found")

    _, _, selected_offset, selected = max(
        candidates, key=lambda item: (item[0], item[1])
    )
    return ParsedMMKVRecords(selected_offset, tuple(selected))


def parse_mmkv_records(
    plaintext: bytes, *, record_offset: int | None = None
) -> dict[str, DecodedEntry]:
    history = parse_mmkv_history(plaintext, record_offset=record_offset)
    latest: dict[str, DecodedEntry] = {}
    for entry in history.records:
        if entry.deleted:
            latest.pop(entry.key, None)
        else:
            latest[entry.key] = entry
    return latest
