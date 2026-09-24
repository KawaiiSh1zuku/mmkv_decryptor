from __future__ import annotations

import struct
import zlib
from dataclasses import dataclass
from pathlib import Path

from Crypto.Cipher import AES

from .errors import MMKVError


DEFAULT_IV_OFFSET = 12
IV_SIZE = 16
MMKV_VERSION_ACTUAL_SIZE = 3


@dataclass(frozen=True)
class MMKVMetadata:
    crc_digest: int
    version: int
    sequence: int
    vector: bytes
    actual_size: int
    last_actual_size: int | None
    last_crc_digest: int | None
    flags: int | None


@dataclass(frozen=True)
class DecryptedStore:
    data_path: Path
    crc_path: Path
    mapped_size: int
    header_actual_size: int
    actual_size: int
    computed_crc32: int
    crc_matches: bool | None
    metadata: MMKVMetadata
    plaintext: bytes


def derive_store_key(store_id: str) -> bytes:
    """Derive the 16-byte RadiumWMPF MMKV key recovered from KVStorageMgr."""
    material = store_id[::2].encode("utf-8")
    if not material:
        raise MMKVError("store ID produced an empty key")
    return material[:16].ljust(16, b"\0")


def derive_appid_key(appid: str) -> bytes:
    """Backward-compatible alias for the original AppID-specific API."""
    return derive_store_key(appid)


def _unpack_u32(data: bytes, offset: int) -> int | None:
    if len(data) < offset + 4:
        return None
    return struct.unpack_from("<I", data, offset)[0]


def read_crc_metadata(
    crc_path: Path, iv_offset: int = DEFAULT_IV_OFFSET
) -> MMKVMetadata:
    metadata = Path(crc_path).read_bytes()
    end = iv_offset + IV_SIZE
    if iv_offset < 0 or len(metadata) < end:
        raise MMKVError(f"CRC metadata is too short for IV at offset {iv_offset}")
    return MMKVMetadata(
        crc_digest=_unpack_u32(metadata, 0) or 0,
        version=_unpack_u32(metadata, 4) or 0,
        sequence=_unpack_u32(metadata, 8) or 0,
        vector=metadata[iv_offset:end],
        actual_size=_unpack_u32(metadata, 28) or 0,
        last_actual_size=_unpack_u32(metadata, 32),
        last_crc_digest=_unpack_u32(metadata, 36),
        flags=(
            struct.unpack_from("<Q", metadata, 104)[0]
            if len(metadata) >= 112
            else None
        ),
    )


def read_crc_iv(crc_path: Path, iv_offset: int = DEFAULT_IV_OFFSET) -> bytes:
    return read_crc_metadata(crc_path, iv_offset).vector


def decrypt_store(
    data_path: Path,
    *,
    store_id: str | None = None,
    appid: str | None = None,
    crc_path: Path | None = None,
    iv_offset: int = DEFAULT_IV_OFFSET,
) -> DecryptedStore:
    if store_id is None:
        store_id = appid
    elif appid is not None and appid != store_id:
        raise MMKVError("store_id and appid refer to different stores")
    if not store_id:
        raise MMKVError("store ID is required")

    data_path = Path(data_path)
    crc_path = Path(crc_path) if crc_path else data_path.with_name(data_path.name + ".crc")
    if not data_path.is_file():
        raise MMKVError(f"MMKV data file not found: {data_path}")
    if not crc_path.is_file():
        raise MMKVError(f"MMKV CRC file not found: {crc_path}")

    mapped = data_path.read_bytes()
    if len(mapped) < 4:
        raise MMKVError(f"MMKV data file is too short: {data_path}")
    header_actual_size = struct.unpack_from("<I", mapped, 0)[0]
    metadata = read_crc_metadata(crc_path, iv_offset)
    actual_size = (
        metadata.actual_size
        if metadata.version >= MMKV_VERSION_ACTUAL_SIZE
        else header_actual_size
    )
    if actual_size <= 0:
        return DecryptedStore(
            data_path=data_path,
            crc_path=crc_path,
            mapped_size=len(mapped),
            header_actual_size=header_actual_size,
            actual_size=actual_size,
            computed_crc32=0,
            crc_matches=(metadata.crc_digest == 0),
            metadata=metadata,
            plaintext=b"",
        )
    if actual_size > len(mapped) - 4:
        raise MMKVError(
            f"MMKV actual size {actual_size} exceeds mapped payload {len(mapped) - 4}"
        )

    key = derive_store_key(store_id)
    ciphertext = mapped[4 : 4 + actual_size]
    computed_crc32 = zlib.crc32(ciphertext) & 0xFFFFFFFF
    plaintext = AES.new(
        key, AES.MODE_CFB, iv=metadata.vector, segment_size=128
    ).decrypt(
        ciphertext
    )
    return DecryptedStore(
        data_path=data_path,
        crc_path=crc_path,
        mapped_size=len(mapped),
        header_actual_size=header_actual_size,
        actual_size=actual_size,
        computed_crc32=computed_crc32,
        crc_matches=(
            computed_crc32 == metadata.crc_digest
            if metadata.crc_digest != 0
            else None
        ),
        metadata=metadata,
        plaintext=plaintext,
    )
