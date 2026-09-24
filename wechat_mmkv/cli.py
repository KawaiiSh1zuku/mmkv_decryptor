from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .discovery import locate_app_directory, validate_store_id
from .errors import MMKVError
from .jsonl_export import export_jsonl
from .storage import dump_storage


def _common(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--store-id",
        "--appid",
        dest="store_id",
        required=True,
        help="MMKV store file name/key identifier (--appid is a compatibility alias)",
    )
    parser.add_argument("--app-dir", type=Path)
    parser.add_argument("--wechat-users-root", type=Path)
    parser.add_argument("--record-offset", type=int)
    parser.add_argument("--iv-offset", type=int, default=12)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Decrypt and mirror local RadiumWMPF MMKV storage."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    locate = subparsers.add_parser("locate", help="locate a matching local store")
    _common(locate)

    dump = subparsers.add_parser("dump", help="decrypt and decode storage entries")
    _common(dump)
    dump.add_argument("--include-adapter", action="store_true")
    dump.add_argument("--output", type=Path)

    jsonl_parser = subparsers.add_parser(
        "export-jsonl", help="export a loss-aware append-history JSONL mirror"
    )
    _common(jsonl_parser)
    jsonl_parser.add_argument("--include-adapter", action="store_true")
    jsonl_parser.add_argument(
        "--output",
        type=Path,
        help="output path (default: <store-id>.jsonl in the current directory)",
    )
    jsonl_parser.add_argument("--overwrite", action="store_true")
    return parser


def _write_result(result: dict[str, object], output: Path | None) -> None:
    encoded = json.dumps(result, ensure_ascii=False, indent=2)
    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(encoded + "\n", encoding="utf-8")
    else:
        print(encoded)


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        store_id = validate_store_id(args.store_id)
        if args.command == "locate":
            app_directory = locate_app_directory(
                store_id,
                app_dir=args.app_dir,
                wechat_users_root=args.wechat_users_root,
            )
            result = {
                "store_id": store_id,
                "app_directory": str(app_directory),
            }
            _write_result(result, None)
            return 0

        if args.command in {"dump", "export-jsonl"}:
            dump = dump_storage(
                store_id,
                app_dir=args.app_dir,
                wechat_users_root=args.wechat_users_root,
                include_adapter=args.include_adapter,
                record_offset=args.record_offset,
                iv_offset=args.iv_offset,
            )
            if args.command == "export-jsonl":
                output = args.output or Path(f"{store_id}.jsonl")
                mirror = export_jsonl(
                    dump, output, overwrite=args.overwrite
                )
                _write_result(
                    {
                        "store_id": dump.store_id,
                        "jsonl": str(mirror),
                        "source_count": len(dump.source_metadata),
                        "record_count": len(dump.records),
                        "current_count": len(dump.entries),
                    },
                    None,
                )
                return 0
            result = {
                "store_id": dump.store_id,
                "app_directory": str(dump.app_directory),
                "entries": dump.entries,
                "entry_types": dump.entry_types,
                "raw_sizes": dump.raw_sizes,
                "sources": dump.sources,
            }
            _write_result(result, args.output)
            return 0

        return 0
    except (MMKVError, OSError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
