from __future__ import annotations

import argparse
import os
from collections.abc import Mapping, Sequence
from pathlib import Path


def _unicode_escape(character: str) -> str:
    code_point = ord(character)
    if code_point <= 0xFFFF:
        return f"\\u{code_point:04X}"
    code_point -= 0x10000
    high_surrogate = 0xD800 + (code_point >> 10)
    low_surrogate = 0xDC00 + (code_point & 0x3FF)
    return f"\\u{high_surrogate:04X}\\u{low_surrogate:04X}"


def _escape(value: str, *, key: bool) -> str:
    escaped: list[str] = []
    for index, character in enumerate(value):
        if character == " ":
            escaped.append("\\ " if key or index == 0 else " ")
        elif character == "\\":
            escaped.append("\\\\")
        elif character == "\t":
            escaped.append("\\t")
        elif character == "\n":
            escaped.append("\\n")
        elif character == "\r":
            escaped.append("\\r")
        elif character == "\f":
            escaped.append("\\f")
        elif character in "=:#!":
            escaped.append(f"\\{character}")
        elif 0x20 <= ord(character) <= 0x7E:
            escaped.append(character)
        else:
            escaped.append(_unicode_escape(character))
    return "".join(escaped)


def serialize_properties(properties: Mapping[str, str]) -> str:
    return "".join(
        f"{_escape(name, key=True)}={_escape(value, key=False)}\n"
        for name, value in properties.items()
    )


def _write_private_properties(path: Path, properties: Mapping[str, str]) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    descriptor = os.open(path, flags, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="ascii", newline="\n") as output:
            descriptor = -1
            output.write(serialize_properties(properties))
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    os.chmod(path, 0o600)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    android_signing = commands.add_parser("android-signing")
    android_signing.add_argument("--output", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _build_parser().parse_args(argv)
    if arguments.command == "android-signing":
        properties = {
            "storeFile": os.environ["KEYSTORE_PATH"],
            "storePassword": os.environ["ANDROID_STORE_PASSWORD"],
            "keyAlias": os.environ["ANDROID_KEY_ALIAS"],
            "keyPassword": os.environ["ANDROID_KEY_PASSWORD"],
        }
        _write_private_properties(arguments.output, properties)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
