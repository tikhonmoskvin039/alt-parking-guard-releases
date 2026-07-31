from __future__ import annotations

import argparse
import json
from collections.abc import Iterable, Sequence
from pathlib import Path


class ReleaseStateError(RuntimeError):
    pass


def select_release_state(tag: str, pages: Iterable[object]) -> str:
    matching_draft_states: list[bool] = []
    seen_release_ids: set[int] = set()
    for page in pages:
        if not isinstance(page, list):
            raise ReleaseStateError("release API page must be a JSON array")
        for release in page:
            if not isinstance(release, dict):
                raise ReleaseStateError("release API item must be a JSON object")
            release_id = release.get("id")
            if not isinstance(release_id, int) or isinstance(release_id, bool):
                raise ReleaseStateError("release API id must be an integer")
            if release_id in seen_release_ids:
                raise ReleaseStateError(
                    f"pagination returned duplicate release id {release_id}"
                )
            seen_release_ids.add(release_id)
            release_tag = release.get("tag_name")
            if not isinstance(release_tag, str):
                raise ReleaseStateError("release API tag_name must be a string")
            if release_tag != tag:
                continue
            draft = release.get("draft")
            if not isinstance(draft, bool):
                raise ReleaseStateError("matching release draft must be a boolean")
            matching_draft_states.append(draft)

    if not matching_draft_states:
        return "absent"
    if len(matching_draft_states) != 1:
        raise ReleaseStateError(f"multiple releases match tag '{tag}'")
    return "draft" if matching_draft_states[0] else "published"


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    select = commands.add_parser("select")
    select.add_argument("--tag", required=True)
    select.add_argument("pages", type=Path, nargs="+")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    arguments = parser.parse_args(argv)
    try:
        pages = [
            json.loads(path.read_text(encoding="utf-8"))
            for path in arguments.pages
        ]
        state = select_release_state(arguments.tag, pages)
    except (OSError, json.JSONDecodeError, ReleaseStateError) as error:
        parser.error(str(error))
    print(state)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
