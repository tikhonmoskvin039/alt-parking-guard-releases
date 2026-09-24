"""Fail-closed Guard submission and separately authorized manual publication.

APK package/version and certificate verification belongs to the protected
controller. This module binds those verified values to local bytes and the
immutable manifest/receipt; the API does not expose an APK or certificate hash.
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import math
import os
import re
import sys
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import BinaryIO, cast

try:  # Support both `python -m tool.rustore_release` and the controller script.
    from .rustore_api import (
        PACKAGE_NAME, OpenSslSignatureProvider, RustoreApiClient, RustoreApiError,
        RustoreMutationUnresolved, RustoreVersion, StdlibHttpTransport,
    )
except ImportError:
    from rustore_api import (  # type: ignore[no-redef]
        PACKAGE_NAME, OpenSslSignatureProvider, RustoreApiClient, RustoreApiError,
        RustoreMutationUnresolved, RustoreVersion, StdlibHttpTransport,
    )


PENDING = frozenset({"AUTO_CHECK", "TAKEN_FOR_MODERATION", "MODERATION"})
READY = "READY_FOR_PUBLICATION"
LIVE = frozenset({"ACTIVE", "PARTIAL_ACTIVE"})
REJECTED = frozenset({"AUTO_CHECK_FAILED", "REJECTED_BY_MODERATOR", "REJECTED_BY_SECURITY"})
HISTORICAL = frozenset({"PREVIOUS_ACTIVE", "ARCHIVED", "DELETED_DRAFT"})
KNOWN = PENDING | LIVE | REJECTED | HISTORICAL | {READY, "DRAFT"}


class ReleaseError(RuntimeError):
    """Only fixed, nonsecret diagnostic text may be supplied."""


@dataclass(frozen=True)
class ReleaseRequest:
    package_name: str
    tag: str
    version_name: str
    version_code: int
    source_sha: str
    apk_sha256: str
    signer_sha256: str
    apk_path: Path


@dataclass(frozen=True)
class SubmissionReceipt:
    package_name: str
    tag: str
    version_name: str
    version_code: int
    version_id: int
    source_sha: str
    apk_sha256: str
    signer_sha256: str
    publish_type: str
    partial_value: int
    status: str
    submitted_at: str

    def to_bytes(self) -> bytes:
        _validate_receipt(self)
        return (json.dumps({
            "packageName": self.package_name, "tag": self.tag,
            "versionName": self.version_name, "versionCode": self.version_code,
            "versionId": self.version_id, "sourceSha": self.source_sha,
            "apkSha256": self.apk_sha256, "signerSha256": self.signer_sha256,
            "publishType": self.publish_type, "partialValue": self.partial_value,
            "status": self.status, "submittedAt": self.submitted_at,
        }, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode("ascii")


def _hex(value: object, length: int) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{" + str(length) + "}", value) is not None


def _positive(value: object) -> bool:
    return type(value) is int and value > 0


def _validate_identity(value: ReleaseRequest | SubmissionReceipt) -> None:
    if (value.package_name != PACKAGE_NAME or not isinstance(value.version_name, str)
            or re.fullmatch(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)", value.version_name) is None
            or value.tag != "v" + value.version_name or not _positive(value.version_code)
            or not _hex(value.source_sha, 40) or not _hex(value.apk_sha256, 64)
            or not _hex(value.signer_sha256, 64)):
        raise ReleaseError("Invalid Guard release identity")


def _validate_request(request: ReleaseRequest) -> None:
    _validate_identity(request)
    try:
        if not isinstance(request.apk_path, Path) or request.apk_path.suffix != ".apk":
            raise ReleaseError("Verified APK required")
        with request.apk_path.open("rb") as apk:
            digest = hashlib.file_digest(apk, "sha256").hexdigest()
        if not hmac.compare_digest(digest, request.apk_sha256):
            raise ReleaseError("Local APK checksum mismatch")
    except OSError:
        raise ReleaseError("Cannot read verified APK") from None


def _validate_receipt(receipt: SubmissionReceipt) -> None:
    _validate_identity(receipt)
    if (not _positive(receipt.version_id) or receipt.publish_type != "MANUAL"
            or type(receipt.partial_value) is not int or receipt.partial_value != 100
            or not isinstance(receipt.status, str) or receipt.status not in PENDING | {READY}):
        raise ReleaseError("Invalid submission receipt policy or state")
    try:
        stamp = datetime.fromisoformat(receipt.submitted_at)
        if stamp.tzinfo != timezone.utc or stamp.isoformat(timespec="milliseconds") != receipt.submitted_at:
            raise ValueError()
    except (TypeError, ValueError):
        raise ReleaseError("Invalid receipt timestamp") from None


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for name, value in pairs:
        if name in result:
            raise ReleaseError("Duplicate JSON field")
        result[name] = value
    return result


def _load_object(raw: bytes) -> dict[str, object]:
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object)
        if not isinstance(value, dict):
            raise ValueError()
        return cast(dict[str, object], value)
    except (UnicodeError, ValueError):
        raise ReleaseError("Invalid release JSON") from None


def parse_receipt(raw: bytes, expected_sha256: str) -> SubmissionReceipt:
    if (not _hex(expected_sha256, 64)
            or not hmac.compare_digest(hashlib.sha256(raw).hexdigest(), expected_sha256)):
        raise ReleaseError("Submission receipt checksum mismatch")
    data = _load_object(raw)
    names = ("packageName", "tag", "versionName", "versionCode", "versionId", "sourceSha",
             "apkSha256", "signerSha256", "publishType", "partialValue", "status", "submittedAt")
    if set(data) != set(names):
        raise ReleaseError("Invalid receipt fields")
    receipt = SubmissionReceipt(
        cast(str, data["packageName"]), cast(str, data["tag"]), cast(str, data["versionName"]),
        cast(int, data["versionCode"]), cast(int, data["versionId"]), cast(str, data["sourceSha"]),
        cast(str, data["apkSha256"]), cast(str, data["signerSha256"]), cast(str, data["publishType"]),
        cast(int, data["partialValue"]), cast(str, data["status"]), cast(str, data["submittedAt"]),
    )
    if receipt.to_bytes() != raw:
        raise ReleaseError("Receipt is not canonical JSON")
    return receipt


def request_from_manifest(
    manifest_path: Path, apk_path: Path, tag: str, source_sha: str, signer_sha256: str,
) -> ReleaseRequest:
    data = _load_object(manifest_path.read_bytes())
    if data.get("sourceCommit") != source_sha:
        raise ReleaseError("Manifest source does not match requested source")
    request = ReleaseRequest(
        cast(str, data.get("packageId")), tag, cast(str, data.get("versionName")),
        cast(int, data.get("buildNumber")), source_sha, cast(str, data.get("apkSha256")),
        signer_sha256, apk_path,
    )
    _validate_request(request)
    return request


def _remote(version: RustoreVersion, request: ReleaseRequest, version_id: int) -> RustoreVersion:
    if (version.version_id != version_id or version.version_name != request.version_name
            or version.version_code != request.version_code or version.publish_type != "MANUAL"
            or version.partial_value != 100 or version.version_status not in KNOWN):
        raise ReleaseError("Saved RuStore version identity, policy or status mismatch")
    return version


def _poll(
    read: Callable[[], RustoreVersion], *, publish: bool, clock: Callable[[], float],
    sleep: Callable[[float], None], timeout_seconds: float, poll_interval: float,
    initial: RustoreVersion | None = None,
) -> RustoreVersion:
    _poll_settings(timeout_seconds, poll_interval)
    deadline = clock() + timeout_seconds
    # Also bound iteration count if an injected/system clock stops advancing.
    for attempt in range(math.ceil(timeout_seconds / poll_interval) + 1):
        current = initial if attempt == 0 and initial is not None else read()
        status = current.version_status
        if status == ("ACTIVE" if publish else READY):
            return current
        if status not in ({READY} if publish else PENDING):
            raise ReleaseError("RuStore state requires operator attention")
        remaining = deadline - clock()
        if remaining <= 0 or attempt == math.ceil(timeout_seconds / poll_interval):
            if publish:
                raise ReleaseError("Publication not confirmed ACTIVE before deadline")
            return current
        sleep(min(poll_interval, remaining))
    raise ReleaseError("RuStore polling unresolved")


def _poll_settings(timeout_seconds: float, poll_interval: float) -> None:
    if any(type(value) not in (int, float) or not math.isfinite(value) or value <= 0
           for value in (timeout_seconds, poll_interval)):
        raise ReleaseError("Invalid polling bounds")


def _submission_timestamp(instant: float) -> str:
    try:
        return datetime.fromtimestamp(instant, timezone.utc).isoformat(timespec="milliseconds")
    except (ValueError, OverflowError, OSError, TypeError):
        raise ReleaseError("Invalid submission clock") from None


def submit_for_moderation(
    api: RustoreApiClient, request: ReleaseRequest, *, clock: Callable[[], float],
    sleep: Callable[[float], None], timeout_seconds: float = 300, poll_interval: float = 10,
) -> SubmissionReceipt:
    _validate_request(request)
    _poll_settings(timeout_seconds, poll_interval)
    submitted_at = _submission_timestamp(clock())
    versions = api.list_versions(request.package_name)
    if any(item.version_status not in KNOWN for item in versions):
        raise ReleaseError("Unknown remote release state")
    if not any(item.version_status == "ACTIVE" for item in versions):
        raise ReleaseError("An ACTIVE console bootstrap release is required")
    drafts = [item for item in versions if item.version_status == "DRAFT"]
    candidates = [item for item in versions if item.version_name == request.version_name
                  or item.version_code == request.version_code]
    if len(drafts) > 1 or len(candidates) > 1:
        raise ReleaseError("Multiple or ambiguous RuStore versions")
    if drafts:
        # Version metadata is not evidence of APK bytes. Never repeat an upload
        # on a draft left by a previous run, even when its name/code match.
        raise ReleaseError("Existing draft upload cannot be proven; operator attention required")
    if candidates:
        # Matching metadata cannot prove which APK/source created this version.
        raise ReleaseError("Pre-existing release requires its original trusted receipt")
    else:
        try:
            version_id = api.create_manual_draft(request.package_name)
        except RustoreMutationUnresolved:
            # The API has no ownership/idempotency token: even one new matching
            # draft may belong to a concurrent operator or another runner.
            raise ReleaseError("Draft creation unresolved; operator reconciliation required") from None
        if version_id in {item.version_id for item in versions}:
            raise ReleaseError("Creation returned a pre-existing version ID")
        initial = api.get_version(request.package_name, version_id)
        # Before the first upload only ownership (the returned new ID) and
        # policy are knowable; name/code can still describe the previous APK.
        if (initial.version_id != version_id or initial.publish_type != "MANUAL"
                or initial.partial_value != 100 or initial.version_status != "DRAFT"):
            raise ReleaseError("Created draft is not in the expected state")
        _validate_request(request)
        try:
            api.upload_main_apk(request.package_name, version_id, request.apk_path)
        except RustoreMutationUnresolved:
            _validate_request(request)
            initial = _remote(api.get_version(request.package_name, version_id), request, version_id)
            if initial.version_status not in PENDING | {READY}:
                raise ReleaseError("APK upload unresolved; draft metadata cannot prove bytes") from None
        else:
            _validate_request(request)
            uploaded = _remote(api.get_version(request.package_name, version_id), request, version_id)
            if uploaded.version_status != "DRAFT":
                raise ReleaseError("Uploaded draft changed state before commit")
            _validate_request(request)
            try:
                api.commit_for_moderation(request.package_name, version_id)
            except RustoreMutationUnresolved:
                pass  # Only an advanced exact-ID read can establish commit success.
            initial = _remote(api.get_version(request.package_name, version_id), request, version_id)
    current = _poll(
        lambda: _remote(api.get_version(request.package_name, version_id), request, version_id),
        publish=False, clock=clock, sleep=sleep, timeout_seconds=timeout_seconds,
        poll_interval=poll_interval, initial=initial,
    )
    return SubmissionReceipt(
        request.package_name, request.tag, request.version_name, request.version_code, version_id,
        request.source_sha, request.apk_sha256, request.signer_sha256, "MANUAL", 100,
        current.version_status, submitted_at,
    )


def _bound_receipt(request: ReleaseRequest, raw: bytes, checksum: str) -> SubmissionReceipt:
    receipt = parse_receipt(raw, checksum)
    _validate_request(request)
    fields = ("package_name", "tag", "version_name", "version_code", "source_sha", "apk_sha256", "signer_sha256")
    if any(getattr(receipt, field) != getattr(request, field) for field in fields):
        raise ReleaseError("Receipt does not match verified local release")
    return receipt


def status_from_receipt(
    api: RustoreApiClient, request: ReleaseRequest, receipt_bytes: bytes, receipt_sha256: str,
) -> RustoreVersion:
    receipt = _bound_receipt(request, receipt_bytes, receipt_sha256)
    return _remote(api.get_version(receipt.package_name, receipt.version_id), request, receipt.version_id)


def _validate_confirmation(receipt: SubmissionReceipt, confirmation: str) -> None:
    expected = f"PUBLISH {receipt.package_name} {receipt.tag} {receipt.version_id}"
    if confirmation != expected:
        raise ReleaseError("Exact publication confirmation required")


def publish_from_receipt(
    api: RustoreApiClient, request: ReleaseRequest, *, receipt_bytes: bytes, receipt_sha256: str,
    confirmation: str, clock: Callable[[], float], sleep: Callable[[float], None],
    timeout_seconds: float = 300, poll_interval: float = 10,
    before_publish: Callable[[], None] | None = None,
) -> RustoreVersion:
    receipt = _bound_receipt(request, receipt_bytes, receipt_sha256)
    _poll_settings(timeout_seconds, poll_interval)
    _validate_confirmation(receipt, confirmation)
    read = lambda: _remote(api.get_version(receipt.package_name, receipt.version_id), request, receipt.version_id)
    if read().version_status != READY:
        raise ReleaseError("Manual publication requires exact READY_FOR_PUBLICATION")
    _validate_request(request)
    if before_publish is not None:
        before_publish()
    try:
        api.publish_manual(receipt.package_name, receipt.version_id)
    except RustoreMutationUnresolved:
        pass  # Never repeat publish. The same ID must become exactly ACTIVE.
    return _poll(read, publish=True, clock=clock, sleep=sleep,
                 timeout_seconds=timeout_seconds, poll_interval=poll_interval)


def client_for_mode(mode: str) -> RustoreApiClient:
    if mode not in ("submit", "status", "publish"):
        raise ReleaseError("Unknown release mode")
    prefix = "RUSTORE_SUBMIT" if mode == "submit" else "RUSTORE_PUBLISH"
    key_id = os.environ.get(prefix + "_KEY_ID", "")
    private_env = prefix + "_PRIVATE_KEY_PKCS8_BASE64"
    if not key_id.strip() or not os.environ.get(private_env, "").strip():
        raise ReleaseError("Mode-specific RuStore credentials are required")
    return RustoreApiClient(key_id, OpenSslSignatureProvider(private_env), StdlibHttpTransport())


def _sync_write(output: BinaryIO, content: bytes) -> None:
    output.seek(0)
    output.write(content)
    output.truncate()
    output.flush()
    os.fsync(output.fileno())


def _checkpoint(request: ReleaseRequest, operation: str) -> bytes:
    # A single durable fence covers the entire attempt. A crash at any stage
    # requires operator reconciliation, rather than replaying intermediate POSTs.
    return (json.dumps({"operation": operation, "state": "UNRESOLVED",
                        "packageName": request.package_name, "tag": request.tag,
                        "sourceSha": request.source_sha, "apkSha256": request.apk_sha256},
                       sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")


def _sync_parent(path: Path) -> None:
    if os.name != "posix":
        return
    try:
        descriptor = os.open(str(path.parent), os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    except OSError:
        raise ReleaseError("Cannot durably sync release directory") from None


def _write_durable(path: Path, content: bytes, *, exclusive: bool) -> None:
    try:
        with path.open("xb" if exclusive else "wb") as output:
            _sync_write(output, content)
        # The new directory entry must survive a crash before any POST. Closing
        # the marker first also makes a delayed write/close failure fail closed.
        _sync_parent(path)
    except OSError:
        raise ReleaseError("Cannot durably write release checkpoint") from None


def _publish_checkpoint(path: Path, request: ReleaseRequest) -> None:
    _write_durable(path, _checkpoint(request, "publish"), exclusive=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for command in ("submit", "status", "publish"):
        sub = commands.add_parser(command)
        for name in ("manifest", "apk"):
            sub.add_argument("--" + name, required=True, type=Path)
        for name in ("tag", "source-sha", "signer-sha256"):
            sub.add_argument("--" + name, required=True)
        if command == "submit":
            sub.add_argument("--output", required=True, type=Path)
        else:
            sub.add_argument("--receipt", required=True, type=Path)
            sub.add_argument("--receipt-sha256", required=True)
        if command == "publish":
            sub.add_argument("--confirmation", required=True)
    args = parser.parse_args(argv)
    try:
        request = request_from_manifest(args.manifest, args.apk, args.tag, args.source_sha, args.signer_sha256)
        if args.command == "submit":
            _poll_settings(300, 10)
            _submission_timestamp(time.time())
            # Reserve a new output before mutations; do not overwrite a receipt.
            _write_durable(args.output, _checkpoint(request, "submit"), exclusive=True)
            receipt = submit_for_moderation(client_for_mode("submit"), request, clock=time.time, sleep=time.sleep)
            _write_durable(args.output, receipt.to_bytes(), exclusive=False)
        else:
            raw = args.receipt.read_bytes()
            receipt = _bound_receipt(request, raw, args.receipt_sha256)
            if args.command == "publish":
                _poll_settings(300, 10)
                _validate_confirmation(receipt, args.confirmation)
            if args.command == "status":
                result = status_from_receipt(client_for_mode("status"), request, raw, args.receipt_sha256)
            else:
                result = publish_from_receipt(
                    client_for_mode("publish"), request, receipt_bytes=raw,
                    receipt_sha256=args.receipt_sha256, confirmation=args.confirmation,
                    clock=time.time, sleep=time.sleep,
                    before_publish=lambda: _publish_checkpoint(
                        args.receipt.with_name(args.receipt.name + ".publish-attempt.json"), request,
                    ),
                )
            print(json.dumps({"versionId": result.version_id, "status": result.version_status}, sort_keys=True))
    except (ReleaseError, RustoreApiError, OSError, ValueError):
        print("RuStore release validation or operation failed; operator attention required", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
