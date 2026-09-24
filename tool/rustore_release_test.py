"""Offline release decisions; fixtures model the public API boundary only."""
from __future__ import annotations

import contextlib
import hashlib
import io
import json
import os
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from tool.rustore_api import HttpResponse, RustoreApiClient, RustoreApiError, RustoreMutationUnresolved, RustoreVersion
from tool.rustore_api_test import (
    BASE, Clock as ApiClock, RecordingSigner, ScriptedTransport,
    ok, page, response, version as api_version,
)
from tool.rustore_release import (
    ReleaseError, ReleaseRequest, SubmissionReceipt, client_for_mode,
    main, parse_receipt, publish_from_receipt, request_from_manifest,
    status_from_receipt, submit_for_moderation,
)


PACKAGE = "ru.altparking.guard"
SOURCE = "a" * 40
SIGNER = "b" * 64
# The SHA-256 of the literal three-byte artifact b"abc" is independently known.
APK_HASH = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
PENDING = ("AUTO_CHECK", "TAKEN_FOR_MODERATION", "MODERATION")
STOP = ("ACTIVE", "PARTIAL_ACTIVE", "PREVIOUS_ACTIVE", "ARCHIVED",
        "REJECTED_BY_MODERATOR", "AUTO_CHECK_FAILED", "DELETED_DRAFT",
        "REJECTED_BY_SECURITY", "NEW_UNKNOWN_STATUS")


def version(status: str, **changes: object) -> RustoreVersion:
    return replace(RustoreVersion(42, "0.1.11", 12, status, "MANUAL", 100), **changes)


ACTIVE = RustoreVersion(9, "0.1.10", 11, "ACTIVE", "MANUAL", 100)


class ApiFixture:
    """Single-shot operations and explicitly queued read-only snapshots."""

    def __init__(self, *, lists: list[tuple[RustoreVersion, ...]] | None = None,
                 reads: list[RustoreVersion] | None = None,
                 unresolved: str | None = None) -> None:
        self.lists = lists if lists is not None else [(ACTIVE,)]
        self.reads = reads if reads is not None else [version("DRAFT"), version("DRAFT"), version("READY_FOR_PUBLICATION")]
        self.unresolved = unresolved
        self.events: list[tuple[object, ...]] = []

    def list_versions(self, package: str, *, statuses: tuple[str, ...] = ()) -> tuple[RustoreVersion, ...]:
        self.events.append(("list", package, statuses))
        if len(self.lists) > 1:
            return self.lists.pop(0)
        return self.lists[0]

    def get_version(self, package: str, version_id: int) -> RustoreVersion:
        self.events.append(("get", package, version_id))
        if len(self.reads) > 1:
            return self.reads.pop(0)
        return self.reads[0]

    def mutate(self, action: str, *args: object) -> None:
        self.events.append((action, *args))
        if action == self.unresolved:
            raise RustoreMutationUnresolved()

    def create_manual_draft(self, package: str) -> int:
        self.mutate("create", package)
        return 42

    def upload_main_apk(self, package: str, version_id: int, apk: Path) -> None:
        self.mutate("upload", package, version_id, apk.read_bytes())

    def commit_for_moderation(self, package: str, version_id: int) -> None:
        self.mutate("commit", package, version_id)

    def publish_manual(self, package: str, version_id: int) -> None:
        self.mutate("publish", package, version_id)

    @property
    def mutations(self) -> list[str]:
        return [str(event[0]) for event in self.events if event[0] not in ("list", "get")]


class Clock:
    def __init__(self) -> None:
        self.value = 0.0
        self.sleeps: list[float] = []

    def now(self) -> float:
        return self.value

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.value += seconds


class ReleaseTest(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.apk = Path(self.directory.name) / "guard.apk"
        self.apk.write_bytes(b"abc")
        self.request = ReleaseRequest(PACKAGE, "v0.1.11", "0.1.11", 12, SOURCE, APK_HASH, SIGNER, self.apk)
        self.clock = Clock()
        self.receipt_data = {
            "packageName": PACKAGE, "tag": "v0.1.11", "versionName": "0.1.11", "versionCode": 12,
            "versionId": 42, "sourceSha": SOURCE, "apkSha256": APK_HASH, "signerSha256": SIGNER,
            "publishType": "MANUAL", "partialValue": 100, "status": "READY_FOR_PUBLICATION",
            "submittedAt": "1970-01-01T00:00:00.000+00:00",
        }
        self.raw = (json.dumps(self.receipt_data, sort_keys=True, separators=(",", ":")) + "\n").encode()
        self.checksum = hashlib.sha256(self.raw).hexdigest()

    def submit(self, api: ApiFixture | RustoreApiClient) -> SubmissionReceipt:
        return submit_for_moderation(api, self.request, clock=self.clock.now, sleep=self.clock.sleep,
                                     timeout_seconds=20, poll_interval=10)

    def publish(self, api: ApiFixture, **changes: object) -> RustoreVersion:
        arguments = dict(receipt_bytes=self.raw, receipt_sha256=self.checksum,
                         confirmation="PUBLISH ru.altparking.guard v0.1.11 42",
                         clock=self.clock.now, sleep=self.clock.sleep, timeout_seconds=20, poll_interval=10)
        arguments.update(changes)
        return publish_from_receipt(api, self.request, **arguments)

    def test_missing_exact_active_bootstrap_stops_before_every_mutation(self) -> None:
        for existing in ((), (replace(ACTIVE, version_status="PARTIAL_ACTIVE"),)):
            api = ApiFixture(lists=[existing])
            with self.assertRaises(ReleaseError):
                self.submit(api)
            self.assertEqual(api.mutations, [])

    def test_zero_drafts_creates_uploads_commits_and_never_publishes(self) -> None:
        api = ApiFixture()
        receipt = self.submit(api)
        self.assertEqual(receipt.to_bytes(), self.raw)
        self.assertEqual(api.mutations, ["create", "upload", "commit"])
        self.assertIn(("upload", PACKAGE, 42, b"abc"), api.events)
        self.assertEqual(api.events[0], ("list", PACKAGE, ()))

    def test_foreign_multiple_or_unproven_existing_drafts_never_mutate(self) -> None:
        for drafts in (
            (version("DRAFT", version_code=99),),
            (version("DRAFT", publish_type="INSTANTLY"),),
            (version("DRAFT"), version("DRAFT", version_id=43)),
            (version("DRAFT"),),
        ):
            with self.subTest(drafts=drafts):
                api = ApiFixture(lists=[(ACTIVE, *drafts)])
                with self.assertRaises(ReleaseError):
                    self.submit(api)
                self.assertEqual(api.mutations, [])

    def test_existing_exact_pending_or_ready_cannot_acquire_this_invocations_provenance(self) -> None:
        for status in (*PENDING, "READY_FOR_PUBLICATION"):
            api = ApiFixture(lists=[(ACTIVE, version(status))], reads=[version(status)])
            with self.subTest(status=status), self.assertRaises(ReleaseError):
                self.submit(api)
            self.assertEqual(api.mutations, [])

    def test_foreign_draft_blocks_even_an_existing_exact_ready_version(self) -> None:
        api = ApiFixture(lists=[(ACTIVE, version("READY_FOR_PUBLICATION"), version("DRAFT", version_id=43))])
        with self.assertRaises(ReleaseError):
            self.submit(api)
        self.assertEqual(api.mutations, [])

    def test_create_timeout_cannot_adopt_a_new_matching_manual_draft(self) -> None:
        api = ApiFixture(lists=[(ACTIVE,), (ACTIVE, version("DRAFT"))], unresolved="create")
        receipt = None
        with self.assertRaisesRegex(ReleaseError, "operator"):
            receipt = self.submit(api)
        self.assertIsNone(receipt)
        self.assertEqual(api.mutations, ["create"])

    def test_real_client_bodyless_upload_and_commit_produce_receipt(self) -> None:
        active = {**api_version(9), "versionName": "0.1.10", "versionCode": 11}
        draft = {**api_version(42, "DRAFT"), "versionCode": 12}
        transport = ScriptedTransport(
            ok({"jwe": "test-jwe", "ttl": 900}), page([active]), ok(42), page([draft]),
            response({"code": "OK", "message": None, "timestamp": "2026-09-23T09:10:11.123+00:00"}),
            page([draft]), response({"code": "OK"}),
            page([{**draft, "versionStatus": "READY_FOR_PUBLICATION"}]),
        )
        client = RustoreApiClient("key-42", RecordingSigner(), transport, now=ApiClock())
        self.assertEqual(self.submit(client).to_bytes(), self.raw)
        self.assertEqual([request.url for request in transport.requests if request.method == "POST"], [
            BASE + "/public/auth/",
            BASE + "/public/v1/application/ru.altparking.guard/version",
            BASE + "/public/v1/application/ru.altparking.guard/version/42/apk?isMainApk=true&servicesType=Unknown",
            BASE + "/public/v1/application/ru.altparking.guard/version/42/commit?priorityUpdate=0",
        ])
        self.assertEqual(transport.replies, [])

    def test_real_client_unresolved_or_rejected_create_never_adopts_concurrent_draft(self) -> None:
        active = {**api_version(9), "versionName": "0.1.10", "versionCode": 11}
        # This matching draft could have been created and uploaded by another
        # operator; list delta and APK metadata cannot establish ownership.
        draft = {**api_version(42, "DRAFT"), "versionCode": 12}
        for reply, expected_error in (
            (TimeoutError("raw transport secret"), ReleaseError),
            (HttpResponse(200, b"invalid"), ReleaseError),
            (HttpResponse(400, b"raw rejection secret"), RustoreApiError),
            (HttpResponse(409, b"raw rejection secret"), RustoreApiError),
            (response({"code": "ERROR", "message": "raw rejection secret"}), RustoreApiError),
        ):
            with self.subTest(reply=reply):
                transport = ScriptedTransport(
                    ok({"jwe": "test-jwe", "ttl": 900}), page([active]), reply,
                    page([active, draft]), page([draft]), ok(None), page([draft]), ok(None),
                    page([{**draft, "versionStatus": "READY_FOR_PUBLICATION"}]),
                )
                client = RustoreApiClient("key-42", RecordingSigner(), transport, now=ApiClock())
                receipt = None
                with self.assertRaises(expected_error) as caught:
                    receipt = self.submit(client)
                self.assertIs(type(caught.exception), expected_error)
                self.assertIsNone(receipt)
                self.assertEqual(len(transport.requests), 3)
                self.assertEqual(transport.requests[-1].url,
                                 BASE + "/public/v1/application/ru.altparking.guard/version")

    def test_create_timeout_foreign_multiple_or_missing_draft_is_not_retried(self) -> None:
        for after in ((ACTIVE,), (ACTIVE, version("DRAFT", version_name="0.1.99")),
                      (ACTIVE, version("DRAFT"), version("DRAFT", version_id=43))):
            api = ApiFixture(lists=[(ACTIVE,), after], unresolved="create")
            with self.assertRaises(ReleaseError):
                self.submit(api)
            self.assertEqual(api.mutations, ["create"])

    def test_upload_timeout_in_draft_cannot_prove_bytes_and_never_commits(self) -> None:
        api = ApiFixture(reads=[version("DRAFT")], unresolved="upload")
        with self.assertRaises(ReleaseError):
            self.submit(api)
        self.assertEqual(api.mutations, ["create", "upload"])

    def test_upload_timeout_reconciles_advanced_state_without_commit(self) -> None:
        api = ApiFixture(reads=[version("DRAFT"), version("MODERATION"), version("READY_FOR_PUBLICATION")],
                         unresolved="upload")
        self.assertEqual(self.submit(api).status, "READY_FOR_PUBLICATION")
        self.assertEqual(api.mutations, ["create", "upload"])

    def test_changed_apk_after_ambiguous_upload_stops_before_remote_reconciliation(self) -> None:
        for status in (*PENDING, "READY_FOR_PUBLICATION"):
            self.apk.write_bytes(b"abc")
            api = ApiFixture(reads=[version("DRAFT"), version(status)])
            def upload(package: str, version_id: int, apk: Path) -> None:
                apk.write_bytes(b"changed")
                raise RustoreMutationUnresolved()
            with patch.object(api, "upload_main_apk", side_effect=upload), self.assertRaises(ReleaseError):
                self.submit(api)
            self.assertEqual([event for event in api.events if event[0] == "get"], [("get", PACKAGE, 42)])
            self.assertNotIn("commit", api.mutations)

    def test_commit_timeout_in_draft_stops_without_a_second_commit(self) -> None:
        api = ApiFixture(reads=[version("DRAFT")], unresolved="commit")
        with self.assertRaises(ReleaseError):
            self.submit(api)
        self.assertEqual(api.mutations, ["create", "upload", "commit"])

    def test_commit_timeout_reconciles_pending_then_ready(self) -> None:
        api = ApiFixture(reads=[version("DRAFT"), version("DRAFT"), version("AUTO_CHECK"), version("READY_FOR_PUBLICATION")],
                         unresolved="commit")
        self.assertEqual(self.submit(api).status, "READY_FOR_PUBLICATION")
        self.assertEqual(api.mutations, ["create", "upload", "commit"])

    def test_every_pending_status_returns_durable_id_at_poll_deadline(self) -> None:
        for status in PENDING:
            self.clock = Clock()
            api = ApiFixture(reads=[version("DRAFT"), version("DRAFT"), version(status)])
            receipt = self.submit(api)
            self.assertEqual((receipt.version_id, receipt.status), (42, status))
            self.assertEqual(self.clock.sleeps, [10, 10])
            self.assertEqual(len([event for event in api.events if event[0] == "get"]), 5)

    def test_stalled_clock_cannot_make_polling_unbounded(self) -> None:
        api = ApiFixture(reads=[version("DRAFT"), version("DRAFT"), version("MODERATION")])
        sleeps: list[float] = []
        result = submit_for_moderation(api, self.request, clock=lambda: 0, sleep=sleeps.append,
                                       timeout_seconds=20, poll_interval=10)
        self.assertEqual(result.status, "MODERATION")
        self.assertEqual(sleeps, [10, 10])

    def test_local_artifact_change_during_creation_stops_before_upload(self) -> None:
        api = ApiFixture()
        def create(package: str) -> int:
            self.apk.write_bytes(b"changed")
            return 42
        with patch.object(api, "create_manual_draft", side_effect=create), self.assertRaises(ReleaseError):
            self.submit(api)
        self.assertNotIn("upload", api.mutations)

    def test_local_artifact_change_during_ready_check_stops_before_publish(self) -> None:
        api = ApiFixture(reads=[version("READY_FOR_PUBLICATION")])
        def ready(package: str, version_id: int) -> RustoreVersion:
            self.apk.write_bytes(b"changed")
            return version("READY_FOR_PUBLICATION")
        with patch.object(api, "get_version", side_effect=ready), self.assertRaises(ReleaseError):
            self.publish(api)
        self.assertEqual(api.mutations, [])

    def test_local_artifact_change_during_upload_stops_before_commit(self) -> None:
        api = ApiFixture()
        def upload(package: str, version_id: int, apk: Path) -> None:
            apk.write_bytes(b"changed")
        with patch.object(api, "upload_main_apk", side_effect=upload), self.assertRaises(ReleaseError):
            self.submit(api)
        self.assertNotIn("commit", api.mutations)

    def test_live_rejected_historical_unknown_and_uncommitted_states_fail_closed(self) -> None:
        for status in (*STOP, "DRAFT"):
            with self.subTest(status=status):
                api = ApiFixture(reads=[version("DRAFT"), version("DRAFT"), version(status)])
                with self.assertRaises(ReleaseError):
                    self.submit(api)
                self.assertNotIn("publish", api.mutations)

    def test_remote_id_or_policy_drift_stops_before_upload_or_publish(self) -> None:
        for changes in ({"version_id": 43}, {"publish_type": "INSTANTLY"}, {"partial_value": 50}):
            api = ApiFixture(reads=[version("DRAFT", **changes)])
            with self.assertRaises(ReleaseError):
                self.submit(api)
            self.assertEqual(api.mutations, ["create"])

    def test_owned_fresh_draft_need_not_have_target_metadata_before_first_upload(self) -> None:
        api = ApiFixture(reads=[version("DRAFT", version_name="0.1.10", version_code=11),
                                version("DRAFT"), version("READY_FOR_PUBLICATION")])
        self.assertEqual(self.submit(api).version_code, 12)
        self.assertEqual(api.mutations, ["create", "upload", "commit"])

    def test_uploaded_or_publishable_identity_drift_stops_before_commit_or_publish(self) -> None:
        for changes in ({"version_id": 43}, {"version_name": "0.1.12"}, {"version_code": 13},
                        {"publish_type": "INSTANTLY"}, {"partial_value": 50}):
            with self.subTest(changes=changes):
                api = ApiFixture(reads=[version("DRAFT"), version("DRAFT", **changes)])
                with self.assertRaises(ReleaseError):
                    self.submit(api)
                self.assertEqual(api.mutations, ["create", "upload"])
                api = ApiFixture(reads=[version("READY_FOR_PUBLICATION", **changes)])
                with self.assertRaises(ReleaseError):
                    self.publish(api)
                self.assertEqual(api.mutations, [])

    def test_receipt_parser_requires_exact_checksum_canonical_bytes_and_schema(self) -> None:
        self.assertEqual(parse_receipt(self.raw, self.checksum).to_bytes(), self.raw)
        bad_blobs = [self.raw[:-1], self.raw.replace(b'"versionCode":12', b'"versionCode":true'),
                     self.raw.replace(b'"partialValue":100', b'"partialValue":50'),
                     self.raw.replace(b'"publishType":"MANUAL"', b'"publishType":"INSTANTLY"'),
                     self.raw.replace(b'"status":"READY_FOR_PUBLICATION"', b'"status":"ACTIVE"'),
                     self.raw.replace(b'{', b'{"secret":"x",', 1),
                     self.raw.replace(b'{', b'{"versionId":42,', 1),
                     self.raw.replace(b'1970-01-01', b'1970-02-30')]
        for raw in bad_blobs:
            with self.subTest(raw=raw), self.assertRaises(ReleaseError):
                parse_receipt(raw, hashlib.sha256(raw).hexdigest())
        with self.assertRaises(ReleaseError):
            parse_receipt(self.raw, "0" * 64)

    def test_publish_checks_receipt_confirmation_and_local_identity_before_api(self) -> None:
        for changes in ({"receipt_sha256": "0" * 64}, {"confirmation": "yes"},
                        {"confirmation": "PUBLISH ru.altparking.guard v0.1.11 43"}):
            api = ApiFixture()
            with self.assertRaises(ReleaseError):
                self.publish(api, **changes)
            self.assertEqual(api.events, [])
        for changes in ({"source_sha": "c" * 40}, {"signer_sha256": "c" * 64},
                        {"version_code": 13}, {"apk_sha256": "c" * 64}):
            saved = self.request
            self.request = replace(saved, **changes)
            api = ApiFixture()
            with self.assertRaises(ReleaseError):
                self.publish(api)
            self.assertEqual(api.events, [])
            self.request = saved
        self.apk.write_bytes(b"changed")
        api = ApiFixture()
        with self.assertRaises(ReleaseError):
            self.publish(api)
        self.assertEqual(api.events, [])

    def test_publish_queries_saved_id_only_and_requires_active_after_one_post(self) -> None:
        api = ApiFixture(reads=[version("READY_FOR_PUBLICATION"), version("READY_FOR_PUBLICATION"), version("ACTIVE")])
        self.assertEqual(self.publish(api).version_status, "ACTIVE")
        self.assertEqual(api.events, [("get", PACKAGE, 42), ("publish", PACKAGE, 42),
                                      ("get", PACKAGE, 42), ("get", PACKAGE, 42)])

    def test_publish_cannot_start_from_any_status_except_exact_ready(self) -> None:
        for status in (*PENDING, *STOP, "DRAFT"):
            api = ApiFixture(reads=[version(status)])
            with self.assertRaises(ReleaseError):
                self.publish(api)
            self.assertEqual(api.mutations, [])

    def test_ambiguous_publish_succeeds_only_when_same_id_becomes_active(self) -> None:
        for status, succeeds in (("ACTIVE", True), ("READY_FOR_PUBLICATION", False),
                                 ("PARTIAL_ACTIVE", False), ("MODERATION", False),
                                 ("REJECTED_BY_SECURITY", False)):
            self.clock = Clock()
            api = ApiFixture(reads=[version("READY_FOR_PUBLICATION"), version(status)], unresolved="publish")
            if succeeds:
                self.assertEqual(self.publish(api).version_status, "ACTIVE")
            else:
                with self.assertRaises(ReleaseError):
                    self.publish(api)
            self.assertEqual(api.mutations, ["publish"])
            self.assertLessEqual(self.clock.value, 20)

    def test_successful_publish_reply_without_active_is_not_success(self) -> None:
        for status in ("READY_FOR_PUBLICATION", "PARTIAL_ACTIVE"):
            api = ApiFixture(reads=[version("READY_FOR_PUBLICATION"), version(status)])
            with self.assertRaises(ReleaseError):
                self.publish(api)
            self.assertEqual(api.mutations, ["publish"])

    def test_status_is_read_only_and_crosschecks_saved_remote_identity(self) -> None:
        api = ApiFixture(reads=[version("ACTIVE")])
        result = status_from_receipt(api, self.request, self.raw, self.checksum)
        self.assertEqual(result.version_status, "ACTIVE")
        self.assertEqual(api.events, [("get", PACKAGE, 42)])
        api = ApiFixture(reads=[version("ACTIVE", version_code=99)])
        with self.assertRaises(ReleaseError):
            status_from_receipt(api, self.request, self.raw, self.checksum)

    def test_manifest_binds_release_fields_and_apk_before_any_network(self) -> None:
        manifest = {"versionName": "0.1.11", "buildNumber": 12, "packageId": PACKAGE,
                    "sourceCommit": SOURCE, "apkSha256": APK_HASH, "builtAt": "2026-09-23T00:00:00Z"}
        path = Path(self.directory.name) / "release-manifest.json"
        path.write_text(json.dumps(manifest), encoding="utf-8")
        self.assertEqual(request_from_manifest(path, self.apk, "v0.1.11", SOURCE, SIGNER), self.request)
        for field, value in (("packageId", "ru.altparking.driver"), ("sourceCommit", "c" * 40),
                             ("versionName", "0.1.12"), ("buildNumber", True), ("apkSha256", "c" * 64)):
            path.write_text(json.dumps({**manifest, field: value}), encoding="utf-8")
            with self.assertRaises(ReleaseError):
                request_from_manifest(path, self.apk, "v0.1.11", SOURCE, SIGNER)

    def test_credentials_are_mode_specific_and_push_project_is_never_a_fallback(self) -> None:
        with patch.dict(os.environ, {"RUSTORE_PUSH_PROJECT_ID": "push", "RUSTORE_SUBMIT_KEY_ID": "submit-key",
                                     "RUSTORE_SUBMIT_PRIVATE_KEY_PKCS8_BASE64": "secret"}, clear=True):
            client = client_for_mode("submit")
            self.assertEqual(repr(client), "RustoreApiClient()")
            with self.assertRaises(ReleaseError):
                client_for_mode("publish")
        with patch.dict(os.environ, {"RUSTORE_PUBLISH_KEY_ID": "publish-key",
                                     "RUSTORE_PUBLISH_PRIVATE_KEY_PKCS8_BASE64": "secret"}, clear=True):
            self.assertEqual(repr(client_for_mode("publish")), "RustoreApiClient()")
            with self.assertRaises(ReleaseError):
                client_for_mode("submit")

    def test_cli_submit_writes_receipt_and_status_publish_consume_exact_assets(self) -> None:
        root = Path(self.directory.name)
        manifest = root / "release-manifest.json"
        manifest.write_text(json.dumps({"versionName": "0.1.11", "buildNumber": 12, "packageId": PACKAGE,
                                       "sourceCommit": SOURCE, "apkSha256": APK_HASH, "builtAt": "2026-09-23"}))
        receipt_path = root / "rustore-submission.json"
        common = ["--manifest", str(manifest), "--apk", str(self.apk), "--tag", "v0.1.11",
                  "--source-sha", SOURCE, "--signer-sha256", SIGNER]
        api = ApiFixture()
        with patch("tool.rustore_release.client_for_mode", return_value=api), patch(
            "tool.rustore_release.time.time", return_value=0.0,
        ):
            self.assertEqual(main(["submit", *common, "--output", str(receipt_path)]), 0)
        self.assertEqual(receipt_path.read_bytes(), self.raw)
        for command in ("status", "publish"):
            api = ApiFixture(reads=[version("READY_FOR_PUBLICATION"), version("ACTIVE")])
            args = [command, *common, "--receipt", str(receipt_path), "--receipt-sha256", self.checksum]
            if command == "publish":
                args += ["--confirmation", "PUBLISH ru.altparking.guard v0.1.11 42"]
            with patch("tool.rustore_release.client_for_mode", return_value=api), contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(main(args), 0)
            self.assertEqual(api.mutations, ["publish"] if command == "publish" else [])

    def test_cli_crash_marker_prevents_resending_submit_or_publish_on_rerun(self) -> None:
        root = Path(self.directory.name)
        manifest = root / "release-manifest.json"
        manifest.write_text(json.dumps({"versionName": "0.1.11", "buildNumber": 12, "packageId": PACKAGE,
                                       "sourceCommit": SOURCE, "apkSha256": APK_HASH, "builtAt": "2026-09-23"}))
        common = ["--manifest", str(manifest), "--apk", str(self.apk), "--tag", "v0.1.11",
                  "--source-sha", SOURCE, "--signer-sha256", SIGNER]
        receipt_path = root / "rustore-submission.json"
        for command in ("submit", "publish"):
            api = ApiFixture(reads=[version("READY_FOR_PUBLICATION")])
            if command == "submit":
                args = [command, *common, "--output", str(receipt_path)]
                method = "create_manual_draft"
            else:
                receipt_path.write_bytes(self.raw)
                args = [command, *common, "--receipt", str(receipt_path), "--receipt-sha256", self.checksum,
                        "--confirmation", "PUBLISH ru.altparking.guard v0.1.11 42"]
                method = "publish_manual"
            with patch("tool.rustore_release.client_for_mode", return_value=api), patch.object(
                api, method, side_effect=KeyboardInterrupt,
            ), self.assertRaises(KeyboardInterrupt):
                main(args)
            fresh = ApiFixture(reads=[version("READY_FOR_PUBLICATION"), version("ACTIVE")])
            with patch("tool.rustore_release.client_for_mode", return_value=fresh), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(main(args), 1)
            self.assertEqual(fresh.mutations, [])
            marker = receipt_path if command == "submit" else receipt_path.with_name("rustore-submission.json.publish-attempt.json")
            marker_data = json.loads(marker.read_bytes())
            self.assertEqual(marker_data["operation"], command)
            self.assertEqual(marker_data["state"], "UNRESOLVED")

    def cli_arguments(self, command: str, root: Path | None = None) -> tuple[list[str], Path]:
        root = root if root is not None else Path(self.directory.name)
        manifest = root / "release-manifest.json"
        manifest.write_text(json.dumps({"versionName": "0.1.11", "buildNumber": 12, "packageId": PACKAGE,
                                       "sourceCommit": SOURCE, "apkSha256": APK_HASH, "builtAt": "2026-09-23"}))
        receipt = root / "rustore-submission.json"
        args = [command, "--manifest", str(manifest), "--apk", str(self.apk), "--tag", "v0.1.11",
                "--source-sha", SOURCE, "--signer-sha256", SIGNER]
        if command == "submit":
            args += ["--output", str(receipt)]
        else:
            receipt.write_bytes(self.raw)
            args += ["--receipt", str(receipt), "--receipt-sha256", self.checksum]
        if command == "publish":
            args += ["--confirmation", "PUBLISH ru.altparking.guard v0.1.11 42"]
        return args, receipt

    def test_invalid_local_receipts_and_confirmation_never_construct_credential_client(self) -> None:
        invalid_data = [b"not-json", self.raw[:-1]]
        for changes in ({"sourceSha": "c" * 40}, {"signerSha256": "c" * 64},
                        {"apkSha256": "c" * 64}, {"versionCode": 99},
                        *({"status": status} for status in (*STOP, "DRAFT"))):
            invalid_data.append((json.dumps({**self.receipt_data, **changes}, sort_keys=True,
                                            separators=(",", ":")) + "\n").encode())
        for command in ("status", "publish"):
            for raw in invalid_data:
                args, path = self.cli_arguments(command)
                path.write_bytes(raw)
                args[args.index("--receipt-sha256") + 1] = hashlib.sha256(raw).hexdigest()
                with self.subTest(command=command, raw=raw), patch(
                    "tool.rustore_release.client_for_mode", return_value=ApiFixture(),
                ) as factory, contextlib.redirect_stderr(io.StringIO()):
                    self.assertEqual(main(args), 1)
                    factory.assert_not_called()
            args, _ = self.cli_arguments(command)
            args[args.index("--receipt-sha256") + 1] = "0" * 64
            with patch("tool.rustore_release.client_for_mode", return_value=ApiFixture()) as factory, contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(main(args), 1)
                factory.assert_not_called()
        args, _ = self.cli_arguments("publish")
        args[-1] = "yes"
        with patch("tool.rustore_release.client_for_mode", return_value=ApiFixture()) as factory, contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(main(args), 1)
            factory.assert_not_called()

    def test_trusted_pending_receipt_can_publish_only_after_fresh_ready(self) -> None:
        for status in PENDING:
            raw = (json.dumps({**self.receipt_data, "status": status}, sort_keys=True, separators=(",", ":")) + "\n").encode()
            api = ApiFixture(reads=[version("READY_FOR_PUBLICATION"), version("ACTIVE")])
            self.assertEqual(self.publish(api, receipt_bytes=raw,
                                          receipt_sha256=hashlib.sha256(raw).hexdigest()).version_status, "ACTIVE")

    def test_invalid_submit_timestamp_never_constructs_credential_client(self) -> None:
        args, _ = self.cli_arguments("submit")
        with patch("tool.rustore_release.time.time", return_value=float("nan")), patch(
            "tool.rustore_release.client_for_mode", return_value=ApiFixture(),
        ) as factory, contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(main(args), 1)
            factory.assert_not_called()

    def test_posix_checkpoint_directory_is_synced_and_closed_before_mutation(self) -> None:
        for command in ("submit", "publish"):
            with self.subTest(command=command), tempfile.TemporaryDirectory() as folder:
                args, receipt = self.cli_arguments(command, Path(folder))
                events: list[str] = []
                api = ApiFixture() if command == "submit" else ApiFixture(reads=[version("READY_FOR_PUBLICATION"), version("ACTIVE")])
                original_mutate = api.mutate
                def mutate(action: str, *values: object) -> None:
                    events.append(action)
                    original_mutate(action, *values)
                def sync(descriptor: int) -> None:
                    if descriptor == 999999:
                        events.append("directory-sync")
                    else:
                        events.append("file-sync")
                        os.fsync(descriptor)
                with patch("tool.rustore_release.os", wraps=os) as system, patch.object(api, "mutate", side_effect=mutate), patch(
                    "tool.rustore_release.client_for_mode", return_value=api,
                ), contextlib.redirect_stdout(io.StringIO()):
                    system.name = "posix"
                    system.O_RDONLY = os.O_RDONLY
                    system.open.return_value = 999999
                    system.fsync.side_effect = sync
                    system.close.side_effect = lambda descriptor: events.append("directory-close")
                    self.assertEqual(main(args), 0)
                    self.assertEqual([call.args for call in system.open.call_args_list],
                                     [(str(receipt.parent), os.O_RDONLY)] * (2 if command == "submit" else 1))
                    self.assertEqual([call.args for call in system.close.call_args_list],
                                     [(999999,)] * (2 if command == "submit" else 1))
                first_mutation = "create" if command == "submit" else "publish"
                self.assertEqual(events[:4], ["file-sync", "directory-sync", "directory-close", first_mutation])
                if command == "submit":
                    self.assertEqual(events[-3:], ["file-sync", "directory-sync", "directory-close"])

    def test_checkpoint_sync_and_close_failures_are_sanitized_before_mutation(self) -> None:
        for command in ("submit", "publish"):
            for failure in ("file-sync", "directory-open", "directory-sync", "directory-close", "file-close"):
                with self.subTest(command=command, failure=failure), tempfile.TemporaryDirectory() as folder:
                    args, receipt = self.cli_arguments(command, Path(folder))
                    api = ApiFixture() if command == "submit" else ApiFixture(reads=[version("READY_FOR_PUBLICATION"), version("ACTIVE")])
                    output = io.StringIO()
                    def sync(descriptor: int) -> None:
                        if failure == ("directory-sync" if descriptor == 999999 else "file-sync"):
                            raise OSError("sensitive sync failure")
                        if descriptor != 999999:
                            os.fsync(descriptor)
                    actual_open = Path.open
                    def open_file(path: Path, *values: object, **keywords: object):
                        handle = actual_open(path, *values, **keywords)
                        if failure == "file-close" and values and values[0] == "xb":
                            class FailingClose:
                                def __enter__(self):
                                    return handle
                                def __exit__(self, *exception: object) -> None:
                                    handle.close()
                                    raise OSError("sensitive close failure")
                            return FailingClose()
                        return handle
                    with patch("tool.rustore_release.os", wraps=os) as system, patch.object(Path, "open", new=open_file), patch(
                        "tool.rustore_release.client_for_mode", return_value=api,
                    ), contextlib.redirect_stderr(output):
                        system.name = "posix"
                        system.O_RDONLY = os.O_RDONLY
                        system.open.return_value = 999999
                        if failure == "directory-open":
                            system.open.side_effect = OSError("sensitive open failure")
                        system.fsync.side_effect = sync
                        if failure == "directory-close":
                            system.close.side_effect = OSError("sensitive close failure")
                        self.assertEqual(main(args), 1)
                        if failure in ("directory-sync", "directory-close"):
                            system.close.assert_called_once_with(999999)
                        else:
                            system.close.assert_not_called()
                    self.assertEqual(api.mutations, [])
                    self.assertNotIn("sensitive", output.getvalue())


if __name__ == "__main__":
    unittest.main()
