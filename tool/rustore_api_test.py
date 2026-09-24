from __future__ import annotations

import base64
import json
import os
import stat
import subprocess
import tempfile
import traceback
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import Mock, patch

from tool.rustore_api import (
    HttpRequest, HttpResponse, RustoreApiClient, RustoreApiError,
    RustoreMutationUnresolved,
    OpenSslSignatureProvider, StdlibHttpTransport,
)


BASE = "https://public-api.rustore.ru"
PACKAGE = "ru.altparking.guard"
TIMESTAMP = "2026-09-23T09:10:11.123+00:00"
STATUSES = (
    "ACTIVE", "PARTIAL_ACTIVE", "READY_FOR_PUBLICATION", "PREVIOUS_ACTIVE",
    "ARCHIVED", "REJECTED_BY_MODERATOR", "TAKEN_FOR_MODERATION", "MODERATION",
    "AUTO_CHECK", "AUTO_CHECK_FAILED", "DRAFT", "DELETED_DRAFT",
    "REJECTED_BY_SECURITY",
)


def response(payload: object, status_code: int = 200) -> HttpResponse:
    return HttpResponse(status_code, json.dumps(payload).encode("utf-8"))


def ok(body: object) -> HttpResponse:
    return response({"code": "OK", "message": None, "body": body, "timestamp": TIMESTAMP})


def version(version_id: int, status: str = "ACTIVE") -> dict[str, object]:
    return {
        "versionId": version_id,
        "appName": "ALT:PARKING Guard",
        "appType": "MAIN",
        "versionName": "0.1.11",
        "versionCode": version_id + 11,
        "versionStatus": status,
        "publishType": "MANUAL",
        "testingType": None,
        "publishDateTime": None,
        "sendDateForModer": TIMESTAMP,
        "partialValue": 100,
        "whatsNew": "Guard update",
        "priceValue": 0,
        "paid": False,
    }


def page(
    items: list[dict[str, object]],
    number: int = 0,
    total_pages: int = 1,
    total_elements: int | None = None,
) -> HttpResponse:
    return ok({
        "content": items,
        "pageNumber": number,
        "pageSize": 100,
        "totalElements": len(items) if total_elements is None else total_elements,
        "totalPages": total_pages,
    })


class RecordingSigner:
    def __init__(self) -> None:
        self.messages: list[bytes] = []

    def sign_sha512_rsa(self, message: bytes) -> bytes:
        self.messages.append(message)
        return b"\x00\xff"


class ScriptedTransport:
    def __init__(self, *replies: HttpResponse | Exception) -> None:
        self.replies = list(replies)
        self.requests: list[HttpRequest] = []

    def send(self, request: HttpRequest) -> HttpResponse:
        self.requests.append(request)
        if not self.replies:
            raise AssertionError("unexpected HTTP request")
        result = self.replies.pop(0)
        if isinstance(result, Exception):
            raise result
        return result


class Clock:
    def __init__(self) -> None:
        self.value = datetime(2026, 9, 23, 9, 10, 11, 123000, tzinfo=timezone.utc)

    def __call__(self) -> datetime:
        return self.value


class RustoreApiContractTest(unittest.TestCase):
    def client(
        self, *replies: HttpResponse | Exception, auth: HttpResponse | None = None,
    ) -> tuple[RustoreApiClient, ScriptedTransport, RecordingSigner, Clock]:
        signer = RecordingSigner()
        transport = ScriptedTransport(
            auth if auth is not None else ok({"jwe": "test-jwe", "ttl": 900}),
            *replies,
        )
        clock = Clock()
        return RustoreApiClient("key-42", signer, transport, now=clock), transport, signer, clock

    def test_auth_signs_exact_utf8_bytes_and_sends_exact_json_fields(self) -> None:
        client, transport, signer, _ = self.client(page([]))
        self.assertEqual(client.list_versions(PACKAGE), ())
        self.assertEqual(signer.messages, [b"key-422026-09-23T09:10:11.123+00:00"])
        auth_request = transport.requests[0]
        self.assertEqual((auth_request.method, auth_request.url), ("POST", BASE + "/public/auth/"))
        self.assertEqual(auth_request.headers["Content-Type"], "application/json")
        self.assertEqual(json.loads(auth_request.body), {
            "keyId": "key-42",
            "timestamp": TIMESTAMP,
            "signature": base64.b64encode(b"\x00\xff").decode("ascii"),
        })
        self.assertEqual(transport.requests[1].headers["Public-Token"], "test-jwe")

    def test_auth_requires_nested_jwe_and_positive_numeric_ttl(self) -> None:
        bad_bodies = (
            {"jwe": "top-level", "body": {"ttl": 900}},
            {"body": {"jwe": "", "ttl": 900}},
            {"body": {"jwe": "test-jwe", "ttl": "900"}},
            {"body": {"jwe": "test-jwe", "ttl": 0}},
            {"body": {"jwe": "test-jwe", "ttl": True}},
        )
        for payload in bad_bodies:
            with self.subTest(payload=payload):
                client, transport, _, _ = self.client(auth=response({"code": "OK", **payload}))
                with self.assertRaises(RustoreApiError):
                    client.list_versions(PACKAGE)
                self.assertEqual(len(transport.requests), 1)

    def test_token_is_refreshed_before_documented_900_second_expiry(self) -> None:
        client, transport, signer, clock = self.client(
            page([]), ok({"jwe": "new-jwe", "ttl": 900}), page([]),
        )
        client.list_versions(PACKAGE)
        clock.value += timedelta(seconds=850)
        client.list_versions(PACKAGE)
        self.assertEqual([request.url for request in transport.requests].count(BASE + "/public/auth/"), 2)
        self.assertEqual(len(signer.messages), 2)
        self.assertEqual(transport.requests[-1].headers["Public-Token"], "new-jwe")

    def test_list_consumes_all_pages_with_status_filter(self) -> None:
        first = [version(index) for index in range(1, 101)]
        second = [version(101, "DRAFT")]
        client, transport, _, _ = self.client(
            page(first, total_pages=2, total_elements=101),
            page(second, number=1, total_pages=2, total_elements=101),
        )
        versions = client.list_versions(PACKAGE, statuses=("ACTIVE", "DRAFT"))
        self.assertEqual(len(versions), 101)
        self.assertEqual((versions[0].version_id, versions[-1].version_id), (1, 101))
        self.assertEqual(versions[-1].version_status, "DRAFT")
        self.assertEqual([request.url for request in transport.requests[1:]], [
            BASE + "/public/v1/application/ru.altparking.guard/version?versionStatuses=ACTIVE,DRAFT&page=0&size=100",
            BASE + "/public/v1/application/ru.altparking.guard/version?versionStatuses=ACTIVE,DRAFT&page=1&size=100",
        ])

    def test_list_preserves_every_documented_status_without_collapsing_it(self) -> None:
        client, _, _, _ = self.client(page([
            version(index, status) for index, status in enumerate(STATUSES, 1)
        ]))
        self.assertEqual(tuple(item.version_status for item in client.list_versions(PACKAGE)), STATUSES)

    def test_duplicate_version_id_across_pages_fails_closed(self) -> None:
        client, _, _, _ = self.client(
            page([version(index) for index in range(1, 101)], total_pages=2, total_elements=101),
            page([version(100)], number=1, total_pages=2, total_elements=101),
        )
        with self.assertRaises(RustoreApiError):
            client.list_versions(PACKAGE)

    def test_malformed_version_or_page_fails_closed(self) -> None:
        malformed = (
            ok({"content": {}, "pageNumber": 0, "pageSize": 100, "totalElements": 0, "totalPages": 1}),
            page([{**version(3), "versionId": True}]),
            page([{**version(3), "publishType": None}]),
            page([{**version(3), "partialValue": "100"}]),
            ok({"content": [], "pageNumber": 1, "pageSize": 100, "totalElements": 0, "totalPages": 1}),
        )
        for bad_response in malformed:
            with self.subTest(body=bad_response.body):
                client, _, _, _ = self.client(bad_response)
                with self.assertRaises(RustoreApiError):
                    client.list_versions(PACKAGE)

    def test_get_version_uses_only_id_query_and_requires_unique_exact_id(self) -> None:
        client, transport, _, _ = self.client(page([version(12)]))
        self.assertEqual(client.get_version(PACKAGE, 12).version_id, 12)
        self.assertEqual(transport.requests[1].url, BASE + "/public/v1/application/ru.altparking.guard/version?ids=12")
        for items in ([], [version(13)], [version(12), version(12)]):
            with self.subTest(items=items):
                candidate, _, _, _ = self.client(page(items))
                with self.assertRaises(RustoreApiError):
                    candidate.get_version(PACKAGE, 12)

    def test_create_draft_sends_manual_100_and_requires_positive_id(self) -> None:
        client, transport, _, _ = self.client(ok(321))
        self.assertEqual(client.create_manual_draft(PACKAGE), 321)
        request = transport.requests[1]
        self.assertEqual((request.method, request.url), (
            "POST", BASE + "/public/v1/application/ru.altparking.guard/version",
        ))
        self.assertEqual(json.loads(request.body), {"publishType": "MANUAL", "partialValue": 100})
        for invalid_id in (0, -1, True, "321", {"versionId": 321}):
            with self.subTest(invalid_id=invalid_id):
                candidate, _, _, _ = self.client(ok(invalid_id))
                with self.assertRaises(RustoreApiError):
                    candidate.create_manual_draft(PACKAGE)

    def test_exact_id_accepts_server_page_size_without_relaxing_consistency(self) -> None:
        body = {
            "content": [version(12)], "pageNumber": 0, "pageSize": 20,
            "totalElements": 1, "totalPages": 1,
        }
        client, transport, _, _ = self.client(ok(body))
        self.assertEqual(client.get_version(PACKAGE, 12).version_id, 12)
        self.assertEqual(transport.requests[-1].url, BASE + "/public/v1/application/ru.altparking.guard/version?ids=12")
        for changes in (
            {"pageSize": 0}, {"pageSize": True}, {"pageNumber": 1},
            {"totalElements": 2}, {"totalPages": 2},
            {"content": [version(13)]},
            {"content": [version(12), version(12)], "totalElements": 2},
        ):
            with self.subTest(changes=changes):
                candidate, _, _, _ = self.client(ok({**body, **changes}))
                with self.assertRaises(RustoreApiError):
                    candidate.get_version(PACKAGE, 12)

    def test_list_still_requires_requested_page_size_100(self) -> None:
        client, _, _, _ = self.client(ok({
            "content": [version(12)], "pageNumber": 0, "pageSize": 20,
            "totalElements": 1, "totalPages": 1,
        }))
        with self.assertRaises(RustoreApiError):
            client.list_versions(PACKAGE)

    def test_upload_uses_exact_main_apk_query_and_binary_multipart_field(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            apk = Path(directory) / "guard.apk"
            apk.write_bytes(b"PK\x03\x04fake-apk")
            client, transport, _, _ = self.client(ok(None))
            client.upload_main_apk(PACKAGE, 321, apk)
            request = transport.requests[1]
            self.assertEqual((request.method, request.url), (
                "POST", BASE + "/public/v1/application/ru.altparking.guard/version/321/apk?isMainApk=true&servicesType=Unknown",
            ))
            self.assertEqual(request.multipart_file, ("file", apk))
            self.assertIsNone(request.body)

    def test_commit_query_and_manual_publish_paths_are_distinct(self) -> None:
        client, transport, _, _ = self.client(ok(None), ok(None))
        client.commit_for_moderation(PACKAGE, 321)
        client.publish_manual(PACKAGE, 321)
        self.assertEqual([(request.method, request.url) for request in transport.requests[1:]], [
            ("POST", BASE + "/public/v1/application/ru.altparking.guard/version/321/commit?priorityUpdate=0"),
            ("POST", BASE + "/public/v1/application/ru.altparking.guard/version/321/publish"),
        ])

    def test_acknowledgement_endpoints_accept_missing_or_null_body(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            apk = Path(directory) / "guard.apk"
            apk.write_bytes(b"abc")
            for action in ("upload", "commit", "publish"):
                for reply in (response({"code": "OK", "message": None, "timestamp": TIMESTAMP}), ok(None)):
                    with self.subTest(action=action, reply=reply.body):
                        client, transport, _, _ = self.client(reply)
                        if action == "upload":
                            client.upload_main_apk(PACKAGE, 42, apk)
                        elif action == "commit":
                            client.commit_for_moderation(PACKAGE, 42)
                        else:
                            client.publish_manual(PACKAGE, 42)
                        self.assertEqual(len(transport.requests), 2)

    def test_acknowledgement_endpoints_reject_nonnull_or_malformed_body(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            apk = Path(directory) / "guard.apk"
            apk.write_bytes(b"abc")
            for action in ("upload", "commit", "publish"):
                for reply in (ok({}), ok([]), ok(42), ok(False), ok("OK"),
                              HttpResponse(200, b'{"code":"OK","body":null,"body":null}')):
                    with self.subTest(action=action, reply=reply.body):
                        client, transport, _, _ = self.client(reply)
                        with self.assertRaises(RustoreMutationUnresolved):
                            if action == "upload":
                                client.upload_main_apk(PACKAGE, 42, apk)
                            elif action == "commit":
                                client.commit_for_moderation(PACKAGE, 42)
                            else:
                                client.publish_manual(PACKAGE, 42)
                        self.assertEqual(len(transport.requests), 2)

    def test_data_endpoints_still_require_body(self) -> None:
        for reply in (response({"code": "OK"}), ok(None)):
            for action in ("auth", "list", "get", "create"):
                with self.subTest(action=action, reply=reply.body):
                    client, _, _, _ = self.client(reply, auth=reply if action == "auth" else None)
                    with self.assertRaises(RustoreApiError):
                        if action == "create":
                            client.create_manual_draft(PACKAGE)
                        elif action == "get":
                            client.get_version(PACKAGE, 42)
                        else:
                            client.list_versions(PACKAGE)

    def test_definitive_mutation_rejection_is_sanitized_and_never_unresolved(self) -> None:
        for reply in (HttpResponse(400, b"raw rejection secret"),
                      HttpResponse(409, b"raw rejection secret"),
                      HttpResponse(503, b"raw rejection secret"),
                      response({"code": "ERROR", "message": "raw rejection secret", "body": None})):
            for action in ("create", "commit", "publish"):
                with self.subTest(action=action, reply=reply):
                    client, transport, _, _ = self.client(reply)
                    with self.assertRaises(RustoreApiError) as caught:
                        if action == "create":
                            client.create_manual_draft(PACKAGE)
                        elif action == "commit":
                            client.commit_for_moderation(PACKAGE, 42)
                        else:
                            client.publish_manual(PACKAGE, 42)
                    self.assertIs(type(caught.exception), RustoreApiError)
                    self.assertNotIn("raw rejection secret", "".join(traceback.format_exception(caught.exception)))
                    self.assertEqual(len(transport.requests), 2)

    def test_api_errors_redact_token_key_and_response_body(self) -> None:
        secret = "sensitive-jwe-value"
        api_reply = response({
            "code": "error", "message": "key-42 " + secret,
            "body": {"diagnostic": "private-key-material", "marker": "raw-response-marker-777"},
        })
        auth_reply = ok({"jwe": secret, "ttl": 900})
        client, transport, _, _ = self.client(api_reply, auth=auth_reply)
        with self.assertRaises(RustoreApiError) as caught:
            client.list_versions(PACKAGE)
        exposed_surfaces = (
            str(caught.exception), repr(caught.exception), repr(client),
            repr(transport.requests[0]), repr(transport.requests[1]),
            repr(auth_reply), repr(api_reply),
        )
        for surface in exposed_surfaces:
            for forbidden in (secret, "key-42", "AP8=", "private-key-material", "raw-response-marker-777"):
                self.assertNotIn(forbidden, surface)
        self.assertNotIn(repr(auth_reply.body), repr(auth_reply))
        self.assertNotIn(repr(api_reply.body), repr(api_reply))

    def test_mutation_transport_timeout_is_unresolved_and_not_resent(self) -> None:
        client, transport, _, _ = self.client(TimeoutError("sensitive-jwe-value raw-response-marker-777"))
        with self.assertRaises(RustoreMutationUnresolved) as caught:
            client.create_manual_draft(PACKAGE)
        for surface in (str(caught.exception), repr(caught.exception)):
            self.assertNotIn("sensitive-jwe-value", surface)
            self.assertNotIn("raw-response-marker-777", surface)
        self.assertEqual(
            [(request.method, request.url) for request in transport.requests],
            [
                ("POST", BASE + "/public/auth/"),
                ("POST", BASE + "/public/v1/application/ru.altparking.guard/version"),
            ],
        )

    def test_invalid_package_and_version_never_authenticate(self) -> None:
        client, transport, _, _ = self.client()
        for package in ("ru.altparking.driver", "ru.altparking.guard/", ""):
            with self.subTest(package=package), self.assertRaises(RustoreApiError):
                client.list_versions(package)
        for version_id in (0, -1, True, "12"):
            with self.subTest(version_id=version_id), self.assertRaises(RustoreApiError):
                client.get_version(PACKAGE, version_id)
        self.assertEqual(transport.requests, [])

    def test_ambiguous_mutation_replies_are_unresolved_without_retry(self) -> None:
        for reply in (HttpResponse(200, b"invalid"), ok({"id": 12}),
                      response({"code": "OK"}), ok(None), response({"body": 12}),
                      response({"code": None, "body": 12})):
            with self.subTest(reply=reply):
                client, transport, _, _ = self.client(reply)
                with self.assertRaises(RustoreMutationUnresolved):
                    client.create_manual_draft(PACKAGE)
                self.assertEqual(len(transport.requests), 2)

    def test_inconsistent_pagination_and_duplicate_json_keys_fail_closed(self) -> None:
        for reply in (
            page([version(1)], total_pages=2, total_elements=101),
            page([version(1)], total_elements=2),
            HttpResponse(200, b'{"code":"ERROR","code":"OK","body":null}'),
        ):
            with self.subTest(reply=reply):
                client, _, _, _ = self.client(reply)
                with self.assertRaises(RustoreApiError):
                    client.list_versions(PACKAGE)

    def test_short_ttl_is_respected_and_nonfinite_ttl_is_rejected(self) -> None:
        client, transport, _, clock = self.client(
            page([]), ok({"jwe": "fresh", "ttl": 30}), page([]),
            auth=ok({"jwe": "short", "ttl": 30}),
        )
        client.list_versions(PACKAGE)
        clock.value += timedelta(seconds=30)
        client.list_versions(PACKAGE)
        self.assertEqual(transport.requests[-1].headers["Public-Token"], "fresh")
        for ttl in (float("inf"), float("nan")):
            candidate, _, _, _ = self.client(auth=ok({"jwe": "secret", "ttl": ttl}))
            with self.assertRaises(RustoreApiError):
                candidate.list_versions(PACKAGE)


class RustoreRuntimeBoundaryTest(unittest.TestCase):
    def test_file_close_failure_is_sanitized_and_preserves_primary_failure(self) -> None:
        for primary in (None, TimeoutError("raw transport secret")):
            with self.subTest(primary=primary), tempfile.TemporaryDirectory() as directory:
                apk = Path(directory) / "guard.apk"
                apk.write_bytes(b"original-apk")
                with apk.open("rb") as actual:
                    source = Mock(wraps=actual)
                    source.close.side_effect = OSError("raw file cleanup secret")
                    with patch.object(Path, "open", return_value=source), patch(
                        "tool.rustore_api.http.client.HTTPSConnection",
                    ) as connection:
                        wire = connection.return_value
                        wire.getresponse.return_value.status = 200
                        wire.getresponse.return_value.read.return_value = b"{}"
                        if primary is not None:
                            wire.send.side_effect = primary
                        with self.assertRaises(RustoreApiError) as caught:
                            StdlibHttpTransport().send(HttpRequest("POST", BASE + "/upload", multipart_file=("file", apk)))
                        source.close.assert_called_once()
                        wire.close.assert_called_once()
                        if primary is not None:
                            self.assertIs(caught.exception.__context__, primary)
                        rendered = "".join(traceback.format_exception(caught.exception))
                        self.assertNotIn("raw file cleanup secret", rendered)
                        self.assertNotIn("raw transport secret", rendered)

    def test_transport_uses_size_of_its_single_open_apk_handle(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            apk = Path(directory) / "guard.apk"
            apk.write_bytes(b"original-apk")
            with patch("tool.rustore_api.http.client.HTTPSConnection") as connection, patch.object(
                Path, "stat", side_effect=AssertionError("path may now refer to a replacement"),
            ):
                wire = connection.return_value
                wire.getresponse.return_value.status = 200
                wire.getresponse.return_value.read.return_value = b"{}"
                reply = StdlibHttpTransport().send(HttpRequest("POST", BASE + "/upload", multipart_file=("file", apk)))
                self.assertEqual(reply.status_code, 200)
                transmitted = b"".join(call.args[0] for call in wire.send.call_args_list)
                headers = dict(call.args for call in wire.putheader.call_args_list)
                self.assertEqual(int(headers["Content-Length"]), len(transmitted))
                self.assertIn(b"original-apk", transmitted)

    def test_transport_rejects_apk_truncation_or_growth_without_finishing_multipart(self) -> None:
        for changed_content in (b"short", b"longer-than-original-apk"):
            with self.subTest(changed_content=changed_content), tempfile.TemporaryDirectory() as directory:
                apk = Path(directory) / "guard.apk"
                apk.write_bytes(b"original-apk")
                with patch("tool.rustore_api.http.client.HTTPSConnection") as connection:
                    wire = connection.return_value
                    wire.endheaders.side_effect = lambda: apk.write_bytes(changed_content)
                    with self.assertRaises(RustoreApiError):
                        StdlibHttpTransport().send(HttpRequest("POST", BASE + "/upload", multipart_file=("file", apk)))
                    wire.getresponse.assert_not_called()
                    wire.close.assert_called_once()
                    transmitted = b"".join(call.args[0] for call in wire.send.call_args_list)
                    self.assertFalse(transmitted.endswith(b"--\r\n"))
                    headers = dict(call.args for call in wire.putheader.call_args_list)
                    self.assertLess(len(transmitted), int(headers["Content-Length"]))

    def test_signer_passes_only_temporary_der_path_and_cleans_up_on_failure(self) -> None:
        # Removing cleanup, RSA padding selection, or passing key material in argv
        # must fail this boundary test; OpenSSL itself is the external dependency.
        for fails in (False, True):
            paths: list[Path] = []

            def run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
                self.assertEqual(command[:6], ["openssl", "dgst", "-sha512", "-keyform", "DER", "-sign"])
                self.assertEqual(command[7:], ["-sigopt", "rsa_padding_mode:pkcs1"])
                key_path = Path(command[6])
                paths.append(key_path)
                self.assertEqual(key_path.read_bytes(), b"test-der-key")
                if os.name != "nt":
                    self.assertEqual(stat.S_IMODE(key_path.stat().st_mode), 0o600)
                self.assertEqual(kwargs["input"], b"key-id-timestamp")
                self.assertNotIn("test-der-key", repr(command))
                if fails:
                    raise subprocess.CalledProcessError(1, command, stderr=b"secret diagnostic")
                return subprocess.CompletedProcess(command, 0, b"signature", b"")

            encoded_key = base64.b64encode(b"test-der-key").decode("ascii")
            with patch.dict(os.environ, {"RUSTORE_SUBMIT_PRIVATE_KEY_PKCS8_BASE64": encoded_key}), patch(
                "tool.rustore_api.subprocess.run", side_effect=run,
            ):
                signer = OpenSslSignatureProvider("RUSTORE_SUBMIT_PRIVATE_KEY_PKCS8_BASE64")
                if fails:
                    with self.assertRaises(RustoreApiError) as caught:
                        signer.sign_sha512_rsa(b"key-id-timestamp")
                    self.assertNotIn("secret diagnostic", str(caught.exception))
                else:
                    self.assertEqual(signer.sign_sha512_rsa(b"key-id-timestamp"), b"signature")
                self.assertNotIn(encoded_key, repr(signer))
            self.assertEqual(len(paths), 1)
            self.assertFalse(paths[0].exists())

    def test_transport_streams_apk_without_redirects_or_secret_command_arguments(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            apk = Path(directory) / "guard.apk"
            apk.write_bytes(b"PK\x03\x04apk-content")
            with patch("tool.rustore_api.http.client.HTTPSConnection") as connection:
                wire = connection.return_value
                wire.getresponse.return_value.status = 200
                wire.getresponse.return_value.read.return_value = b'{"code":"OK","body":null}'
                request = HttpRequest("POST", BASE + "/upload", {"Public-Token": "secret"}, multipart_file=("file", apk))
                reply = StdlibHttpTransport().send(request)
                self.assertEqual(reply.status_code, 200)
                transmitted = b"".join(call.args[0] for call in wire.send.call_args_list)
                self.assertIn(b'name="file"; filename="guard.apk"', transmitted)
                self.assertIn(b"PK\x03\x04apk-content", transmitted)
                headers = dict(call.args for call in wire.putheader.call_args_list)
                self.assertEqual(int(headers["Content-Length"]), len(transmitted))
                self.assertEqual(headers["Public-Token"], "secret")
                wire.close.assert_called_once()
        with patch("tool.rustore_api.http.client.HTTPSConnection") as connection:
            with self.assertRaises(RustoreApiError):
                StdlibHttpTransport().send(HttpRequest("GET", "https://other.example/", {"Public-Token": "secret"}))
            connection.assert_not_called()


if __name__ == "__main__":
    unittest.main()
