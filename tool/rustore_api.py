"""Guard-only RuStore Public API boundary. No automatic request retries."""
from __future__ import annotations

import base64
import http.client
import json
import math
import os
import re
import subprocess
import tempfile
import uuid
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from types import MappingProxyType
from typing import BinaryIO, Protocol, cast
from urllib.parse import urlencode, urlsplit


BASE_URL = "https://public-api.rustore.ru"
PACKAGE_NAME = "ru.altparking.guard"


class RustoreApiError(RuntimeError):
    """Sanitized failure; never pass upstream text to this exception."""

    def __init__(self) -> None:
        super().__init__("RuStore API request or validation failed")


class RustoreMutationUnresolved(RustoreApiError):
    """A mutation may have succeeded. Reconcile using read-only requests."""

    def __init__(self) -> None:
        RuntimeError.__init__(self, "RuStore mutation unresolved; reconcile before continuing")


@dataclass(frozen=True)
class HttpRequest:
    method: str
    url: str = field(repr=False)
    headers: Mapping[str, str] = field(default_factory=dict, repr=False)
    body: bytes | None = field(default=None, repr=False)
    multipart_file: tuple[str, Path] | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "headers", MappingProxyType(dict(self.headers)))


@dataclass(frozen=True)
class HttpResponse:
    status_code: int
    body: bytes = field(repr=False)


@dataclass(frozen=True)
class RustoreVersion:
    version_id: int
    version_name: str
    version_code: int
    version_status: str
    publish_type: str
    partial_value: int


class SignatureProvider(Protocol):
    def sign_sha512_rsa(self, message: bytes) -> bytes: ...


class HttpTransport(Protocol):
    def send(self, request: HttpRequest) -> HttpResponse: ...


@dataclass(frozen=True)
class OpenSslSignatureProvider:
    """Load Base64 PKCS8 DER only from the named environment variable."""

    private_key_env: str = field(repr=False)

    def sign_sha512_rsa(self, message: bytes) -> bytes:
        key_path: Path | None = None
        try:
            if not re.fullmatch(r"RUSTORE_[A-Z0-9_]+_PRIVATE_KEY_PKCS8_BASE64", self.private_key_env):
                raise RustoreApiError()
            key = base64.b64decode(os.environ[self.private_key_env], validate=True)
            if not key:
                raise RustoreApiError()
            descriptor, name = tempfile.mkstemp(prefix="rustore-", suffix=".der")
            key_path = Path(name)
            with os.fdopen(descriptor, "wb") as output:
                os.chmod(key_path, 0o600)
                output.write(key)
            result = subprocess.run(
                ["openssl", "dgst", "-sha512", "-keyform", "DER", "-sign", str(key_path),
                 "-sigopt", "rsa_padding_mode:pkcs1"],
                input=message, capture_output=True, check=True, timeout=30,
                # Child processes do not need any RuStore credentials.
                env={name: value for name, value in os.environ.items() if not name.upper().startswith("RUSTORE_")},
            )
            if not result.stdout:
                raise RustoreApiError()
            return result.stdout
        except Exception:
            raise RustoreApiError() from None
        finally:
            if key_path is not None:
                try:
                    key_path.unlink(missing_ok=True)
                except OSError:
                    raise RustoreApiError() from None


@dataclass(frozen=True)
class StdlibHttpTransport:
    """Stream APKs over TLS; never follow redirects or retry a send."""

    timeout_seconds: float = 120

    def send(self, request: HttpRequest) -> HttpResponse:
        connection: http.client.HTTPSConnection | None = None
        source: BinaryIO | None = None
        completed = False
        try:
            url = urlsplit(request.url)
            if (url.scheme != "https" or url.netloc != "public-api.rustore.ru"
                    or url.fragment or request.method not in ("GET", "POST")):
                raise RustoreApiError()
            headers = dict(request.headers)
            prefix = suffix = b""
            if request.multipart_file is not None:
                field_name, apk = request.multipart_file
                if field_name != "file" or request.body is not None:
                    raise RustoreApiError()
                boundary = "rustore-" + uuid.uuid4().hex
                prefix = (
                    f"--{boundary}\r\n"
                    'Content-Disposition: form-data; name="file"; filename="guard.apk"\r\n'
                    "Content-Type: application/vnd.android.package-archive\r\n\r\n"
                ).encode("ascii")
                suffix = f"\r\n--{boundary}--\r\n".encode("ascii")
                headers["Content-Type"] = "multipart/form-data; boundary=" + boundary
                source = apk.open("rb")
                remaining = os.fstat(source.fileno()).st_size
                headers["Content-Length"] = str(len(prefix) + remaining + len(suffix))
            elif request.body is not None or request.method == "POST":
                headers["Content-Length"] = str(len(request.body or b""))
            connection = http.client.HTTPSConnection(url.netloc, timeout=self.timeout_seconds)
            target = url.path + ("?" + url.query if url.query else "")
            connection.putrequest(request.method, target, skip_accept_encoding=True)
            for name, value in headers.items():
                connection.putheader(name, value)
            connection.endheaders()
            if source is not None:
                connection.send(prefix)
                while remaining:
                    chunk = source.read(min(1024 * 1024, remaining))
                    if not chunk:
                        raise RustoreApiError()
                    connection.send(chunk)
                    remaining -= len(chunk)
                if source.read(1):
                    raise RustoreApiError()
                connection.send(suffix)
            elif request.body is not None:
                connection.send(request.body)
            response = connection.getresponse()
            result = HttpResponse(response.status, response.read())
            completed = True
            return result
        except Exception:
            raise RustoreApiError() from None
        finally:
            cleanup_failed = False
            for resource in (source, connection):
                if resource is not None:
                    try:
                        resource.close()
                    except Exception:
                        cleanup_failed = True
            # Keep an in-flight primary exception; a cleanup-only failure is
            # sanitized as well, and never prevents closing the other resource.
            if completed and cleanup_failed:
                raise RustoreApiError() from None


def _integer(value: object, minimum: int = 0) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < minimum:
        raise RustoreApiError()
    return value


def _string(value: object) -> str:
    if not isinstance(value, str) or not value.strip():
        raise RustoreApiError()
    return value


def _object(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        raise RustoreApiError()
    return cast(dict[str, object], value)


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise RustoreApiError()
        result[key] = value
    return result


def _invalid_constant(value: str) -> object:
    raise RustoreApiError()


def _version(value: object) -> RustoreVersion:
    data = _object(value)
    partial = _integer(data.get("partialValue"))
    if partial > 100:
        raise RustoreApiError()
    return RustoreVersion(
        _integer(data.get("versionId"), 1), _string(data.get("versionName")),
        _integer(data.get("versionCode"), 1), _string(data.get("versionStatus")),
        _string(data.get("publishType")), partial,
    )


def _page(
    body: object, number: int, *, expected_size: int | None = 100,
) -> tuple[tuple[RustoreVersion, ...], int, int]:
    data = _object(body)
    items = data.get("content")
    page_number = _integer(data.get("pageNumber"))
    size = _integer(data.get("pageSize"), 1)
    total = _integer(data.get("totalElements"))
    pages = _integer(data.get("totalPages"))
    if (not isinstance(items, list) or page_number != number
            or (expected_size is not None and size != expected_size)):
        raise RustoreApiError()
    if total == 0:
        if pages not in (0, 1) or items or number != 0:
            raise RustoreApiError()
    elif (pages != (total + size - 1) // size or number >= pages
          or len(items) != min(size, total - number * size)):
        raise RustoreApiError()
    return tuple(_version(item) for item in items), total, pages


class RustoreApiClient:
    def __init__(
        self, key_id: str, signer: SignatureProvider, transport: HttpTransport,
        *, now: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
    ) -> None:
        self._key_id = _string(key_id)
        self._signer = signer
        self._transport = transport
        self._now = now
        self._token: str | None = None
        self._issued_at = self._expires_at = 0.0

    def __repr__(self) -> str:
        return "RustoreApiClient()"

    def _send(
        self, request: HttpRequest, *, mutation: bool = False, acknowledgement: bool = False,
    ) -> object:
        try:
            response = self._transport.send(request)
            status = _integer(response.status_code, 100)
            if status > 599:
                raise RustoreApiError()
        except Exception:
            if mutation:
                raise RustoreMutationUnresolved() from None
            raise RustoreApiError() from None
        # A definitive HTTP rejection must never enter mutation reconciliation.
        if not 200 <= status < 300:
            raise RustoreApiError()
        try:
            data = _object(json.loads(
                response.body.decode("utf-8"), object_pairs_hook=_unique_object,
                parse_constant=_invalid_constant,
            ))
            code = _string(data.get("code"))
        except Exception:
            if mutation:
                raise RustoreMutationUnresolved() from None
            raise RustoreApiError() from None
        if code != "OK":
            raise RustoreApiError()
        try:
            if acknowledgement:
                if data.get("body") is not None:
                    raise RustoreApiError()
                return None
            if data.get("body") is None:
                raise RustoreApiError()
            return data["body"]
        except Exception:
            # Even a malformed acknowledgement may follow a successful mutation.
            if mutation:
                raise RustoreMutationUnresolved() from None
            raise RustoreApiError() from None

    def _auth_token(self) -> str:
        instant = self._now()
        if instant.tzinfo is None or instant.utcoffset() is None:
            raise RustoreApiError()
        instant = instant.astimezone(timezone.utc)
        timestamp = instant.timestamp()
        if self._token is not None and self._issued_at <= timestamp < self._expires_at:
            return self._token
        self._token = None
        text = instant.isoformat(timespec="milliseconds")
        try:
            signature = self._signer.sign_sha512_rsa((self._key_id + text).encode("utf-8"))
            if not isinstance(signature, bytes) or not signature:
                raise RustoreApiError()
        except Exception:
            raise RustoreApiError() from None
        body = _object(self._send(HttpRequest(
            "POST", BASE_URL + "/public/auth/", {"Content-Type": "application/json"},
            json.dumps({"keyId": self._key_id, "timestamp": text,
                        "signature": base64.b64encode(signature).decode("ascii")}).encode("utf-8"),
        )))
        token = _string(body.get("jwe"))
        if any(char.isspace() or ord(char) < 33 or ord(char) > 126 for char in token):
            raise RustoreApiError()
        ttl = body.get("ttl")
        if (not isinstance(ttl, (int, float)) or isinstance(ttl, bool)
                or not math.isfinite(ttl) or ttl <= 0):
            raise RustoreApiError()
        lifetime = min(float(ttl), 900.0)
        self._issued_at = timestamp
        self._expires_at = timestamp + lifetime - min(60.0, lifetime / 10)
        self._token = token
        return token

    @staticmethod
    def _path(package_name: str, version_id: int | None = None) -> str:
        if package_name != PACKAGE_NAME:
            raise RustoreApiError()
        path = BASE_URL + "/public/v1/application/" + PACKAGE_NAME + "/version"
        if version_id is not None:
            path += "/" + str(_integer(version_id, 1))
        return path

    def _request(
        self, method: str, url: str, *, body: bytes | None = None,
        multipart_file: tuple[str, Path] | None = None, acknowledgement: bool = False,
    ) -> object:
        headers = {"Public-Token": self._auth_token()}
        if body is not None:
            headers["Content-Type"] = "application/json"
        return self._send(
            HttpRequest(method, url, headers, body, multipart_file),
            mutation=method == "POST", acknowledgement=acknowledgement,
        )

    def list_versions(self, package_name: str, *, statuses: Sequence[str] = ()) -> tuple[RustoreVersion, ...]:
        path = self._path(package_name)
        if isinstance(statuses, str) or any(not isinstance(status, str) or not re.fullmatch(r"[A-Z_]+", status) for status in statuses):
            raise RustoreApiError()
        versions: list[RustoreVersion] = []
        ids: set[int] = set()
        expected: tuple[int, int] | None = None
        number = 0
        while True:
            query = {"versionStatuses": ",".join(statuses)} if statuses else {}
            query.update(page=str(number), size="100")
            items, total, pages = _page(self._request("GET", path + "?" + urlencode(query, safe=",")), number)
            if expected is not None and expected != (total, pages):
                raise RustoreApiError()
            expected = (total, pages)
            for item in items:
                if item.version_id in ids:
                    raise RustoreApiError()
                ids.add(item.version_id)
                versions.append(item)
            number += 1
            if number >= pages:
                if len(versions) != total:
                    raise RustoreApiError()
                return tuple(versions)

    def get_version(self, package_name: str, version_id: int) -> RustoreVersion:
        path = self._path(package_name)
        version_id = _integer(version_id, 1)
        items, total, pages = _page(
            self._request("GET", path + "?ids=" + str(version_id)), 0, expected_size=None,
        )
        if total != 1 or pages != 1 or len(items) != 1 or items[0].version_id != version_id:
            raise RustoreApiError()
        return items[0]

    def create_manual_draft(self, package_name: str) -> int:
        body = self._request("POST", self._path(package_name), body=b'{"publishType":"MANUAL","partialValue":100}')
        try:
            return _integer(body, 1)
        except RustoreApiError:
            raise RustoreMutationUnresolved() from None

    def upload_main_apk(self, package_name: str, version_id: int, apk_path: Path) -> None:
        path = self._path(package_name, _integer(version_id, 1))
        if not isinstance(apk_path, Path) or apk_path.suffix.lower() != ".apk" or not apk_path.is_file():
            raise RustoreApiError()
        self._request("POST", path + "/apk?isMainApk=true&servicesType=Unknown",
                      multipart_file=("file", apk_path), acknowledgement=True)

    def commit_for_moderation(self, package_name: str, version_id: int) -> None:
        self._request("POST", self._path(package_name, _integer(version_id, 1)) + "/commit?priorityUpdate=0",
                      acknowledgement=True)

    def publish_manual(self, package_name: str, version_id: int) -> None:
        self._request("POST", self._path(package_name, _integer(version_id, 1)) + "/publish",
                      acknowledgement=True)
