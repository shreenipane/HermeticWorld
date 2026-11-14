"""Bounded, stateless httpbin test service. Also runs as an isolated guest script.

No filesystem, resolver, host identity, or wall clock is used to answer requests.
The listener belongs inside the test sandbox, never on a host-facing interface.
"""

from __future__ import annotations

import argparse
import base64
import binascii
from datetime import datetime, timezone
from email.message import Message
import gzip
import hashlib
import hmac
import io
import json
import os
import re
import socket
import subprocess
import threading
import time
from urllib.parse import parse_qsl, unquote, urlsplit

LISTEN_ADDRESS = "127.0.0.1"
LISTEN_PORT = 8765
MAX_REQUEST_LINE_BYTES = 8192
MAX_HEADER_BYTES = 16384
MAX_HEADERS = 64
MAX_BODY_BYTES = 1024 * 1024
MAX_RESPONSE_BYTES = 4 * 1024 * 1024
MAX_FIELDS = 64
MAX_CHUNKS = 8192
MAX_CHUNK_LINE_BYTES = 128
MAX_REFUSAL_DRAIN_BYTES = (MAX_REQUEST_LINE_BYTES + MAX_HEADER_BYTES + MAX_BODY_BYTES
                           + MAX_CHUNKS * (MAX_CHUNK_LINE_BYTES + 2))
MAX_READ_CHUNK_BYTES = 65536
MAX_STREAM_RECORDS = 1000
MAX_REDIRECTS = 20
MAX_DELAY_SECONDS = 10
MAX_WORKERS = 16
MAX_REQUESTS = 10000
MAX_TOTAL_BYTES = 64 * 1024 * 1024
MAX_RUN_SECONDS = 86400
IO_TIMEOUT_SECONDS = 15
ACCEPT_POLL_SECONDS = 0.1
MIN_CLOCK = 315532800
MAX_CLOCK = 4102444799
REALM = "hermetic-httpbin"
NONCE = "hermetic-httpbin-v1"
OPAQUE = "hermetic-httpbin-opaque-v1"
TOKEN = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+\Z")
OWNED_HEADERS = frozenset((
    "date", "server", "content-length", "connection", "transfer-encoding",
    "content-encoding", "trailer", "upgrade", "keep-alive", "proxy-connection",
))


class InvalidRequest(ValueError):
    """Fixed public failure; never includes request data or credentials."""


def _invalid():
    raise InvalidRequest("invalid test-service request")


def _printable(value):
    return isinstance(value, str) and all(32 <= ord(c) <= 126 for c in value)


def _json(value):
    return (json.dumps(value, ensure_ascii=True, allow_nan=False,
                       sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")


def fixed_date(t_clock):
    if type(t_clock) is not int or not MIN_CLOCK <= t_clock <= MAX_CLOCK:
        raise ValueError("invalid test-service clock")
    dt = datetime.fromtimestamp(t_clock, timezone.utc)
    weekdays = ("Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun")
    months = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")
    return "{}, {:02d} {} {:04d} {:02d}:{:02d}:{:02d} GMT".format(
        weekdays[dt.weekday()], dt.day, months[dt.month - 1], dt.year,
        dt.hour, dt.minute, dt.second)


def _pairs(raw):
    try:
        pairs = parse_qsl(raw, keep_blank_values=True, encoding="utf-8",
                          errors="strict", max_num_fields=MAX_FIELDS)
    except (ValueError, UnicodeError):
        _invalid()
    result = {}
    for key, value in pairs:
        if key in result:
            old = result[key]
            result[key] = old + [value] if isinstance(old, list) else [old, value]
        else:
            result[key] = value
    return result


def _number(value, minimum, maximum):
    if not isinstance(value, str) or not re.fullmatch(r"[0-9]{1,8}", value):
        _invalid()
    number = int(value)
    if not minimum <= number <= maximum:
        _invalid()
    return number


def _multipart(body, content_type):
    message = Message()
    message["content-type"] = content_type
    boundary = message.get_param("boundary")
    if not isinstance(boundary, str) or not re.fullmatch(r"[ -~]{1,70}", boundary):
        _invalid()
    marker = b"--" + boundary.encode("ascii")
    parts = body.split(marker, MAX_FIELDS + 2)
    if len(parts) > MAX_FIELDS + 2 or parts[0] != b"" or parts[-1] not in (b"--\r\n", b"--"):
        _invalid()
    form, files = {}, {}
    for part in parts[1:-1]:
        if not part.startswith(b"\r\n") or not part.endswith(b"\r\n"):
            _invalid()
        header, separator, payload = part[2:-2].partition(b"\r\n\r\n")
        if not separator or len(header) > MAX_HEADER_BYTES:
            _invalid()
        lines = header.split(b"\r\n")
        if len(lines) > MAX_HEADERS:
            _invalid()
        disposition = None
        for line in lines:
            key, sep, value = line.partition(b":")
            if not sep or not TOKEN.fullmatch(key.decode("ascii", "replace")):
                _invalid()
            if key.lower() == b"content-disposition":
                if disposition is not None:
                    _invalid()
                disposition = value.strip().decode("utf-8", "replace")
        if disposition is None:
            _invalid()
        field = Message()
        field["content-disposition"] = disposition
        name = field.get_param("name", header="content-disposition")
        if not isinstance(name, str):
            _invalid()
        target = files if field.get_param("filename", header="content-disposition") is not None else form
        value = payload.decode("utf-8", "replace")
        if name in target:
            old = target[name]
            target[name] = old + [value] if isinstance(old, list) else [old, value]
        else:
            target[name] = value
    return form, files


def _md5(value):
    return hashlib.md5(value.encode("utf-8"), usedforsecurity=False).hexdigest()


def _digest_valid(authorization, method, target, user, password):
    if not authorization.startswith("Digest "):
        return False
    raw = authorization[len("Digest "):]
    fields = {}
    # Consume the entire value: duplicate/unknown syntax must not be ignored.
    for _ in range(MAX_FIELDS):
        match = re.match(r'\s*([A-Za-z]+)=(?:"([^"\\]*)"|([A-Za-z0-9]+))\s*(,|$)', raw)
        if not match or match[1] in fields:
            return False
        fields[match[1]] = match[2] if match[2] is not None else match[3]
        raw = raw[match.end():]
        if match[4] == "," and not raw:
            return False
        if not raw:
            break
    if raw or any(fields.get(key) != value for key, value in (
        ("username", user), ("realm", REALM), ("nonce", NONCE),
        ("uri", target), ("qop", "auth"),
    )):
        return False
    if fields.get("algorithm", "MD5") != "MD5" or fields.get("opaque", OPAQUE) != OPAQUE:
        return False
    nc, cnonce, response = (fields.get(key, "") for key in ("nc", "cnonce", "response"))
    if not re.fullmatch(r"[0-9a-fA-F]{8}", nc) or not 1 <= len(cnonce) <= 128:
        return False
    if not re.fullmatch(r"[0-9a-f]{32}", response):
        return False
    expected = _md5("{}:{}:{}:{}:auth:{}".format(
        _md5("{}:{}:{}".format(user, REALM, password)), NONCE, nc, cnonce,
        _md5("{}:{}".format(method, target))))
    return hmac.compare_digest(expected, response)


def _metadata(method, target, headers):
    if method not in ("GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"):
        _invalid()
    if not isinstance(target, str) or len(target) > MAX_REQUEST_LINE_BYTES or not target.startswith("/"):
        _invalid()
    if not _printable(target) or "#" in target:
        _invalid()
    if len(headers) > MAX_HEADERS or sum(len(k) + len(v) for k, v in headers) > MAX_HEADER_BYTES:
        _invalid()
    incoming = {}
    for key, value in headers:
        if not TOKEN.fullmatch(key) or not _printable(value):
            _invalid()
        lower = key.lower()
        if lower in incoming:
            _invalid()
        incoming[lower] = value
    parsed = urlsplit(target)
    if parsed.scheme or parsed.netloc:
        _invalid()
    try:
        path = unquote(parsed.path, encoding="utf-8", errors="strict")
    except UnicodeError:
        _invalid()
    args = _pairs(parsed.query)
    host = incoming.get("host", "httpbin.org")
    if not re.fullmatch(r"[A-Za-z0-9.-]+(?::[0-9]{1,5})?", host):
        _invalid()
    return incoming, path, args, host


def response(method, target, headers, body, t_clock):
    """Pure endpoint implementation; returned headers retain duplicate cookies."""
    date = fixed_date(t_clock)
    incoming, path, args, host = _metadata(method, target, headers)
    if len(body) > MAX_BODY_BYTES:
        _invalid()
    echoed_headers = {k.title(): v for k, v in incoming.items()}
    echo = {"args": args, "headers": echoed_headers, "origin": "127.0.0.1",
            "url": "http://" + host + target}
    status, extra, payload = 200, [], None
    content_type = "application/json"
    if path in ("/get", "/head", "/post", "/put", "/patch", "/delete", "/gzip"):
        expected = "GET" if path in ("/head", "/gzip") else path[1:].upper()
        if method != expected and not (method == "HEAD" and expected == "GET"):
            status, payload = 405, {"error": "method not allowed"}
        else:
            if path in ("/post", "/put", "/patch", "/delete"):
                form, files, data, json_body = {}, {}, "", None
                ct = incoming.get("content-type", "").split(";", 1)[0].lower()
                if ct == "application/x-www-form-urlencoded":
                    try:
                        form = _pairs(body.decode("utf-8"))
                    except UnicodeError:
                        _invalid()
                elif ct == "multipart/form-data":
                    form, files = _multipart(body, incoming["content-type"])
                else:
                    try:
                        data = body.decode("utf-8")
                    except UnicodeError:
                        data = "data:application/octet-stream;base64," + base64.b64encode(body).decode("ascii")
                    if ct == "application/json":
                        try:
                            json_body = json.loads(data, parse_constant=lambda _: _invalid())
                        except (ValueError, RecursionError):
                            _invalid()
                echo.update(data=data, form=form, files=files, json=json_body)
            payload = echo
            if path == "/gzip":
                payload = dict(echo, gzipped=True)
    elif path == "/headers":
        payload = {"headers": echoed_headers}
    elif path == "/user-agent":
        payload = {"user-agent": incoming.get("user-agent")}
    elif path == "/cookies":
        cookies = {}
        if incoming.get("cookie", "").count(";") >= MAX_FIELDS:
            _invalid()
        for part in incoming.get("cookie", "").split(";", MAX_FIELDS):
            key, sep, value = part.strip().partition("=")
            if sep:
                cookies[key] = value.strip('"')
        if len(cookies) > MAX_FIELDS:
            _invalid()
        payload = {"cookies": cookies}
    elif path in ("/cookies/set", "/cookies/delete"):
        for key, values in args.items():
            if not TOKEN.fullmatch(key):
                _invalid()
            for value in values if isinstance(values, list) else [values]:
                if not _printable(value) or any(c in value for c in ";,\\"):
                    _invalid()
                cookie = key + "=" + (value if path.endswith("set") else "") + "; Path=/"
                if path.endswith("delete"):
                    cookie += "; Max-Age=0"
                extra.append(("Set-Cookie", cookie))
        status, payload = 302, {}
        extra.append(("Location", "/cookies"))
    elif path.startswith(("/redirect/", "/relative-redirect/", "/absolute-redirect/")):
        prefix, _, number = path.rpartition("/")
        count = _number(number, 1, MAX_REDIRECTS)
        location = prefix + "/" + str(count - 1) if count > 1 else "/get"
        if prefix == "/absolute-redirect":
            location = "http://" + host + location
        status, payload = 302, {}
        extra.append(("Location", location))
    elif path == "/redirect-to":
        location = args.get("url")
        if not isinstance(location, str) or not location or not _printable(location):
            _invalid()
        dest = urlsplit(location)
        if dest.scheme.lower() not in ("", "http", "https"):
            _invalid()
        status = _number(args.get("status_code", "302"), 300, 399)
        payload = {}
        extra.append(("Location", location))
    elif path.startswith("/status/"):
        status = _number(path[len("/status/"):], 200, 599)
        payload = {}
        if status in (301, 302, 303, 307, 308):
            extra.append(("Location", "/get"))
    elif path.startswith("/basic-auth/"):
        parts = path.split("/")
        if len(parts) != 4:
            _invalid()
        user, password = parts[2:]
        expected = "Basic " + base64.b64encode((user + ":" + password).encode("utf-8")).decode("ascii")
        authenticated = hmac.compare_digest(incoming.get("authorization", ""), expected)
        status = 200 if authenticated else 401
        payload = {"authenticated": authenticated}
        if authenticated:
            payload["user"] = user
        else:
            extra.append(("WWW-Authenticate", 'Basic realm="' + REALM + '"'))
    elif path.startswith("/digest-auth/"):
        parts = path.split("/")
        if len(parts) != 5 or parts[2] != "auth":
            _invalid()
        user, password = parts[3:]
        authenticated = _digest_valid(incoming.get("authorization", ""), method, target, user, password)
        status = 200 if authenticated else 401
        payload = {"authenticated": authenticated}
        extra.append(("Set-Cookie", "fake=fake_value; Path=/"))
        if authenticated:
            payload["user"] = user
        else:
            extra.append(("WWW-Authenticate", 'Digest realm="{}", nonce="{}", qop="auth", algorithm=MD5, opaque="{}"'.format(REALM, NONCE, OPAQUE)))
    elif path.startswith("/stream/"):
        count = _number(path[len("/stream/"):], 0, MAX_STREAM_RECORDS)
        records, total = [], 0
        for i in range(count):
            record = _json(dict(echo, id=i))
            total += len(record)
            if total > MAX_RESPONSE_BYTES:
                _invalid()
            records.append(record)
        payload = b"".join(records)
    elif path.startswith("/delay/"):
        _number(path[len("/delay/"):], 0, MAX_DELAY_SECONDS)
        payload = echo  # The transport applies the bounded delay, not this pure function.
    elif path == "/response-headers":
        payload = args
        for key, values in args.items():
            lower = key.lower()
            if not TOKEN.fullmatch(key) or lower in OWNED_HEADERS or lower.startswith(("x-archive-", "memento-")):
                _invalid()
            for value in values if isinstance(values, list) else [values]:
                if not _printable(value):
                    _invalid()
                if lower == "content-type":
                    content_type = value
                else:
                    extra.append((key, value))
    elif path == "/html":
        payload, content_type = b"<!doctype html><html><body>httpbin</body></html>\n", "text/html; charset=utf-8"
    else:
        status, payload = 404, {"error": "not found"}
    try:
        encoded = payload if isinstance(payload, bytes) else _json(payload)
    except (ValueError, RecursionError):
        _invalid()
    if path == "/gzip" and status == 200:
        compressed = io.BytesIO()
        with gzip.GzipFile(filename="", fileobj=compressed, mode="wb", mtime=0) as stream:
            stream.write(encoded)
        encoded = compressed.getvalue()
        extra.append(("Content-Encoding", "gzip"))
    if status in (204, 304):
        encoded = b""
    result_headers = [("Date", date), ("Content-Type", content_type)] + extra
    if len(encoded) > MAX_RESPONSE_BYTES or len(result_headers) > MAX_HEADERS or sum(len(k) + len(v) for k, v in result_headers) > MAX_HEADER_BYTES:
        _invalid()
    return status, result_headers, encoded


class _Reader:
    def __init__(self, connection):
        self.connection = connection
        self.buffer = b""
        self.deadline = time.monotonic() + IO_TIMEOUT_SECONDS

    def _timeout(self):
        left = self.deadline - time.monotonic()
        if left <= 0:
            _invalid()
        self.connection.settimeout(left)

    def line(self, cap):
        while True:
            end = self.buffer.find(b"\r\n")
            if end >= 0:
                if end + 2 > cap:
                    _invalid()
                line, self.buffer = self.buffer[:end], self.buffer[end + 2:]
                return line
            if len(self.buffer) >= cap:
                _invalid()
            self._timeout()
            chunk = self.connection.recv(min(cap - len(self.buffer), MAX_READ_CHUNK_BYTES))
            if not chunk:
                _invalid()
            self.buffer += chunk

    def read(self, length):
        data, self.buffer = self.buffer[:length], self.buffer[length:]
        chunks, size = [data], len(data)
        while size < length:
            self._timeout()
            chunk = self.connection.recv(min(length - size, MAX_READ_CHUNK_BYTES))
            if not chunk:
                _invalid()
            size += len(chunk)
            chunks.append(chunk)
        return b"".join(chunks)

    def request(self):
        try:
            method, target, version = self.line(MAX_REQUEST_LINE_BYTES).decode("ascii").split(" ")
        except (ValueError, UnicodeError):
            _invalid()
        if version not in ("HTTP/1.0", "HTTP/1.1"):
            _invalid()
        headers, total = [], 0
        for _ in range(MAX_HEADERS + 1):
            line = self.line(MAX_HEADER_BYTES)
            total += len(line) + 2
            if total > MAX_HEADER_BYTES:
                _invalid()
            if not line:
                break
            key, sep, value = line.partition(b":")
            if not sep:
                _invalid()
            try:
                headers.append((key.decode("ascii"), value.strip(b" \t").decode("ascii")))
            except UnicodeError:
                _invalid()
        else:
            _invalid()
        # Validate headers and target before reading a body or sending 100 Continue.
        _metadata(method, target, headers)
        lower = {k.lower(): v for k, v in headers}
        if version == "HTTP/1.1" and "host" not in lower:
            _invalid()
        if "transfer-encoding" in lower and "content-length" in lower:
            _invalid()
        expect = lower.get("expect")
        if expect and expect.lower() != "100-continue":
            _invalid()
        encoding = lower.get("transfer-encoding")
        if encoding is not None and encoding.lower() != "chunked":
            _invalid()
        length = _number(lower.get("content-length", "0"), 0, MAX_BODY_BYTES) if encoding is None else 0
        if expect:
            self.connection.sendall(b"HTTP/1.1 100 Continue\r\n\r\n")
        if encoding is None:
            body = self.read(length)
        else:
            chunks, total = [], 0
            for _ in range(MAX_CHUNKS):
                chunk_line = self.line(MAX_CHUNK_LINE_BYTES)
                if not re.fullmatch(b"[0-9a-fA-F]{1,8}", chunk_line):
                    _invalid()
                size = int(chunk_line, 16)
                total += size
                if total > MAX_BODY_BYTES:
                    _invalid()
                if not size:
                    if self.line(MAX_HEADER_BYTES) != b"":
                        _invalid()
                    break
                chunks.append(self.read(size))
                if self.read(2) != b"\r\n":
                    _invalid()
            else:
                _invalid()
            body = b"".join(chunks)
        return method, target, headers, body


class Service:
    """A fixed number of workers; one bounded request per connection, no logs."""

    def __init__(self, t_clock, port=LISTEN_PORT):
        self.date = fixed_date(t_clock)
        self.t_clock = t_clock
        self.stopping = threading.Event()
        self.lock = threading.Lock()
        self.requests = 0
        self.bytes = 0
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.listener.bind((LISTEN_ADDRESS, port))
            self.listener.listen(MAX_WORKERS)
            self.listener.settimeout(ACCEPT_POLL_SECONDS)
        except BaseException:
            self.listener.close()
            raise
        self.port = self.listener.getsockname()[1]
        self.deadline = time.monotonic() + MAX_RUN_SECONDS
        self.workers = []

    def start(self):
        for _ in range(MAX_WORKERS):
            worker = threading.Thread(target=self._worker, daemon=True)
            self.workers.append(worker)
            worker.start()
        return self

    def close(self):
        self.stopping.set()
        self.listener.close()
        for worker in self.workers:
            worker.join(IO_TIMEOUT_SECONDS + MAX_DELAY_SECONDS + ACCEPT_POLL_SECONDS)

    def _discard(self, connection):
        # Send EOF first, then consume bounded unread input so a refused request
        # does not turn a normal client half-close into a connection reset.
        deadline = time.monotonic() + IO_TIMEOUT_SECONDS
        remaining = MAX_REFUSAL_DRAIN_BYTES
        try:
            connection.shutdown(socket.SHUT_WR)
            while remaining:
                left = deadline - time.monotonic()
                if left <= 0:
                    return
                connection.settimeout(left)
                data = connection.recv(min(remaining, MAX_READ_CHUNK_BYTES))
                if not data:
                    return
                remaining -= len(data)
        except OSError:
            pass

    def _worker(self):
        while not self.stopping.is_set() and time.monotonic() < self.deadline:
            try:
                connection, _ = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            with connection:
                with self.lock:
                    exhausted = self.requests >= MAX_REQUESTS
                    if not exhausted:
                        self.requests += 1
                if exhausted:
                    self._discard(connection)
                    return
                reader = _Reader(connection)
                try:
                    method, target, headers, body = reader.request()
                    status, outgoing, payload = response(method, target, headers, body, self.t_clock)
                    path = unquote(urlsplit(target).path, encoding="utf-8", errors="strict")
                    if path.startswith("/delay/"):
                        delay = _number(path[len("/delay/"):], 0, MAX_DELAY_SECONDS)
                        if self.stopping.wait(delay):
                            return
                    packet = ("HTTP/1.1 {} Status\r\n".format(status) +
                              "".join(k + ": " + v + "\r\n" for k, v in outgoing) +
                              "Content-Length: {}\r\nConnection: close\r\n\r\n".format(len(payload))).encode("ascii")
                    if method != "HEAD":
                        packet += payload
                    with self.lock:
                        if self.bytes + len(packet) > MAX_TOTAL_BYTES:
                            return
                        self.bytes += len(packet)
                    connection.settimeout(IO_TIMEOUT_SECONDS)
                    connection.sendall(packet)
                except (InvalidRequest, OSError, ValueError, UnicodeError, RecursionError, binascii.Error):
                    # Close malformed requests without reflecting them or emitting a log.
                    pass


def main(argv=None):
    parser = argparse.ArgumentParser(description="Run a local sealed test service and its tests")
    parser.add_argument("--t-clock", type=int, required=True)
    parser.add_argument("--run", nargs=argparse.REMAINDER, required=True)
    args = parser.parse_args(argv)
    if not args.run:
        parser.error("a test command is required")
    service = Service(args.t_clock).start()
    try:
        env = dict(os.environ)
        for key in tuple(env):
            if key.lower() in ("http_proxy", "https_proxy", "all_proxy", "no_proxy"):
                del env[key]
        env["HTTPBIN_URL"] = "http://127.0.0.1:{}/".format(service.port)
        env["NO_PROXY"] = "127.0.0.1,localhost"
        # The parent waits for the entire test command. The Docker/VM supervisor
        # owns the outer deadline and destroys the sandbox, including this service.
        return subprocess.call(args.run, env=env, close_fds=True, timeout=MAX_RUN_SECONDS)
    finally:
        service.close()


if __name__ == "__main__":
    try:
        code = main()
    except (OSError, ValueError, subprocess.SubprocessError):
        code = 1
    raise SystemExit(code)
