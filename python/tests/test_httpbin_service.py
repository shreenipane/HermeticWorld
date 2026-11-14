"""Offline known answers for the historical requests test service."""

import gzip
import http.client
import json
import socket
import time

import pytest

from hermetic_slice import httpbin_service as hb

CLOCK = 1435708800
DATE = "Wed, 01 Jul 2015 00:00:00 GMT"
HEADERS = [("Host", "httpbin.org"), ("User-Agent", "test-agent")]


def endpoint(path, method="GET", body=b"", headers=HEADERS):
    return hb.response(method, path, headers, body, CLOCK)


@pytest.fixture
def service():
    server = hb.Service(CLOCK, port=0).start()
    try:
        yield server
    finally:
        server.close()


def request(service, path, method="GET", body=None, headers=()):
    connection = http.client.HTTPConnection("127.0.0.1", service.port, timeout=3)
    try:
        connection.putrequest(method, path, skip_host=True, skip_accept_encoding=True)
        connection.putheader("Host", "httpbin.org")
        for key, value in headers:
            connection.putheader(key, value)
        if body is not None:
            connection.putheader("Content-Length", str(len(body)))
        connection.endheaders(body)
        result = connection.getresponse()
        data = result.read(hb.MAX_RESPONSE_BYTES + 1)
        return result.status, result.getheaders(), data
    finally:
        connection.close()


def raw(service, packet):
    with socket.create_connection(("127.0.0.1", service.port), timeout=3) as connection:
        connection.sendall(packet)
        connection.shutdown(socket.SHUT_WR)
        try:
            return connection.recv(hb.MAX_RESPONSE_BYTES + hb.MAX_HEADER_BYTES)
        except ConnectionResetError:
            return b""


def test_get_known_answer_and_no_host_metadata(monkeypatch):
    monkeypatch.setenv("TZ", "Pacific/Auckland")
    monkeypatch.setenv("LANG", "not-a-locale")
    monkeypatch.setenv("HOSTNAME", "secret-host-name")
    monkeypatch.setattr(time, "time", lambda: pytest.fail("host wall clock read"))
    monkeypatch.setattr(socket, "gethostname", lambda: pytest.fail("host identity read"))
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a: pytest.fail("resolver read"))
    assert endpoint("/get?q=x&q=y&blank=") == (
        200, [("Date", DATE), ("Content-Type", "application/json")],
        b'{"args":{"blank":"","q":["x","y"]},"headers":{"Host":"httpbin.org","User-Agent":"test-agent"},"origin":"127.0.0.1","url":"http://httpbin.org/get?q=x&q=y&blank="}\n',
    )


@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE"])
def test_echo_methods_form_and_json_known_answers(service, method):
    status, headers, data = request(service, "/" + method.lower(), method,
                                    b"x=one&x=two&utf=%C3%B8",
                                    [("Content-Type", "application/x-www-form-urlencoded")])
    assert status == 200 and dict(headers)["Date"] == DATE
    assert json.loads(data) == {
        "args": {}, "data": "", "files": {}, "form": {"x": ["one", "two"], "utf": "ø"},
        "headers": {"Host": "httpbin.org", "Content-Length": "22",
                    "Content-Type": "application/x-www-form-urlencoded"},
        "json": None, "origin": "127.0.0.1", "url": "http://httpbin.org/" + method.lower(),
    }
    status, _, data = request(service, "/" + method.lower(), method,
                             b'{"life":42}', [("Content-Type", "application/json")])
    assert status == 200
    assert json.loads(data)["json"] == {"life": 42}
    assert json.loads(data)["data"] == '{"life":42}'


def test_multipart_and_binary_echo_known_answers(service):
    body = (b'--BOUNDARY\r\nContent-Disposition: form-data; name="field"\r\n\r\nvalue\r\n'
            b'--BOUNDARY\r\nContent-Disposition: form-data; name="file"; filename="a.txt"\r\n'
            b'Content-Type: text/plain\r\n\r\nfile contents\r\n--BOUNDARY--\r\n')
    status, _, data = request(service, "/post", "POST", body,
                             [("Content-Type", "multipart/form-data; boundary=BOUNDARY")])
    assert status == 200
    value = json.loads(data)
    assert value["form"] == {"field": "value"}
    assert value["files"] == {"file": "file contents"}
    assert value["data"] == "" and value["json"] is None
    assert json.loads(endpoint("/put", "PUT", b"\xff\0")[2])["data"] == "data:application/octet-stream;base64,/wA="


@pytest.mark.parametrize("code", [200, 201, 204, 301, 302, 303, 304, 307, 308, 401, 404, 500, 599])
def test_status_known_answers(service, code):
    status, headers, body = request(service, "/status/" + str(code))
    assert status == code
    assert dict(headers)["Date"] == DATE
    assert body == (b"" if code in (204, 304) else b"{}\n")
    if code in (301, 302, 303, 307, 308):
        assert dict(headers)["Location"] == "/get"


def test_redirects_known_answers(service):
    for prefix in ("redirect", "relative-redirect", "absolute-redirect"):
        for count in (3, 2, 1):
            status, headers, body = request(service, "/{}/{}".format(prefix, count))
            expected = "/{}/{}".format(prefix, count - 1) if count > 1 else "/get"
            if prefix == "absolute-redirect":
                expected = "http://httpbin.org" + expected
            assert (status, dict(headers)["Location"], body) == (302, expected, b"{}\n")
    status, headers, _ = request(service, "/redirect-to?url=HTTP%3A%2F%2Fhttpbin.org%2Fhtml&status_code=307")
    assert (status, dict(headers)["Location"]) == (307, "HTTP://httpbin.org/html")


def test_cookies_and_response_headers_known_answers(service):
    status, headers, _ = request(service, '/cookies/set?foo=%22bar%3Abaz%22&second=two')
    assert status == 302
    assert [v for k, v in headers if k == "Set-Cookie"] == ['foo="bar:baz"; Path=/', 'second=two; Path=/']
    status, _, data = request(service, "/cookies", headers=[("Cookie", 'foo="bar:baz"; second=two')])
    assert status == 200 and data == b'{"cookies":{"foo":"bar:baz","second":"two"}}\n'
    assert ("Set-Cookie", "foo=; Path=/; Max-Age=0") in endpoint("/cookies/delete?foo=bar")[1]
    status, headers, data = request(service, "/response-headers?Set-Cookie=foo%3Ddeleted%3B%20expires%3DThu%2C%2001-Jan-1970%2000%3A00%3A01%20GMT")
    assert status == 200
    assert dict(headers)["Set-Cookie"] == "foo=deleted; expires=Thu, 01-Jan-1970 00:00:01 GMT"
    assert json.loads(data)["Set-Cookie"] == dict(headers)["Set-Cookie"]


def test_basic_auth_known_answers(service):
    for authorization, code in [(None, 401), ("Basic dXNlcjp3cm9uZw==", 401), ("Basic dXNlcjpwYXNz", 200)]:
        status, headers, body = request(service, "/basic-auth/user/pass", headers=[] if authorization is None else [("Authorization", authorization)])
        assert status == code
        if code == 200:
            assert body == b'{"authenticated":true,"user":"user"}\n'
        else:
            assert dict(headers)["WWW-Authenticate"] == 'Basic realm="hermetic-httpbin"'
            assert body == b'{"authenticated":false}\n'


DIGEST = ('Digest username="user", realm="hermetic-httpbin", nonce="hermetic-httpbin-v1", '
          'uri="/digest-auth/auth/user/pass", qop="auth", nc=00000001, cnonce="abcdef", '
          'response="520e53d6d7adfce6b7c75d7b49c8f581", opaque="hermetic-httpbin-opaque-v1"')


def test_digest_auth_known_answer_and_rejects_forgery(service):
    path = "/digest-auth/auth/user/pass"
    status, headers, body = request(service, path)
    assert status == 401
    assert dict(headers)["WWW-Authenticate"] == ('Digest realm="hermetic-httpbin", nonce="hermetic-httpbin-v1", '
                                               'qop="auth", algorithm=MD5, opaque="hermetic-httpbin-opaque-v1"')
    assert dict(headers)["Set-Cookie"] == "fake=fake_value; Path=/"
    assert body == b'{"authenticated":false}\n'
    status, headers, body = request(service, path, headers=[("Authorization", DIGEST)])
    assert status == 200 and body == b'{"authenticated":true,"user":"user"}\n'
    for forged in (DIGEST.replace("520e53", "000000"), DIGEST.replace('nonce="hermetic-httpbin-v1"', 'nonce="other"'),
                   DIGEST.replace('uri="/digest-auth/auth/user/pass"', 'uri="/other"'),
                   DIGEST + ', username="user"', DIGEST + "JUNK"):
        assert request(service, path, headers=[("Authorization", forged)])[0] == 401


def test_gzip_stream_headers_user_agent_and_head_known_answers(service):
    status, headers, compressed = endpoint("/gzip")
    assert status == 200 and ("Content-Encoding", "gzip") in headers
    assert compressed[:10] == b"\x1f\x8b\x08\0\0\0\0\0\x02\xff"
    assert compressed == endpoint("/gzip")[2]
    assert gzip.decompress(compressed) == b'{"args":{},"gzipped":true,"headers":{"Host":"httpbin.org","User-Agent":"test-agent"},"origin":"127.0.0.1","url":"http://httpbin.org/gzip"}\n'
    status, headers, data = request(service, "/stream/3")
    assert status == 200
    assert [json.loads(line) for line in data.splitlines()] == [
        {"args": {}, "headers": {"Host": "httpbin.org"}, "origin": "127.0.0.1",
         "url": "http://httpbin.org/stream/3", "id": i} for i in range(3)
    ]
    assert endpoint("/headers")[2] == b'{"headers":{"Host":"httpbin.org","User-Agent":"test-agent"}}\n'
    assert endpoint("/user-agent")[2] == b'{"user-agent":"test-agent"}\n'
    assert request(service, "/get", "HEAD")[2] == b""
    assert dict(request(service, "/get", "HEAD")[1])["Content-Length"] == str(len(request(service, "/get")[2]))


def test_chunked_upload_and_continue(service):
    packet = (b"POST /post HTTP/1.1\r\nHost: httpbin.org\r\nTransfer-Encoding: chunked\r\n\r\n"
              b"3\r\none\r\n3\r\ntwo\r\n0\r\n\r\n")
    output = raw(service, packet)
    assert output.startswith(b"HTTP/1.1 200 ")
    assert json.loads(output.split(b"\r\n\r\n", 1)[1])["data"] == "onetwo"
    with socket.create_connection(("127.0.0.1", service.port), timeout=3) as connection:
        connection.sendall(b"POST /post HTTP/1.1\r\nHost: httpbin.org\r\nContent-Length: 3\r\nExpect: 100-continue\r\n\r\n")
        assert connection.recv(4096) == b"HTTP/1.1 100 Continue\r\n\r\n"
        connection.sendall(b"abc")
        assert connection.recv(4096).startswith(b"HTTP/1.1 200 ")


@pytest.mark.parametrize("path", [
    "/stream/1001", "/redirect/21", "/redirect/0", "/delay/11", "/status/999",
    "/status/-1", "/get?" + "a=1&" * hb.MAX_FIELDS + "x=1",
    "/response-headers?Date=bad", "/response-headers?Server=host", "/response-headers?Content-Length=100",
    "/response-headers?Set-Cookie=secret%0D%0AX-Leak%3Ayes",
    "/cookies/set?x=bad%3Bcookie", "/redirect-to?url=file%3A%2F%2F%2Fetc%2Fpasswd",
    "/redirect-to?url=%0Asecret", "/redirect-to?url=%2Fget&status_code=301&status_code=302",
    "/digest-auth/auth/user", "/basic-auth/user", "/get?x=%FF",
])
def test_hostile_endpoint_inputs_are_closed(path):
    with pytest.raises(hb.InvalidRequest, match="^invalid test-service request$"):
        endpoint(path)


@pytest.mark.parametrize("headers,body", [
    (b"Content-Length: 3\r\nContent-Length: 3\r\n", b"abc"),
    (b"Transfer-Encoding: chunked\r\nContent-Length: 3\r\n", b"abc"),
    (b"Content-Length: 1048577\r\n", b""),
    (b"Transfer-Encoding: gzip\r\n", b""),
    (b"Transfer-Encoding: chunked\r\n", b"100001\r\n"),
    (b"Transfer-Encoding: chunked\r\n", b"0\r\nSecret: x\r\n\r\n"),
    (b"Content-Length: 4\r\n", b"abc"),
    (b"X-Bad: secret\x00\r\n", b""),
    (b"x: y\r\n" * hb.MAX_HEADERS, b""),
    (b"X-Long: " + b"a" * hb.MAX_HEADER_BYTES + b"\r\n", b""),
])
def test_hostile_wire_inputs_are_closed_without_logs(service, capsys, headers, body):
    assert raw(service, b"POST /post HTTP/1.1\r\nHost: httpbin.org\r\n" + headers + b"\r\n" + body) == b""
    assert capsys.readouterr() == ("", "")


def test_resource_caps_and_listener_are_local(service, monkeypatch):
    assert service.listener.getsockname()[0] == "127.0.0.1"
    assert len(service.workers) == hb.MAX_WORKERS
    monkeypatch.setattr(hb, "MAX_TOTAL_BYTES", 1)
    assert raw(service, b"GET /get HTTP/1.1\r\nHost: httpbin.org\r\n\r\n") == b""
    assert service.bytes == 0
    monkeypatch.setattr(hb, "MAX_REQUESTS", service.requests)
    assert raw(service, b"GET /get HTTP/1.1\r\nHost: httpbin.org\r\n\r\n") == b""


def test_stream_response_cap_is_checked_before_join(monkeypatch):
    monkeypatch.setattr(hb, "MAX_RESPONSE_BYTES", 200)
    with pytest.raises(hb.InvalidRequest):
        endpoint("/stream/1000")


def test_slow_input_has_an_absolute_deadline(monkeypatch):
    class SlowSocket:
        def settimeout(self, value):
            assert value > 0

        def recv(self, cap):
            return b"a"

    times = iter([0, 1, hb.IO_TIMEOUT_SECONDS + 1])
    monkeypatch.setattr(time, "monotonic", lambda: next(times))
    with pytest.raises(hb.InvalidRequest):
        hb._Reader(SlowSocket()).line(hb.MAX_HEADER_BYTES)


@pytest.mark.parametrize("path", [b"/delay/10", b"/%64elay/10"])
def test_delay_is_bounded_and_interruptible(service, path):
    start = time.monotonic()
    with socket.create_connection(("127.0.0.1", service.port), timeout=0.1) as connection:
        connection.sendall(b"GET " + path + b" HTTP/1.1\r\nHost: httpbin.org\r\n\r\n")
        with pytest.raises(socket.timeout):
            connection.recv(1)
    service.close()
    assert time.monotonic() - start < 3
