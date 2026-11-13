"""Offline hostile-peer and known-answer tests for the Mode H adapters."""

import contextlib
import http.server
import json
import importlib.util
import os
from pathlib import Path
import socket
import struct
import sys
import threading
import time

import pytest

from hermetic_agent.environment import ExecdEnvironment
from hermetic_agent.errors import (ExecutionTimeout, GatewayError, HarnessError,
                                   LimitError, ProtocolError)
from hermetic_agent.model import HermeticGatewayModel
from hermetic_agent.protocol import (ExecdClient, MAX_FRAME_BYTES, MAX_OUTPUT_BYTES,
                                     encode_frame, parse_json)
from hermetic_agent.task import task_clock

CLOCK = "2001-02-03T04:05:06Z"


@contextlib.contextmanager
def execd(tmp_path, responder):
    path = str(tmp_path / "vsock")
    errors = []
    with socket.socket(socket.AF_UNIX) as listener:
        listener.bind(path)
        listener.listen(1)
        listener.settimeout(3)

        def serve():
            try:
                with listener.accept()[0] as connection:
                    connection.settimeout(3)
                    with connection.makefile("rb") as source:
                        assert source.readline(65) == b"CONNECT 5000\n"
                        connection.sendall(b"OK 5000\n")
                        length, = struct.unpack("<I", source.read(4))
                        assert length <= MAX_FRAME_BYTES
                        request = parse_json(source.read(length))
                        responder(connection, request)
            except BaseException as exc:
                errors.append(exc)
        thread = threading.Thread(target=serve)
        thread.start()
        try:
            yield path
        finally:
            thread.join(4)
            assert not thread.is_alive()
            if errors:
                raise errors[0]


def reply(output=b"hi", **kwargs):
    return {"type": "exec", "code": 0, "output": list(output),
            "truncated": False, "timed_out": False} | kwargs


def test_execd_known_answers_match_shared_rust_vectors():
    vectors = json.loads((Path(__file__).parents[1] / "hermetic_agent/wire-vectors.json").read_bytes())
    assert encode_frame(vectors["request"]) == bytes(vectors["request_bytes"])
    assert encode_frame(vectors["reply"]) == bytes(vectors["reply_bytes"])
    raw = bytes(vectors["reply_bytes"])
    assert struct.unpack("<I", raw[:4])[0] == len(raw) - 4
    assert parse_json(raw[4:]) == reply()


def test_environment_executes_only_through_execd_and_quotes_cwd(tmp_path):
    def respond(connection, request):
        assert request == {"type": "exec", "argv": ["/bin/bash", "--noprofile", "--norc", "-c",
            "cd -- '/work/has space' && printf hi"], "tty": False, "timeout_ms": 1500}
        connection.sendall(encode_frame(reply()))
    with execd(tmp_path, respond) as path:
        env = ExecdEnvironment(path, cwd="/work/has space")
        assert env.execute("printf hi", timeout=1.5) == {"returncode": 0, "output": "hi"}
        assert path not in str(env.get_template_vars())


@pytest.mark.parametrize("output", [reply(timed_out=True), reply(code="host-secret"),
    reply(output=[-1]), reply(output=[True]), reply(extra="host-secret")])
def test_environment_rejects_hostile_or_timed_out_replies(tmp_path, output):
    with execd(tmp_path, lambda c, _: c.sendall(encode_frame(output))) as path:
        with pytest.raises(HarnessError) as error:
            ExecdEnvironment(path, cwd="/work").execute("true")
        assert "host-secret" not in str(error.value)


def test_output_is_capped_before_returning_to_agent(tmp_path):
    with execd(tmp_path, lambda c, _: c.sendall(encode_frame(reply(b"a" * (MAX_OUTPUT_BYTES + 20))))) as path:
        result = ExecdEnvironment(path, cwd="/work").execute("true")
    marker = "\n[output truncated]"
    assert result["output"] == "a" * (MAX_OUTPUT_BYTES-len(marker)) + marker
    assert len(result["output"].encode()) <= MAX_OUTPUT_BYTES


def test_invalid_utf8_cannot_expand_past_output_byte_cap(tmp_path):
    with execd(tmp_path, lambda c, _: c.sendall(encode_frame(reply(b"\xff" * MAX_OUTPUT_BYTES)))) as path:
        output = ExecdEnvironment(path,cwd="/work").execute("true")["output"]
    assert output.endswith("[output truncated]")
    assert len(output.encode()) <= MAX_OUTPUT_BYTES


@pytest.mark.parametrize("length", [0, MAX_FRAME_BYTES + 1, 0xffffffff])
def test_oversize_peer_length_refused_before_body_read(tmp_path, length):
    with execd(tmp_path, lambda c, _: c.sendall(struct.pack("<I", length))) as path:
        with pytest.raises(LimitError):
            ExecdClient(path).call({"type": "status"})


def test_slow_peer_has_absolute_deadline(tmp_path):
    def slow(connection, _):
        connection.sendall(struct.pack("<I", 100))
        for _ in range(20):
            try:
                connection.sendall(b" ")
                time.sleep(.02)
            except (BrokenPipeError, ConnectionResetError):
                break
    with execd(tmp_path, slow) as path:
        started = time.monotonic()
        with pytest.raises(ExecutionTimeout):
            ExecdClient(path).call({"type": "status"}, timeout=.08)
        assert time.monotonic() - started < 1


@pytest.mark.parametrize("raw", [b'{"a":1,"a":2}', b'{"a":NaN}', b'[' * 1000, b'\xff'])
def test_hostile_json_is_typed(raw):
    with pytest.raises(ProtocolError):
        parse_json(raw)


def test_surrogate_json_is_refused_before_rendering():
    with pytest.raises(ProtocolError):
        parse_json(b'{"content":"\\ud800"}')


def test_command_size_matches_execd_single_argument_cap():
    env = ExecdEnvironment("/not-contacted", cwd="/work")
    with pytest.raises(LimitError):
        env.execute("x" * 4096)


def test_run_deadline_prevents_next_command_or_model_request():
    environment = ExecdEnvironment("/not-contacted",cwd="/work")
    model = HermeticGatewayModel("http://127.0.0.1:1","pinned",t_clock=CLOCK)
    for component in (environment,model):
        component.set_run_deadline(time.monotonic()-1)
    with pytest.raises(LimitError):
        environment.execute("true")
    with pytest.raises(LimitError):
        model.query([{"role":"user","content":"x"}])


@pytest.mark.parametrize("timeout", [10**10000, float("nan"), float("inf"), True, 0, -1],
                         ids=["huge-integer","nan","infinity","boolean","zero","negative"])
def test_hostile_timeout_values_are_typed_limits(timeout):
    with pytest.raises(LimitError):
        ExecdEnvironment("/not-contacted",cwd="/work",timeout=timeout)
    with pytest.raises(LimitError):
        ExecdClient("/not-contacted").call({"type":"status"},timeout=timeout)


def test_command_journal_precedes_execution_and_stops_on_write_failure(tmp_path):
    from hermetic_agent.journal import CommandJournal
    from hermetic_agent.task import clock_value
    log = tmp_path / "commands.jsonl"
    journal = CommandJournal(log, t_clock=CLOCK)
    def respond(connection, _):
        record = json.loads(log.read_text())
        assert record == {"type":"command","action":"true","cwd":"/work", "timestamp":clock_value(CLOCK)}
        connection.sendall(encode_frame(reply()))
    with execd(tmp_path, respond) as path:
        ExecdEnvironment(path, cwd="/work", journal=journal).execute("true")
    assert len(log.read_text().splitlines()) == 2
    assert log.stat().st_mode & 0o777 == 0o600
    log.unlink()
    log.symlink_to(tmp_path / "outside")
    env = ExecdEnvironment("/not-contacted", cwd="/work", journal=journal)
    with pytest.raises(OSError):
        env.execute("true")
    assert not (tmp_path / "outside").exists()


@contextlib.contextmanager
def gateway(responder):
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            length = int(self.headers["Content-Length"])
            assert length < 1024 * 1024
            data = json.loads(self.rfile.read(length))
            status, body = responder(self.path, dict(self.headers), data)
            self.send_response_only(status)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass
    server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    server.timeout = 3
    thread = threading.Thread(target=server.handle_request)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        thread.join(4)
        server.server_close()
        assert not thread.is_alive()


def test_model_uses_messages_api_and_drops_host_metadata(monkeypatch):
    monkeypatch.setenv("HTTP_PROXY", "http://host-secret:1234")
    seen = []
    def respond(path, headers, data):
        seen.append(data)
        assert path == "/v1/messages"
        assert not any(k.lower() in ("authorization", "x-api-key") for k in headers)
        return 200, json.dumps({"type":"message", "content":[{"type":"text","text":"```bash\ntrue\n```"}],
                               "usage":{"input_tokens":5,"output_tokens":8}}).encode()
    with gateway(respond) as url:
        model = HermeticGatewayModel(url, "pinned", t_clock=CLOCK)
        result = model.query([{"role":"system","content":"world", "timestamp":99999999},
                              {"role":"user","content":"fix", "host":"host-secret"}])
    assert result == {"content":"```bash\ntrue\n```"}
    assert model.n_calls == 1 and model.tokens == 13
    assert seen[0]["messages"] == [{"role":"user","content":"fix"}]
    assert "host-secret" not in json.dumps(seen)
    assert model.get_template_vars() == {"model_name":"pinned","t_clock":CLOCK}


@pytest.mark.parametrize("status, body", [(500,b"host-secret"),(200,b"[]"),
    (200,b'{"type":"message","content":[],"usage":{"input_tokens":true,"output_tokens":0}}')])
def test_gateway_errors_never_echo_body(status, body):
    with gateway(lambda *_: (status,body)) as url:
        with pytest.raises(HarnessError) as error:
            HermeticGatewayModel(url,"pinned",t_clock=CLOCK).query([{"role":"user","content":"x"}])
    assert "host-secret" not in str(error.value)


@pytest.mark.parametrize("url", ["https://example.com", "http://localhost:80", "http://127.0.0.1:80/evil",
                                  "http://secret@127.0.0.1:80", "http://127.0.0.1:80?x=secret"])
def test_model_refuses_remote_or_ambiguous_gateway(url):
    with pytest.raises(ProtocolError):
        HermeticGatewayModel(url,"pinned",t_clock=CLOCK)


def test_model_response_cap_is_enforced_before_json(monkeypatch):
    import hermetic_agent.model as module
    monkeypatch.setattr(module,"MAX_MODEL_BODY_BYTES",32)
    with gateway(lambda *_: (200,b"x"*100)) as url:
        with pytest.raises(LimitError):
            HermeticGatewayModel(url,"pinned",t_clock=CLOCK).query([{"role":"user","content":"x"}])


def test_model_slow_status_line_cannot_extend_absolute_deadline():
    errors = []
    with socket.socket(socket.AF_INET) as listener:
        listener.bind(("127.0.0.1",0))
        listener.listen(1)
        listener.settimeout(3)
        port = listener.getsockname()[1]
        def serve():
            try:
                with listener.accept()[0] as connection:
                    connection.settimeout(3)
                    connection.recv(8192)
                    for byte in b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n":
                        try:
                            connection.sendall(bytes([byte]))
                        except OSError:
                            break
                        time.sleep(.05)
            except BaseException as exc:
                errors.append(exc)
        thread = threading.Thread(target=serve)
        thread.start()
        started = time.monotonic()
        with pytest.raises(GatewayError):
            HermeticGatewayModel(f"http://127.0.0.1:{port}","pinned",t_clock=CLOCK,timeout=1).query(
                [{"role":"user","content":"x"}])
        assert time.monotonic() - started < 1.8
        thread.join(4)
        assert not thread.is_alive() and not errors


def test_manifest_clock_has_no_fallback_and_refuses_symlinks(tmp_path):
    path = tmp_path / "world.json"
    path.write_text(json.dumps({"cutoffs":{"t_clock":CLOCK}}))
    assert task_clock(path) == CLOCK
    link = tmp_path / "link"
    link.symlink_to(tmp_path, target_is_directory=True)
    with pytest.raises(ProtocolError):
        task_clock(link / "world.json")
    path.write_text("{}")
    with pytest.raises(ProtocolError):
        task_clock(path)


def test_runner_uses_real_pinned_agent_and_world_clock(tmp_path, monkeypatch):
    if importlib.util.find_spec("minisweagent") is None:
        pytest.skip("optional harness extra is not installed")
    from hermetic_agent.runner import run
    from hermetic_agent.scripted import ScriptedModel
    from hermetic_agent.task import clock_value
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    observations = []
    class Environment:
        def get_template_vars(self):
            return {"cwd":"/testbed"}
        def execute(self, action, cwd=""):
            observations.append(action)
            return {"output": "COMPLETE_TASK_AND_SUBMIT_FINAL_OUTPUT\n", "returncode":0}
    result = run(ScriptedModel(["echo COMPLETE_TASK_AND_SUBMIT_FINAL_OUTPUT"], t_clock=CLOCK),
                 Environment(), "fix the issue", config_dir=str(private))
    assert result["status"] == "Submitted"
    assert len(observations) == 1
    assert {m["timestamp"] for m in result["messages"]} == {clock_value(CLOCK)}
    assert CLOCK in result["messages"][0]["content"]
    assert str(tmp_path) not in json.dumps(result)
    assert not any(name in sys.modules for name in ("litellm", "tiktoken", "huggingface_hub"))
