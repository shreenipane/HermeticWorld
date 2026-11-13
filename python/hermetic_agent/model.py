"""Direct Anthropic Messages client for the local policy gateway."""

from dataclasses import dataclass, asdict
import http.client
import ipaddress
import json
import socket
import time
from urllib.parse import urlsplit

from .errors import GatewayError, LimitError, ProtocolError
from .protocol import parse_json

MAX_MODEL_BODY_BYTES = 4 * 1024 * 1024
MAX_HISTORY_BYTES = 8 * 1024 * 1024
MAX_MESSAGES = 256
MAX_MODEL_TIMEOUT_SECONDS = 300
MAX_MODEL_CALLS = 250
MAX_TOTAL_TOKENS = 4_000_000


class _DeadlineSocket(socket.socket):
    """Include slow HTTP status lines and headers in the absolute call deadline."""

    def __init__(self, family, deadline):
        super().__init__(family, socket.SOCK_STREAM)
        self._deadline = deadline

    def _remaining(self):
        remaining = self._deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError()
        self.settimeout(remaining)

    def recv_into(self, *args):
        self._remaining()
        return super().recv_into(*args)

    def sendall(self, *args):
        self._remaining()
        return super().sendall(*args)


@dataclass(frozen=True)
class ModelConfig:
    model_name: str
    t_clock: str


class HermeticGatewayModel:
    """Implements the pinned Model protocol with the SWE-bench bash text tool."""

    def __init__(self, gateway_url: str, model_name: str, *, t_clock: str, timeout: int = 120):
        from .task import clock_value
        clock_value(t_clock)
        try:
            url = urlsplit(gateway_url)
            if (url.scheme != "http" or not ipaddress.ip_address(url.hostname).is_loopback
                    or url.username or url.password or url.path not in ("", "/")
                    or url.query or url.fragment or url.port is None):
                raise ValueError()
        except (ValueError, TypeError):
            raise ProtocolError("Gateway must be an explicit local HTTP endpoint") from None
        if not isinstance(model_name, str) or not model_name or len(model_name.encode()) > 256:
            raise ProtocolError("Invalid pinned model")
        if type(timeout) is not int or not 0 < timeout <= MAX_MODEL_TIMEOUT_SECONDS:
            raise LimitError("Model deadline limit")
        self.config = ModelConfig(model_name, t_clock)
        self._host, self._port = url.hostname, url.port
        self._timeout = timeout
        self.cost = 0.0
        self.n_calls = 0
        self.tokens = 0
        self._run_deadline = None

    def set_run_deadline(self, deadline):
        self._run_deadline = deadline

    def get_template_vars(self):
        return asdict(self.config)

    def query(self, messages: list[dict[str, str]], **kwargs) -> dict:
        if kwargs:
            raise ProtocolError("Unsupported query options")
        if not isinstance(messages, list) or not 1 <= len(messages) <= MAX_MESSAGES:
            raise LimitError("Message limit")
        system = []
        chat = []
        total_bytes = 0
        for message in messages:
            if not isinstance(message, dict) or not isinstance(message.get("content"), str):
                raise ProtocolError("Invalid message")
            role, content = message.get("role"), message["content"]
            total_bytes += len(content.encode("utf-8"))
            if total_bytes > MAX_HISTORY_BYTES:
                raise LimitError("History byte limit")
            if role == "system" and not chat:
                system.append(content)
            elif role in ("user", "assistant"):
                chat.append({"role": role, "content": content})
            else:
                raise ProtocolError("Invalid message role")
        if not chat or self.n_calls >= MAX_MODEL_CALLS or self.tokens >= MAX_TOTAL_TOKENS:
            raise LimitError("Model run limit")
        body = json.dumps({"model": self.config.model_name, "system": "\n".join(system),
                           "messages": chat, "max_tokens": 8192, "temperature": 0,
                           "stream": False}, separators=(",", ":")).encode()
        if len(body) > MAX_HISTORY_BYTES:
            raise LimitError("Model request byte limit")
        self.n_calls += 1
        end = time.monotonic() + self._timeout
        if self._run_deadline is not None:
            end = min(end, self._run_deadline)
        remaining = end - time.monotonic()
        if remaining <= 0:
            raise LimitError("Run deadline exceeded")
        connection = http.client.HTTPConnection(self._host, self._port, timeout=remaining)
        def connect(address, *args):
            stream = _DeadlineSocket(socket.AF_INET6 if ":" in self._host else socket.AF_INET, end)
            try:
                stream._remaining()
                stream.connect(address)
                return stream
            except BaseException:
                stream.close()
                raise
        connection._create_connection = connect
        try:
            connection.request("POST", "/v1/messages", body=body,
                               headers={"Content-Type": "application/json", "anthropic-version": "2023-06-01"})
            response = connection.getresponse()
            if response.status != 200:
                raise GatewayError("Gateway refused request")
            output = bytearray()
            while len(output) <= MAX_MODEL_BODY_BYTES:
                remaining = end - time.monotonic()
                if remaining <= 0:
                    raise GatewayError("Gateway deadline exceeded")
                if connection.sock is not None:
                    connection.sock.settimeout(remaining)
                part = response.read1(min(65536, MAX_MODEL_BODY_BYTES + 1 - len(output)))
                if not part:
                    break
                output.extend(part)
            if len(output) > MAX_MODEL_BODY_BYTES:
                raise LimitError("Model response byte limit")
        except (OSError, http.client.HTTPException):
            raise GatewayError("Gateway transport failed") from None
        finally:
            connection.close()
        data = parse_json(bytes(output))
        if not isinstance(data, dict) or data.get("type") != "message":
            raise ProtocolError("Invalid gateway message")
        blocks, usage = data.get("content"), data.get("usage")
        if not isinstance(blocks, list) or not isinstance(usage, dict):
            raise ProtocolError("Invalid gateway content")
        text = []
        for block in blocks:
            if not isinstance(block, dict) or block.get("type") != "text" or not isinstance(block.get("text"), str):
                raise ProtocolError("Only bash text responses are supported")
            text.append(block["text"])
        values = [usage.get("input_tokens"), usage.get("output_tokens")]
        if any(type(value) is not int or not 0 <= value <= MAX_TOTAL_TOKENS for value in values):
            raise ProtocolError("Invalid gateway usage")
        self.tokens += sum(values)
        if self.tokens > MAX_TOTAL_TOKENS:
            raise LimitError("Model token limit")
        return {"content": "".join(text)}
