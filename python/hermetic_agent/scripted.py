"""Finite offline command source for integration smoke runs."""

from .errors import ProtocolError, LimitError
from .model import ModelConfig
from .protocol import MAX_COMMAND_BYTES
from .task import clock_value


class ScriptedModel:
    def __init__(self, commands, *, t_clock):
        clock_value(t_clock)
        if (not isinstance(commands, list) or not 1 <= len(commands) <= 60
                or any(not isinstance(c, str) or len(c.encode()) > MAX_COMMAND_BYTES or "```" in c for c in commands)):
            raise ProtocolError("Invalid smoke script")
        self._commands = iter(commands)
        self.config = ModelConfig("scripted", t_clock)
        self.n_calls = 0
        self.cost = 0.0

    def get_template_vars(self):
        return {"t_clock": self.config.t_clock}

    def query(self, messages, **kwargs):
        try:
            command = next(self._commands)
        except StopIteration:
            raise LimitError("Smoke script exhausted") from None
        self.n_calls += 1
        return {"content": f"```bash\n{command}\n```"}
