"""Public failures contain no transport diagnostics or upstream bodies."""


class HarnessError(Exception):
    """A closed, bounded harness failure."""


class ProtocolError(HarnessError):
    pass


class LimitError(HarnessError):
    pass


class TransportError(HarnessError):
    pass


class ExecutionTimeout(HarnessError, TimeoutError):
    def __init__(self, output: str = ""):
        super().__init__("Command deadline exceeded")
        self.output = output.encode("utf-8")


class GatewayError(HarnessError):
    pass
