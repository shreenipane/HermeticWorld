"""Typed error definitions for hermetic_assert_flow."""


class FlowError(Exception):
    """Typed error raised on hostile, invalid, or resource-exceeding inputs."""

    def __init__(self, message: str, code: str = "FLOW_ERROR") -> None:
        super().__init__(message)
        self.code = code
