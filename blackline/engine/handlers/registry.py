"""Deterministic provider-to-handler dispatch registry."""

from __future__ import annotations

from blackline.engine.handlers.base import StepHandler


class HandlerRegistry:
    """Own the executable handler registered for each provider name."""

    def __init__(self) -> None:
        self._handlers: dict[str, StepHandler] = {}

    @property
    def names(self) -> tuple[str, ...]:
        return tuple(self._handlers)

    def register(self, name: str, handler: StepHandler) -> None:
        normalized = name.strip().lower()
        if not normalized:
            raise ValueError("handler name cannot be empty")
        if normalized in self._handlers:
            raise ValueError(f"duplicate execution handler: {normalized}")
        self._handlers[normalized] = handler

    def resolve(self, name: str) -> StepHandler | None:
        return self._handlers.get(name.strip().lower())


def default_handler_registry() -> HandlerRegistry:
    """Build the complete built-in handler registry in stable order."""
    from blackline.engine.handlers.discovery import HANDLERS as DISCOVERY_HANDLERS
    from blackline.engine.handlers.network import HANDLERS as NETWORK_HANDLERS
    from blackline.engine.handlers.tls import HANDLERS as TLS_HANDLERS
    from blackline.engine.handlers.web import HANDLERS as WEB_HANDLERS

    registry = HandlerRegistry()
    for name, handler in (
        *DISCOVERY_HANDLERS,
        *WEB_HANDLERS,
        *TLS_HANDLERS,
        *NETWORK_HANDLERS,
    ):
        registry.register(name, handler)
    return registry
