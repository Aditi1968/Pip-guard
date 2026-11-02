"""Fixture (benign): same API, but the connecting function is never called at import."""

import socket


def phone_home() -> None:
    with socket.create_connection(("203.0.113.10", 443), timeout=1):
        pass
