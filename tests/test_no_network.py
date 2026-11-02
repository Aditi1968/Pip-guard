import socket

import pytest


def test_inet_connect_is_blocked() -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s, pytest.raises(RuntimeError):
        s.connect(("127.0.0.1", 9))
