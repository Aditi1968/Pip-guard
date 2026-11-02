import os


def connect(host):
    import socket

    return socket.create_connection((host, 80)), os.environ.get("HOME")
