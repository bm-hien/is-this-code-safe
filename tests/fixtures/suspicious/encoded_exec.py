"""Inert test fixture with a harmless literal payload."""

from base64 import b64decode as unpack


def uncalled_fixture() -> None:
    exec(unpack(b"cHJpbnQoJ2ZpeHR1cmUnKQ=="))
