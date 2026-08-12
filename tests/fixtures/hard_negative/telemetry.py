"""Inert hard negative: a local setting is unrelated to public telemetry."""

import os

import requests


def send_health_status():
    local_mode = os.getenv("DISPLAY_MODE", "compact")
    print(f"local display mode: {local_mode}")
    return requests.post(
        "https://telemetry.example.invalid/health",
        json={"service": "ready"},
    )
