"""Canonical semantic tokens shared by training and inference."""

from __future__ import annotations

import re
from collections.abc import Iterable

from .types import Event

_EVENT = re.compile(
    r"^P:(?P<phase>[^|]+)\|C:(?P<category>[^|]+)"
    r"\|O:(?P<operation>[^|]+)\|T:(?P<target>.*)$"
)
_SENSITIVE_MARKERS = {
    "api_key",
    "apikey",
    "cookie",
    "credential",
    "id_ed25519",
    "id_rsa",
    "passwd",
    "password",
    "private_key",
    "secret",
    "token",
    "wallet",
}
_ORIGINS = {
    "ENV_READ": "environment",
    "SENSITIVE_FILE_READ": "sensitive_local_file",
    "FILE_READ": "local_file",
    "SYSTEM_DISCOVERY": "host_state",
    "NETWORK_RECEIVE": "network",
}
_DESTINATIONS = {
    "FILE_WRITE": "local_artifact",
    "NETWORK_SEND": "network",
    "PROCESS_EXEC": "process",
    "PERSISTENCE_WRITE": "persistence",
    "FILE_DELETE": "filesystem_delete",
}
_TRANSFORMATIONS = {
    "ENCODE": "encoding",
    "DECODE": "decoding",
    "DYNAMIC_IMPORT": "dynamic_loading",
    "CODE_COMPILE": "code_compilation",
    "DYNAMIC_EXEC": "dynamic_execution",
    "UNSAFE_DESERIALIZE": "unsafe_deserialization",
}
_FLOW_BY_MOTIF = {
    "credential_or_file_exfil": "sensitive_data_to_network",
    "fingerprinting_transfer": "host_state_to_network",
    "file_to_network": "local_file_to_network",
    "download_execute": "network_to_execution",
    "encoded_execution": "encoded_data_to_execution",
    "persistence_write": "code_to_persistence",
    "destructive_file_action": "code_to_filesystem_delete",
}
_PURPOSE_BY_MOTIF = {
    "credential_or_file_exfil": "sensitive_data_transfer",
    "download_execute": "remote_code_executor",
    "persistence_write": "persistence_modifier",
    "destructive_file_action": "destructive_file_operator",
}
_IMPORT_TIME_EFFECTS = {
    "DYNAMIC_EXEC",
    "PROCESS_EXEC",
    "NETWORK_SEND",
    "PERSISTENCE_WRITE",
    "FILE_DELETE",
}


def model_target_class(operation: str, target: str) -> str:
    normalized = target.lower().replace("\\", "/").replace(" ", "_")
    if operation in {"NETWORK_SEND", "NETWORK_RECEIVE"}:
        return "network"
    if operation in {"SENSITIVE_FILE_READ", "PERSISTENCE_WRITE"}:
        return "sensitive"
    if operation == "ENV_READ" and any(
        marker in normalized for marker in _SENSITIVE_MARKERS
    ):
        return "sensitive"
    if operation in {"FILE_READ", "FILE_WRITE", "FILE_DELETE"}:
        return "file"
    if "/" in normalized or normalized.startswith("."):
        return "path"
    return "generic"


def model_event_token(event: Event) -> str:
    target = model_target_class(event.op, event.target)
    return f"P:{event.phase}|C:{event.category}|O:{event.op}|T:{target}"


def canonicalize_model_tokens(tokens: Iterable[str]) -> list[str]:
    """Normalize targets and derive ordered effect context for datasets."""

    output = ["FILE"]
    seen: set[str] = set()
    operations: set[str] = set()
    phases: set[str] = set()
    import_operations: set[str] = set()
    motifs: set[str] = set()
    entries: set[str] = set()
    origins: set[str] = set()
    destinations: set[str] = set()
    transformations: set[str] = set()
    flows: set[str] = set()
    purposes: set[str] = set()

    def append(token: str) -> None:
        if token == "FILE" or token in seen:
            return
        seen.add(token)
        output.append(token)

    for raw in tokens:
        token = str(raw)
        if token == "FILE" or token.startswith("FILE:"):
            continue
        match = _EVENT.fullmatch(token)
        if match:
            phase = match.group("phase")
            category = match.group("category")
            operation = match.group("operation")
            target = model_target_class(operation, match.group("target"))
            append(f"P:{phase}|C:{category}|O:{operation}|T:{target}")
            phases.add(phase)
            operations.add(operation)
            if phase == "import":
                import_operations.add(operation)
            continue
        if token.startswith("MOTIF:"):
            motifs.add(token.removeprefix("MOTIF:"))
            append(token)
            continue
        if token.startswith("EFFECT:ENTRY:"):
            entries.add(token.removeprefix("EFFECT:ENTRY:"))
            continue
        if token.startswith("EFFECT:ORIGIN:"):
            origins.add(token.removeprefix("EFFECT:ORIGIN:"))
            continue
        if token.startswith("EFFECT:DESTINATION:"):
            destinations.add(token.removeprefix("EFFECT:DESTINATION:"))
            continue
        if token.startswith("EFFECT:FLOW:"):
            flows.add(token.removeprefix("EFFECT:FLOW:"))
            continue
        if token.startswith("EFFECT:TRANSFORM:"):
            transformations.add(token.removeprefix("EFFECT:TRANSFORM:"))
            continue
        if token.startswith("PURPOSE:"):
            purposes.add(token.removeprefix("PURPOSE:"))
            continue
        append(token)

    if not entries:
        if "install" in phases:
            entries.add("install_time")
        elif import_operations & _IMPORT_TIME_EFFECTS:
            entries.add("import_time_effects")
        else:
            entries.add("library_callable")

    origins.update(
        _ORIGINS[operation] for operation in operations if operation in _ORIGINS
    )
    destinations.update(
        _DESTINATIONS[operation]
        for operation in operations
        if operation in _DESTINATIONS
    )
    transformations.update(
        _TRANSFORMATIONS[operation]
        for operation in operations
        if operation in _TRANSFORMATIONS
    )
    flows.update(_FLOW_BY_MOTIF[motif] for motif in motifs if motif in _FLOW_BY_MOTIF)
    purposes.update(
        _PURPOSE_BY_MOTIF[motif] for motif in motifs if motif in _PURPOSE_BY_MOTIF
    )

    dimensions = (
        ("EFFECT:ENTRY:", entries),
        ("EFFECT:ORIGIN:", origins),
        ("EFFECT:DESTINATION:", destinations),
        ("EFFECT:FLOW:", flows),
        ("EFFECT:TRANSFORM:", transformations),
        ("PURPOSE:", purposes),
    )
    for prefix, values in dimensions:
        for value in sorted(values):
            append(f"{prefix}{value}")
    return output
