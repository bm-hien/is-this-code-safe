"""Canonical semantic tokens shared by training and inference."""

from __future__ import annotations

import re
from collections.abc import Iterable

from .policy import delete_target_class, is_sensitive_env_name, process_target_class
from .types import Event

_EVENT = re.compile(
    r"^P:(?P<phase>[^|]+)\|C:(?P<category>[^|]+)"
    r"\|O:(?P<operation>[^|]+)\|T:(?P<target>.*)$"
)
_PATH = re.compile(
    r"^PATH:(?P<motif>[^|]+)\|K:(?P<kind>[^|]+)\|Q:(?P<confidence>[^|]+)$"
)
_PURPOSE = re.compile(r"^PURPOSE:(?P<label>[^|]+)(?:\|Q:(?P<confidence>[^|]+))?$")
_STRUCTURAL_MOTIFS = {
    "destructive_file_action",
    "install_time_execution",
    "persistence_write",
}
_LEGACY_PURPOSE_CONFIDENCE = {"local_code_transformer": "medium"}
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
    if operation == "ENV_READ" and is_sensitive_env_name(target):
        return "sensitive"
    if operation == "PROCESS_EXEC":
        if target in {
            "process_build_tool",
            "process_compiler",
            "process_generic",
            "process_interpreter",
            "process_package_tool",
            "process_shell",
        }:
            return target
        return f"process_{process_target_class(target)}"
    if operation == "FILE_DELETE":
        if target in {
            "delete_broad",
            "delete_generic",
            "delete_temporary",
            "delete_user_data",
        }:
            return target
        target_class = delete_target_class(target)
        return f"delete_{target_class}"
    if operation in {"FILE_READ", "FILE_WRITE"}:
        return "file"
    if "/" in normalized or normalized.startswith("."):
        return "path"
    return "generic"


def model_event_token(event: Event) -> str:
    target = model_target_class(event.op, event.target)
    return f"P:{event.phase}|C:{event.category}|O:{event.op}|T:{target}"


def _semantic_token(value: str) -> str:
    return value.lower().replace("-", "_").replace(" ", "_")


def _legacy_path_context(motif: str) -> tuple[str, str]:
    if motif in _STRUCTURAL_MOTIFS:
        return "structural", "high"
    return "dataflow", "high"


def canonicalize_model_tokens(tokens: Iterable[str]) -> list[str]:
    """Normalize targets and preserve evidence strength for model datasets."""

    output = ["FILE"]
    seen: set[str] = set()
    operations: set[str] = set()
    import_operations: set[str] = set()
    paths: set[tuple[str, str, str]] = set()
    entries: set[str] = set()
    origins: set[str] = set()
    destinations: set[str] = set()
    transformations: set[str] = set()
    flows: set[str] = set()
    purposes: set[tuple[str, str]] = set()

    def append(token: str) -> None:
        if token == "FILE" or token in seen:
            return
        seen.add(token)
        output.append(token)

    for raw in tokens:
        token = str(raw)
        if token == "FILE" or token.startswith("FILE:"):
            continue
        event_match = _EVENT.fullmatch(token)
        if event_match:
            phase = event_match.group("phase")
            category = event_match.group("category")
            operation = event_match.group("operation")
            target = model_target_class(operation, event_match.group("target"))
            append(f"P:{phase}|C:{category}|O:{operation}|T:{target}")
            operations.add(operation)
            if phase == "import":
                import_operations.add(operation)
            continue
        path_match = _PATH.fullmatch(token)
        if path_match:
            motif = _semantic_token(path_match.group("motif"))
            kind = _semantic_token(path_match.group("kind"))
            confidence = _semantic_token(path_match.group("confidence"))
            paths.add((motif, kind, confidence))
            append(f"PATH:{motif}|K:{kind}|Q:{confidence}")
            continue
        if token.startswith("MOTIF:"):
            motif = _semantic_token(token.removeprefix("MOTIF:"))
            kind, confidence = _legacy_path_context(motif)
            paths.add((motif, kind, confidence))
            append(f"PATH:{motif}|K:{kind}|Q:{confidence}")
            continue
        if token.startswith("EFFECT:ENTRY:"):
            value = _semantic_token(token.removeprefix("EFFECT:ENTRY:"))
            entries.add("import_time_effects" if value == "install_time" else value)
            continue
        if token.startswith("EFFECT:ORIGIN:"):
            origins.add(_semantic_token(token.removeprefix("EFFECT:ORIGIN:")))
            continue
        if token.startswith("EFFECT:DESTINATION:"):
            destinations.add(_semantic_token(token.removeprefix("EFFECT:DESTINATION:")))
            continue
        if token.startswith("EFFECT:FLOW:"):
            flows.add(_semantic_token(token.removeprefix("EFFECT:FLOW:")))
            continue
        if token.startswith("EFFECT:TRANSFORM:"):
            transformations.add(
                _semantic_token(token.removeprefix("EFFECT:TRANSFORM:"))
            )
            continue
        purpose_match = _PURPOSE.fullmatch(token)
        if purpose_match:
            label = _semantic_token(purpose_match.group("label"))
            confidence = purpose_match.group("confidence")
            if confidence is None:
                confidence = _LEGACY_PURPOSE_CONFIDENCE.get(label, "high")
            purposes.add((label, _semantic_token(confidence)))
            continue
        append(token)

    if not entries:
        if import_operations & _IMPORT_TIME_EFFECTS:
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
    for motif, kind, confidence in paths:
        if kind != "proximity" and motif in _FLOW_BY_MOTIF:
            flows.add(_FLOW_BY_MOTIF[motif])
        if motif in _PURPOSE_BY_MOTIF:
            purposes.add((_PURPOSE_BY_MOTIF[motif], confidence))

    dimensions = (
        ("EFFECT:ENTRY:", entries),
        ("EFFECT:ORIGIN:", origins),
        ("EFFECT:DESTINATION:", destinations),
        ("EFFECT:FLOW:", flows),
        ("EFFECT:TRANSFORM:", transformations),
    )
    for prefix, values in dimensions:
        for value in sorted(values):
            append(f"{prefix}{value}")
    for label, confidence in sorted(purposes):
        append(f"PURPOSE:{label}|Q:{confidence}")
    return output
