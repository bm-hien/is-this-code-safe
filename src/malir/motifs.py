"""Bounded behavior-path construction without a full call graph."""

from __future__ import annotations

from collections import defaultdict

from .types import BehaviorPath, Event

SOURCE_OPS = {
    "ENV_READ",
    "SENSITIVE_FILE_READ",
    "FILE_READ",
    "SYSTEM_DISCOVERY",
    "NETWORK_RECEIVE",
}
TRANSFORM_OPS = {"ENCODE", "DECODE", "UNSAFE_DESERIALIZE"}
EXECUTION_SINKS = {"DYNAMIC_EXEC", "PROCESS_EXEC"}


def build_behavior_paths(
    events: list[Event],
    window: int = 12,
) -> list[BehaviorPath]:
    """Find conservative, local proximity motifs.

    This does not claim exact data flow. Event indexes preserve the evidence
    needed for a reviewer to verify each result.
    """
    groups: dict[tuple[str, str], list[tuple[int, Event]]] = defaultdict(list)
    for index, event in enumerate(events):
        groups[(event.path, event.function)].append((index, event))

    paths: list[BehaviorPath] = []
    seen: set[tuple[str, tuple[int, ...]]] = set()
    for group in groups.values():
        for offset, (sink_index, sink) in enumerate(group):
            earlier = group[max(0, offset - window) : offset]
            transforms = [
                (index, event) for index, event in earlier if event.op in TRANSFORM_OPS
            ]
            sources = [
                (index, event) for index, event in earlier if event.op in SOURCE_OPS
            ]
            if sink.op == "NETWORK_SEND":
                for source_index, source in sources[-2:]:
                    if source.op in {"ENV_READ", "SENSITIVE_FILE_READ"}:
                        _append(
                            paths,
                            seen,
                            "credential_or_file_exfil",
                            36.0,
                            "sensitive source appears near an outbound transfer",
                            (source_index, sink_index),
                        )
                    elif source.op == "SYSTEM_DISCOVERY":
                        _append(
                            paths,
                            seen,
                            "fingerprinting_transfer",
                            24.0,
                            "host discovery appears near an outbound transfer",
                            (source_index, sink_index),
                        )
                    elif source.op == "FILE_READ":
                        _append(
                            paths,
                            seen,
                            "file_to_network",
                            14.0,
                            "file read appears near an outbound transfer",
                            (source_index, sink_index),
                        )
            if sink.op in EXECUTION_SINKS:
                remote = [
                    (index, event)
                    for index, event in sources
                    if event.op == "NETWORK_RECEIVE"
                ]
                if remote:
                    _append(
                        paths,
                        seen,
                        "download_execute",
                        42.0,
                        "remote input appears near code or process execution",
                        (remote[-1][0], sink_index),
                    )
                if transforms:
                    _append(
                        paths,
                        seen,
                        "encoded_execution",
                        40.0,
                        "decoded or deserialized data appears near execution",
                        (transforms[-1][0], sink_index),
                    )
                if sink.phase == "install":
                    _append(
                        paths,
                        seen,
                        "install_time_execution",
                        30.0,
                        "execution occurs during package installation",
                        (sink_index,),
                    )
            if sink.op == "PERSISTENCE_WRITE":
                _append(
                    paths,
                    seen,
                    "persistence_write",
                    34.0,
                    "code writes to a common autostart location",
                    (sink_index,),
                )
            if sink.op == "FILE_DELETE":
                _append(
                    paths,
                    seen,
                    "destructive_file_action",
                    18.0,
                    "code deletes a file or directory",
                    (sink_index,),
                )
    return sorted(paths, key=lambda item: (-item.score, item.event_indexes))


def _append(
    output: list[BehaviorPath],
    seen: set[tuple[str, tuple[int, ...]]],
    motif: str,
    score: float,
    reason: str,
    indexes: tuple[int, ...],
) -> None:
    key = motif, indexes
    if key in seen:
        return
    seen.add(key)
    output.append(
        BehaviorPath(
            motif=motif,
            score=score,
            reason=reason,
            event_indexes=indexes,
        )
    )
