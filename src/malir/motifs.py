"""Bounded behavior-path construction without a whole-program call graph."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass

from .policy import is_destructive_delete, is_sensitive_env_name
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


@dataclass(frozen=True, slots=True)
class MotifPolicy:
    reason: str
    dataflow_score: float
    proximity_score: float


MOTIF_POLICIES = {
    "credential_or_file_exfil": MotifPolicy(
        "sensitive data flows into an outbound transfer",
        36.0,
        2.0,
    ),
    "fingerprinting_transfer": MotifPolicy(
        "host discovery data flows into an outbound transfer",
        24.0,
        2.0,
    ),
    "file_to_network": MotifPolicy(
        "file content flows into an outbound transfer",
        14.0,
        1.0,
    ),
    "download_execute": MotifPolicy(
        "remote input flows into code or process execution",
        42.0,
        4.0,
    ),
    "encoded_execution": MotifPolicy(
        "decoded or deserialized data flows into execution",
        40.0,
        6.0,
    ),
}


def make_dataflow_path(
    motif: str,
    indexes: tuple[int, ...],
    *,
    through_summary: bool = False,
) -> BehaviorPath:
    policy = MOTIF_POLICIES[motif]
    return BehaviorPath(
        motif=motif,
        score=policy.dataflow_score,
        reason=(
            f"{policy.reason}; bounded direct-call summary"
            if through_summary
            else policy.reason
        ),
        event_indexes=indexes,
        evidence_kind="summary" if through_summary else "dataflow",
        confidence="medium" if through_summary else "high",
    )


def build_behavior_paths(
    events: list[Event],
    dataflow_paths: list[BehaviorPath] | None = None,
    window: int = 12,
) -> list[BehaviorPath]:
    """Combine causal flows, weak proximity fallbacks, and structural paths.

    Local data flow and bounded direct-call summaries are preferred whenever the
    same source/sink endpoints are available. Proximity remains visible for
    analyst review but has deliberately low weight so unrelated operations do
    not become a strong alert.
    """
    paths = list(dataflow_paths or [])
    seen = {(item.motif, item.event_indexes, item.evidence_kind) for item in paths}
    exact_endpoints = {
        (item.motif, source_index, item.event_indexes[-1])
        for item in paths
        if item.evidence_kind in {"dataflow", "summary"}
        for source_index in item.event_indexes[:-1]
    }

    groups: dict[tuple[str, str], list[tuple[int, Event]]] = defaultdict(list)
    for index, event in enumerate(events):
        groups[(event.path, event.function)].append((index, event))

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
                    if source.op == "SENSITIVE_FILE_READ" or (
                        source.op == "ENV_READ" and is_sensitive_env_name(source.target)
                    ):
                        _append_proximity(
                            paths,
                            seen,
                            exact_endpoints,
                            "credential_or_file_exfil",
                            (source_index, sink_index),
                        )
                    elif source.op == "SYSTEM_DISCOVERY":
                        _append_proximity(
                            paths,
                            seen,
                            exact_endpoints,
                            "fingerprinting_transfer",
                            (source_index, sink_index),
                        )
                    elif source.op == "FILE_READ":
                        _append_proximity(
                            paths,
                            seen,
                            exact_endpoints,
                            "file_to_network",
                            (source_index, sink_index),
                        )
            if sink.op in EXECUTION_SINKS:
                remote = [
                    (index, event)
                    for index, event in sources
                    if event.op == "NETWORK_RECEIVE"
                ]
                if remote:
                    _append_proximity(
                        paths,
                        seen,
                        exact_endpoints,
                        "download_execute",
                        (remote[-1][0], sink_index),
                    )
                if transforms:
                    _append_proximity(
                        paths,
                        seen,
                        exact_endpoints,
                        "encoded_execution",
                        (transforms[-1][0], sink_index),
                    )
                if sink.phase == "install":
                    _append_structural(
                        paths,
                        seen,
                        "install_time_execution",
                        30.0,
                        "execution occurs during package installation",
                        (sink_index,),
                    )
            if sink.op == "PERSISTENCE_WRITE":
                _append_structural(
                    paths,
                    seen,
                    "persistence_write",
                    34.0,
                    "code writes to a common autostart location",
                    (sink_index,),
                )
            if sink.op == "FILE_DELETE" and is_destructive_delete(
                sink.target,
                recursive=sink.detail == "recursive directory deletion",
            ):
                _append_structural(
                    paths,
                    seen,
                    "destructive_file_action",
                    18.0,
                    "code deletes broad, user-data, or recursive filesystem content",
                    (sink_index,),
                )
    return sorted(
        paths,
        key=lambda item: (
            -item.score,
            item.event_indexes,
            item.motif,
            item.evidence_kind,
        ),
    )


def _append_proximity(
    output: list[BehaviorPath],
    seen: set[tuple[str, tuple[int, ...], str]],
    exact_endpoints: set[tuple[str, int, int]],
    motif: str,
    indexes: tuple[int, ...],
) -> None:
    if (motif, indexes[0], indexes[-1]) in exact_endpoints:
        return
    key = motif, indexes, "proximity"
    if key in seen:
        return
    seen.add(key)
    policy = MOTIF_POLICIES[motif]
    output.append(
        BehaviorPath(
            motif=motif,
            score=policy.proximity_score,
            reason=(
                policy.reason.replace(" flows into ", " appears near ")
                + "; exact value flow was not proven"
            ),
            event_indexes=indexes,
            evidence_kind="proximity",
            confidence="low",
        )
    )


def _append_structural(
    output: list[BehaviorPath],
    seen: set[tuple[str, tuple[int, ...], str]],
    motif: str,
    score: float,
    reason: str,
    indexes: tuple[int, ...],
) -> None:
    key = motif, indexes, "structural"
    if key in seen:
        return
    seen.add(key)
    output.append(
        BehaviorPath(
            motif=motif,
            score=score,
            reason=reason,
            event_indexes=indexes,
            evidence_kind="structural",
            confidence="high",
        )
    )
