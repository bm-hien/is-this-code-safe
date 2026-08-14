#!/usr/bin/env python3
"""Train or export the full µMal checkpoint for on-demand browser inference."""

from __future__ import annotations

import argparse
import hashlib
import json
from dataclasses import asdict
from pathlib import Path
from typing import Any

import numpy as np
import torch

from malir.data import DatasetExample, load_training_dataset
from malir.microlm import HashedTokenizer, MicroConfig, MicroMal, train_micro
from malir.support import build_support_profile

SMOKE_TOKENS = (
    (
        "FILE",
        "P:runtime|C:source|O:FILE_READ|T:file",
        "P:runtime|C:sink|O:FILE_WRITE|T:file",
        "EFFECT:ENTRY:library_callable",
        "EFFECT:ORIGIN:local_file",
        "EFFECT:DESTINATION:local_artifact",
    ),
    (
        "FILE",
        "P:runtime|C:source|O:ENV_READ|T:sensitive",
        "P:runtime|C:transform|O:ENCODE|T:generic",
        "P:runtime|C:sink|O:NETWORK_SEND|T:network",
        "MOTIF:credential_or_file_exfil",
        "EFFECT:ENTRY:library_callable",
        "EFFECT:ORIGIN:environment",
        "EFFECT:DESTINATION:network",
        "EFFECT:FLOW:sensitive_data_to_network",
        "EFFECT:TRANSFORM:encoding",
        "PURPOSE:sensitive_data_transfer",
    ),
)


def _variant_name(sample_id: str) -> str:
    return sample_id.rsplit("--", 1)[-1]


def _structured_indexes(
    examples: tuple[DatasetExample, ...],
) -> tuple[list[tuple[int, int]], list[list[int]]]:
    groups: dict[str, list[int]] = {}
    paired: dict[tuple[str, int, str], int] = {}
    pair_ids: set[str] = set()
    for index, example in enumerate(examples):
        groups.setdefault(example.group_id, []).append(index)
        if example.pair_id is None:
            continue
        pair_ids.add(example.pair_id)
        key = (example.pair_id, example.label, _variant_name(example.sample_id))
        if key in paired:
            raise ValueError(f"duplicate paired variant: {key}")
        paired[key] = index

    constraints = []
    for pair_id in sorted(pair_ids):
        negative = {
            variant: index
            for (current, label, variant), index in paired.items()
            if current == pair_id and label == 0
        }
        positive = {
            variant: index
            for (current, label, variant), index in paired.items()
            if current == pair_id and label == 1
        }
        if not negative or negative.keys() != positive.keys():
            raise ValueError(f"incomplete semantic pair: {pair_id}")
        constraints.extend(
            (negative[variant], positive[variant]) for variant in sorted(negative)
        )
    return constraints, [groups[name] for name in sorted(groups)]


def _tensor_names(layer_count: int) -> list[str]:
    names = ["token_embedding.weight", "position_embedding.weight"]
    for index in range(layer_count):
        prefix = f"encoder.layers.{index}"
        names.extend(
            [
                f"{prefix}.self_attn.in_proj_weight",
                f"{prefix}.self_attn.in_proj_bias",
                f"{prefix}.self_attn.out_proj.weight",
                f"{prefix}.self_attn.out_proj.bias",
                f"{prefix}.linear1.weight",
                f"{prefix}.linear1.bias",
                f"{prefix}.linear2.weight",
                f"{prefix}.linear2.bias",
                f"{prefix}.norm1.weight",
                f"{prefix}.norm1.bias",
                f"{prefix}.norm2.weight",
                f"{prefix}.norm2.bias",
            ]
        )
    names.extend(
        [
            "norm.weight",
            "norm.bias",
            "classifier.weight",
            "classifier.bias",
        ]
    )
    return names


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def _load_model(
    checkpoint_path: Path,
) -> tuple[MicroMal, MicroConfig, dict[str, Any]]:
    checkpoint = torch.load(
        checkpoint_path,
        map_location="cpu",
        weights_only=True,
    )
    if checkpoint.get("schema") != "malir.micro-transformer.v1":
        raise ValueError("unsupported µMal checkpoint schema")
    config = MicroConfig(**checkpoint["config"])
    model = MicroMal(config).eval()
    model.load_state_dict(checkpoint["state_dict"])
    return model, config, dict(checkpoint.get("metadata", {}))


def _smoke_vectors(
    model: MicroMal,
    config: MicroConfig,
    temperature: float,
) -> list[dict[str, Any]]:
    tokenizer = HashedTokenizer(config)
    output = []
    with torch.inference_mode():
        for tokens in SMOKE_TOKENS:
            ids, mask = tokenizer.encode(list(tokens))
            input_ids = torch.tensor([ids], dtype=torch.long)
            attention = torch.tensor([mask], dtype=torch.bool)
            logits, _ = model(input_ids, attention)
            probability = float(torch.softmax(logits / temperature, dim=-1)[0, 1])
            output.append({"tokens": list(tokens), "probability": probability})
    return output


def export_checkpoint(
    checkpoint_path: Path,
    binary_path: Path,
    module_path: Path,
) -> dict[str, Any]:
    model, config, checkpoint_metadata = _load_model(checkpoint_path)
    state = model.state_dict()
    binary_path.parent.mkdir(parents=True, exist_ok=True)
    module_path.parent.mkdir(parents=True, exist_ok=True)
    payload = bytearray()
    tensors: dict[str, dict[str, Any]] = {}

    for name in _tensor_names(config.n_layers):
        tensor = state[name].detach().cpu().to(torch.float32).contiguous()
        values = tensor.numpy().astype(np.dtype("<f4"), copy=False)
        offset = len(payload)
        encoded = values.tobytes(order="C")
        payload.extend(encoded)
        tensors[name] = {
            "offset": offset,
            "length": tensor.numel(),
            "shape": list(tensor.shape),
        }

    binary_tmp = binary_path.with_suffix(binary_path.suffix + ".tmp")
    binary_tmp.write_bytes(payload)
    binary_tmp.replace(binary_path)
    support_profile = checkpoint_metadata.get("support_profile")
    manifest = {
        "schema": "itcs.browser-full-model.v1",
        "support_profile": support_profile,
        "metadata": {
            "name": "µMal Full",
            "architecture": (
                f"{config.n_layers}-layer, {config.n_heads}-head behavior Transformer"
            ),
            "parameters": sum(parameter.numel() for parameter in model.parameters()),
            "checkpoint_sha256": _sha256(checkpoint_path),
            "weight_format": "float32-little-endian",
            "feature_schema": checkpoint_metadata.get(
                "feature_schema", "legacy-event-tokens"
            ),
            "training_examples": checkpoint_metadata.get("training_examples"),
            "training_groups": checkpoint_metadata.get("training_groups"),
            "training_epochs": checkpoint_metadata.get("training_epochs"),
            "training_epochs_completed": checkpoint_metadata.get(
                "training_epochs_completed"
            ),
            "training_accuracy": checkpoint_metadata.get("training_accuracy"),
            "validation_examples": checkpoint_metadata.get("validation_examples"),
            "validation_groups": checkpoint_metadata.get("validation_groups"),
            "validation_metrics": checkpoint_metadata.get("validation_metrics"),
            "training_metrics": checkpoint_metadata.get("training_metrics"),
            "structured_objective": checkpoint_metadata.get("structured_objective"),
            "training_roles": checkpoint_metadata.get("training_roles"),
            "validation_roles": checkpoint_metadata.get("validation_roles"),
            "support_schema": (
                support_profile.get("schema") if support_profile else None
            ),
            "support_prototypes": (
                len(support_profile.get("prototypes", ())) if support_profile else 0
            ),
            "temperature": checkpoint_metadata.get("temperature", 1.0),
            "calibration": checkpoint_metadata.get("calibration", "unknown"),
            "validation_kind": checkpoint_metadata.get("validation_kind"),
            "dataset_sha256": checkpoint_metadata.get("dataset_sha256"),
            "split_fingerprint": checkpoint_metadata.get("split_fingerprint"),
            "label_smoothing": checkpoint_metadata.get("label_smoothing"),
            "seed": checkpoint_metadata.get("seed"),
        },
        "config": asdict(config),
        "binary": {
            "path": f"./{binary_path.name}",
            "bytes": binary_path.stat().st_size,
            "sha256": _sha256(binary_path),
        },
        "tensors": tensors,
        "smoke_vectors": _smoke_vectors(
            model,
            config,
            float(checkpoint_metadata.get("temperature", 1.0)),
        ),
    }
    encoded_manifest = json.dumps(
        manifest,
        separators=(",", ":"),
        sort_keys=True,
        ensure_ascii=False,
    )
    module_text = (
        "// Generated by scripts/train_web_model.py; do not edit manually.\n"
        f"export const FULL_MODEL_MANIFEST = Object.freeze({encoded_manifest});\n"
    )
    module_tmp = module_path.with_suffix(module_path.suffix + ".tmp")
    module_tmp.write_text(module_text, encoding="utf-8")
    module_tmp.replace(module_path)
    return {
        "schema": manifest["schema"],
        "checkpoint": str(checkpoint_path),
        "binary": str(binary_path),
        "module": str(module_path),
        "parameters": manifest["metadata"]["parameters"],
        "binary_bytes": manifest["binary"]["bytes"],
        "binary_sha256": manifest["binary"]["sha256"],
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--checkpoint",
        type=Path,
        default=Path("artifacts/micro.pt"),
    )
    parser.add_argument(
        "--binary",
        type=Path,
        default=Path("web/model.bin"),
    )
    parser.add_argument(
        "--module",
        type=Path,
        default=Path("web/model.mjs"),
    )
    parser.add_argument("--train", action="store_true")
    parser.add_argument(
        "--dataset",
        type=Path,
        default=Path("examples/micro_train_v3.jsonl"),
    )
    parser.add_argument("--epochs", type=int, default=80)
    parser.add_argument("--batch-size", type=int, default=8)
    parser.add_argument("--threads", type=int, default=2)
    parser.add_argument("--seed", type=int, default=29)
    parser.add_argument("--patience", type=int, default=12)
    parser.add_argument("--minimum-epochs", type=int, default=12)
    parser.add_argument("--learning-rate", type=float, default=1e-3)
    parser.add_argument("--label-smoothing", type=float, default=0.05)
    parser.add_argument("--pair-margin", type=float, default=1.0)
    parser.add_argument("--pair-weight", type=float, default=0.15)
    parser.add_argument("--consistency-weight", type=float, default=0.05)
    parser.add_argument("--min-token-coverage", type=float, default=1.0)
    parser.add_argument("--min-nearest-jaccard", type=float, default=0.2)
    return parser


def main() -> None:
    args = build_parser().parse_args()
    training = None
    if args.train:
        dataset = load_training_dataset(args.dataset)
        train_pairs, train_groups = _structured_indexes(dataset.train)
        validation_pairs, validation_groups = _structured_indexes(dataset.validation)
        support_profile = build_support_profile(
            (example.tokens for example in dataset.train),
            (example.group_id for example in dataset.train),
            min_token_coverage=args.min_token_coverage,
            min_nearest_jaccard=args.min_nearest_jaccard,
        )
        training = train_micro(
            [example.as_pair() for example in dataset.train],
            args.checkpoint,
            config=MicroConfig(),
            epochs=args.epochs,
            batch_size=args.batch_size,
            learning_rate=args.learning_rate,
            label_smoothing=args.label_smoothing,
            threads=args.threads,
            seed=args.seed,
            validation_examples=[example.as_pair() for example in dataset.validation],
            pair_constraints=train_pairs,
            validation_pair_constraints=validation_pairs,
            consistency_groups=train_groups,
            validation_consistency_groups=validation_groups,
            pair_margin=args.pair_margin,
            pair_weight=args.pair_weight,
            consistency_weight=args.consistency_weight,
            patience=args.patience,
            minimum_epochs=args.minimum_epochs,
            checkpoint_metadata={
                "feature_schema": "malir.effect-context.v3",
                "dataset_sha256": dataset.dataset_sha256,
                "split_fingerprint": dataset.split_fingerprint,
                "training_groups": len(train_groups),
                "validation_groups": len(validation_groups),
                "training_roles": sorted({row.role for row in dataset.train}),
                "validation_roles": sorted({row.role for row in dataset.validation}),
                "validation_kind": "synthetic-group-disjoint-paired-effects",
                "support_profile": support_profile,
            },
        )
    if not args.checkpoint.is_file():
        raise FileNotFoundError(
            f"checkpoint not found: {args.checkpoint}; pass --train to create it"
        )
    result = export_checkpoint(args.checkpoint, args.binary, args.module)
    result["training"] = training
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
