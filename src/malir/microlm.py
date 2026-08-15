"""µMal: a tiny Transformer over MalIR behavior tokens.

PyTorch is an optional training dependency. The scanner imports this module only
when a micro-model checkpoint is explicitly requested.
"""

from __future__ import annotations

import hashlib
import math
import random
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

import torch
from torch import Tensor, nn

from .support import assess_model_support, validate_support_profile

PAD_ID = 0
BOS_ID = 1
EOS_ID = 2
MASK_ID = 3
FIRST_HASH_ID = 4


@dataclass(frozen=True, slots=True)
class MicroConfig:
    vocab_size: int = 4096
    max_length: int = 256
    d_model: int = 96
    n_heads: int = 4
    n_layers: int = 2
    ffn_dim: int = 192
    dropout: float = 0.1

    def validate(self) -> None:
        if not FIRST_HASH_ID < self.vocab_size <= 65_536:
            raise ValueError("vocab_size must be between 5 and 65,536")
        if not 8 <= self.max_length <= 4_096:
            raise ValueError("max_length must be between 8 and 4,096")
        if not 8 <= self.d_model <= 512:
            raise ValueError("d_model must be between 8 and 512")
        if not 1 <= self.n_heads <= 16:
            raise ValueError("n_heads must be between 1 and 16")
        if self.d_model % self.n_heads:
            raise ValueError("d_model must be divisible by n_heads")
        if not 1 <= self.n_layers <= 12:
            raise ValueError("n_layers must be between 1 and 12")
        if not self.d_model <= self.ffn_dim <= 2_048:
            raise ValueError("ffn_dim is outside the supported range")
        if not 0.0 <= self.dropout < 1.0:
            raise ValueError("dropout must be in [0, 1)")


class MicroMal(nn.Module):
    def __init__(self, config: MicroConfig) -> None:
        super().__init__()
        config.validate()
        self.config = config
        self.token_embedding = nn.Embedding(
            config.vocab_size,
            config.d_model,
            padding_idx=PAD_ID,
        )
        self.position_embedding = nn.Embedding(
            config.max_length,
            config.d_model,
        )
        layer = nn.TransformerEncoderLayer(
            d_model=config.d_model,
            nhead=config.n_heads,
            dim_feedforward=config.ffn_dim,
            dropout=config.dropout,
            activation="gelu",
            batch_first=True,
            norm_first=True,
        )
        self.encoder = nn.TransformerEncoder(
            layer,
            config.n_layers,
            enable_nested_tensor=False,
        )
        self.norm = nn.LayerNorm(config.d_model)
        self.classifier = nn.Linear(config.d_model, 2)
        self.lm_head = nn.Linear(config.d_model, config.vocab_size, bias=False)
        self.lm_head.weight = self.token_embedding.weight

    def encode(self, input_ids: Tensor, attention_mask: Tensor) -> Tensor:
        positions = torch.arange(
            input_ids.shape[1],
            device=input_ids.device,
        ).unsqueeze(0)
        hidden = self.token_embedding(input_ids) + self.position_embedding(positions)
        hidden = self.encoder(
            hidden,
            src_key_padding_mask=~attention_mask.bool(),
        )
        return self.norm(hidden)

    def forward(
        self,
        input_ids: Tensor,
        attention_mask: Tensor,
        *,
        return_token_logits: bool = False,
    ) -> tuple[Tensor, Tensor | None]:
        hidden = self.encode(input_ids, attention_mask)
        weights = attention_mask.unsqueeze(-1).to(hidden.dtype)
        pooled = (hidden * weights).sum(dim=1) / weights.sum(dim=1).clamp_min(1.0)
        token_logits = self.lm_head(hidden) if return_token_logits else None
        return self.classifier(pooled), token_logits


class HashedTokenizer:
    def __init__(self, config: MicroConfig) -> None:
        self.config = config

    def encode(self, tokens: list[str]) -> tuple[list[int], list[int]]:
        ids = [BOS_ID]
        for token in tokens[: self.config.max_length - 2]:
            digest = hashlib.blake2b(
                token.encode("utf-8"),
                digest_size=8,
                person=b"mumal-v1",
            ).digest()
            bucket = int.from_bytes(digest, "little")
            bucket %= self.config.vocab_size - FIRST_HASH_ID
            ids.append(FIRST_HASH_ID + bucket)
        ids.append(EOS_ID)
        mask = [1] * len(ids)
        padding = self.config.max_length - len(ids)
        ids.extend([PAD_ID] * padding)
        mask.extend([0] * padding)
        return ids, mask

    def encode_windows(
        self,
        tokens: list[str],
        *,
        overlap: int = 32,
        max_windows: int = 16,
    ) -> list[tuple[list[int], list[int]]]:
        if overlap < 0 or max_windows < 1:
            raise ValueError("overlap must be non-negative and max_windows positive")
        width = self.config.max_length - 2
        overlap = min(overlap, max(0, width - 1))
        stride = max(1, width - overlap)
        windows: list[tuple[list[int], list[int]]] = []
        start = 0
        while len(windows) < max_windows:
            windows.append(self.encode(tokens[start : start + width]))
            if start + width >= len(tokens):
                break
            start += stride
        return windows


class MicroMalPredictor:
    def __init__(
        self,
        model: MicroMal,
        *,
        temperature: float = 1.0,
        support_profile: dict[str, Any] | None = None,
    ) -> None:
        if not math.isfinite(temperature) or temperature <= 0.0:
            raise ValueError("temperature must be finite and positive")
        if support_profile is not None:
            validate_support_profile(support_profile)
        self.model = model.eval()
        self.tokenizer = HashedTokenizer(model.config)
        self.temperature = float(temperature)
        self.support_profile = support_profile

    @classmethod
    def load(
        cls,
        checkpoint_path: str | Path,
        threads: int = 2,
    ) -> MicroMalPredictor:
        torch.set_num_threads(max(1, threads))
        checkpoint = torch.load(
            checkpoint_path,
            map_location="cpu",
            weights_only=True,
        )
        if checkpoint.get("schema") != "malir.micro-transformer.v1":
            raise ValueError("unsupported µMal checkpoint schema")
        config = MicroConfig(**checkpoint["config"])
        model = MicroMal(config)
        model.load_state_dict(checkpoint["state_dict"])
        metadata = checkpoint.get("metadata", {})
        temperature = float(metadata.get("temperature", 1.0))
        support_profile = metadata.get("support_profile")
        return cls(
            model,
            temperature=temperature,
            support_profile=support_profile,
        )

    def predict_details(self, tokens: list[str]) -> dict[str, Any]:
        windows = self.tokenizer.encode_windows(tokens)
        input_ids = torch.tensor([ids for ids, _ in windows], dtype=torch.long)
        attention = torch.tensor([mask for _, mask in windows], dtype=torch.bool)
        with torch.inference_mode():
            logits, _ = self.model(input_ids, attention)
            calibrated = logits / self.temperature
            probability = float(torch.softmax(calibrated, dim=-1)[:, 1].max())
        support = assess_model_support(tokens, self.support_profile)
        return {"probability": probability, **support.to_dict()}

    def predict_proba(self, tokens: list[str]) -> float:
        return float(self.predict_details(tokens)["probability"])

    @property
    def parameter_count(self) -> int:
        return sum(parameter.numel() for parameter in self.model.parameters())


def train_micro(
    examples: list[tuple[list[str], int]],
    output_path: str | Path,
    config: MicroConfig | None = None,
    epochs: int = 40,
    batch_size: int = 16,
    learning_rate: float = 1e-3,
    mlm_weight: float = 0.05,
    label_smoothing: float = 0.05,
    positive_class_weight: float | None = None,
    threads: int = 2,
    seed: int = 13,
    *,
    validation_examples: list[tuple[list[str], int]] | None = None,
    pair_constraints: list[tuple[int, int]] | None = None,
    validation_pair_constraints: list[tuple[int, int]] | None = None,
    consistency_groups: list[list[int]] | None = None,
    validation_consistency_groups: list[list[int]] | None = None,
    pair_margin: float = 1.0,
    pair_weight: float = 0.15,
    consistency_weight: float = 0.05,
    patience: int = 8,
    minimum_epochs: int = 5,
    checkpoint_metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    config = config or MicroConfig()
    if not examples:
        raise ValueError("training set is empty")
    if epochs < 1 or batch_size < 1:
        raise ValueError("epochs and batch_size must be positive")
    if not 0.0 <= mlm_weight <= 1.0:
        raise ValueError("mlm_weight must be between 0 and 1")
    if not 0.0 <= label_smoothing < 1.0:
        raise ValueError("label_smoothing must be in [0, 1)")
    if positive_class_weight is not None and positive_class_weight <= 0.0:
        raise ValueError("positive_class_weight must be positive")
    if patience < 1 or minimum_epochs < 1:
        raise ValueError("patience and minimum_epochs must be positive")
    if pair_margin <= 0.0:
        raise ValueError("pair_margin must be positive")
    if pair_weight < 0.0 or consistency_weight < 0.0:
        raise ValueError("structured objective weights cannot be negative")
    _require_binary_labels(examples, "training")
    train_pairs = list(pair_constraints or ())
    train_groups = list(consistency_groups or ())
    _validate_structured_indexes(examples, train_pairs, train_groups, "training")
    validation_pairs = list(validation_pair_constraints or ())
    validation_groups = list(validation_consistency_groups or ())
    if validation_examples is not None:
        _require_binary_labels(validation_examples, "validation")
        _validate_structured_indexes(
            validation_examples,
            validation_pairs,
            validation_groups,
            "validation",
        )
    elif validation_pairs or validation_groups:
        raise ValueError("validation structure requires validation examples")

    torch.set_num_threads(max(1, threads))
    torch.manual_seed(seed)
    random.seed(seed)
    model = MicroMal(config)
    tokenizer = HashedTokenizer(config)
    optimizer = torch.optim.AdamW(model.parameters(), lr=learning_rate)
    class_weights = (
        torch.tensor([1.0, positive_class_weight], dtype=torch.float32)
        if positive_class_weight is not None
        else None
    )
    class_loss = nn.CrossEntropyLoss(
        weight=class_weights,
        label_smoothing=label_smoothing,
    )
    language_loss = nn.CrossEntropyLoss(ignore_index=-100)
    prepared = [(*tokenizer.encode(tokens), label) for tokens, label in examples]
    validation_prepared = (
        [(*tokenizer.encode(tokens), label) for tokens, label in validation_examples]
        if validation_examples is not None
        else None
    )
    indices = list(range(len(prepared)))
    last_loss = 0.0
    best_epoch = 0
    best_validation_nll = math.inf
    best_state: dict[str, Tensor] | None = None
    stale_epochs = 0

    for epoch in range(1, epochs + 1):
        model.train()
        random.shuffle(indices)
        epoch_loss = 0.0
        batches = 0
        for start in range(0, len(indices), batch_size):
            batch = [prepared[index] for index in indices[start : start + batch_size]]
            ids, mask, labels = _batch_tensors(batch)
            logits, _ = model(ids, mask)
            loss = class_loss(logits, labels)
            if mlm_weight:
                masked_ids, targets = _mask_tokens(ids, mask)
                _, token_logits = model(
                    masked_ids,
                    mask,
                    return_token_logits=True,
                )
                if token_logits is None:  # pragma: no cover - defensive invariant
                    raise RuntimeError("masked-token logits are unavailable")
                loss = loss + mlm_weight * language_loss(
                    token_logits.reshape(-1, config.vocab_size),
                    targets.reshape(-1),
                )
            optimizer.zero_grad(set_to_none=True)
            loss.backward()
            nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            optimizer.step()
            epoch_loss += float(loss.detach())
            batches += 1

        if train_pairs or train_groups:
            ids, mask, _labels = _batch_tensors(prepared)
            logits, _ = model(ids, mask)
            structured_loss = _structured_loss(
                logits,
                train_pairs,
                train_groups,
                pair_margin=pair_margin,
                pair_weight=pair_weight,
                consistency_weight=consistency_weight,
            )
            optimizer.zero_grad(set_to_none=True)
            structured_loss.backward()
            nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            optimizer.step()
            epoch_loss += float(structured_loss.detach())
            batches += 1
        last_loss = epoch_loss / max(1, batches)

        if validation_prepared is None:
            best_epoch = epoch
            continue
        validation_logits, validation_labels = _collect_logits(
            model,
            validation_prepared,
            batch_size,
        )
        validation_nll = float(
            nn.functional.cross_entropy(
                validation_logits,
                validation_labels,
            )
        )
        if validation_nll < best_validation_nll - 1e-6:
            best_validation_nll = validation_nll
            best_epoch = epoch
            best_state = {
                name: value.detach().cpu().clone()
                for name, value in model.state_dict().items()
            }
            stale_epochs = 0
        else:
            stale_epochs += 1
        if epoch >= minimum_epochs and stale_epochs >= patience:
            break

    epochs_completed = epoch
    if best_state is not None:
        model.load_state_dict(best_state)
    model.eval()
    training_logits, training_labels = _collect_logits(
        model,
        prepared,
        batch_size,
    )
    training_metrics = _classification_metrics(training_logits, training_labels)
    training_metrics.update(
        _structured_metrics(training_logits, train_pairs, train_groups)
    )

    temperature = 1.0
    validation_metrics = None
    validation_metrics_uncalibrated = None
    if validation_prepared is not None:
        validation_logits, validation_labels = _collect_logits(
            model,
            validation_prepared,
            batch_size,
        )
        validation_metrics_uncalibrated = _classification_metrics(
            validation_logits,
            validation_labels,
        )
        validation_metrics_uncalibrated.update(
            _structured_metrics(
                validation_logits,
                validation_pairs,
                validation_groups,
            )
        )
        temperature = _fit_conservative_temperature(
            validation_logits,
            validation_labels,
        )
        validation_metrics = _classification_metrics(
            validation_logits,
            validation_labels,
            temperature=temperature,
        )
        validation_metrics.update(
            _structured_metrics(
                validation_logits,
                validation_pairs,
                validation_groups,
                temperature=temperature,
            )
        )

    metadata = dict(checkpoint_metadata or {})
    metadata.setdefault("feature_schema", "malir.effect-context.v2")
    metadata.update(
        {
            "training_examples": len(examples),
            "validation_examples": len(validation_examples or ()),
            "training_epochs": best_epoch or epochs_completed,
            "training_epochs_completed": epochs_completed,
            "training_accuracy": training_metrics["accuracy"],
            "training_metrics": training_metrics,
            "validation_metrics": validation_metrics,
            "validation_metrics_uncalibrated": validation_metrics_uncalibrated,
            "temperature": temperature,
            "calibration": (
                "temperature-scaled-validation"
                if validation_examples is not None
                else "uncalibrated-no-validation"
            ),
            "label_smoothing": label_smoothing,
            "positive_class_weight": positive_class_weight,
            "structured_objective": {
                "pair_constraints": len(train_pairs),
                "consistency_groups": len(train_groups),
                "pair_margin": pair_margin,
                "pair_weight": pair_weight,
                "consistency_weight": consistency_weight,
            },
            "seed": seed,
        }
    )
    checkpoint = {
        "schema": "malir.micro-transformer.v1",
        "config": asdict(config),
        "state_dict": model.state_dict(),
        "metadata": metadata,
    }
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    torch.save(checkpoint, output)
    return {
        "examples": len(examples),
        "validation_examples": len(validation_examples or ()),
        "epochs_requested": epochs,
        "epochs_completed": epochs_completed,
        "best_epoch": best_epoch or epochs_completed,
        "parameters": sum(p.numel() for p in model.parameters()),
        "final_loss": last_loss,
        "training_metrics": training_metrics,
        "validation_metrics": validation_metrics,
        "validation_metrics_uncalibrated": validation_metrics_uncalibrated,
        "pair_constraints": len(train_pairs),
        "consistency_groups": len(train_groups),
        "temperature": temperature,
        "early_stopped": epochs_completed < epochs,
    }


def _require_binary_labels(
    examples: list[tuple[list[str], int]],
    split_name: str,
) -> None:
    labels = {label for _, label in examples}
    if labels != {0, 1}:
        raise ValueError(f"{split_name} examples must contain both label classes")


def _validate_structured_indexes(
    examples: list[tuple[list[str], int]],
    pairs: list[tuple[int, int]],
    groups: list[list[int]],
    split_name: str,
) -> None:
    size = len(examples)
    for negative, positive in pairs:
        if not 0 <= negative < size or not 0 <= positive < size:
            raise ValueError(f"{split_name} pair index is outside the dataset")
        if examples[negative][1] != 0 or examples[positive][1] != 1:
            raise ValueError(f"{split_name} pairs must be ordered negative, positive")
    for group in groups:
        if len(group) < 2 or any(not 0 <= index < size for index in group):
            raise ValueError(f"{split_name} consistency group is invalid")


def _structured_loss(
    logits: Tensor,
    pairs: list[tuple[int, int]],
    groups: list[list[int]],
    *,
    pair_margin: float,
    pair_weight: float,
    consistency_weight: float,
) -> Tensor:
    scores = logits[:, 1] - logits[:, 0]
    terms: list[Tensor] = []
    if pairs and pair_weight:
        negative = torch.tensor([item[0] for item in pairs], device=logits.device)
        positive = torch.tensor([item[1] for item in pairs], device=logits.device)
        gaps = scores[positive] - scores[negative]
        terms.append(pair_weight * torch.relu(pair_margin - gaps).mean())
    if groups and consistency_weight:
        drifts = []
        for group in groups:
            selected = scores[torch.tensor(group, device=logits.device)]
            drifts.append(((selected - selected.mean()) ** 2).mean())
        terms.append(consistency_weight * torch.stack(drifts).mean())
    return sum(terms, start=logits.sum() * 0.0)


def _structured_metrics(
    logits: Tensor,
    pairs: list[tuple[int, int]],
    groups: list[list[int]],
    *,
    temperature: float = 1.0,
) -> dict[str, float]:
    probabilities = torch.softmax(logits / temperature, dim=-1)[:, 1]
    metrics: dict[str, float] = {}
    if pairs:
        gaps = torch.stack(
            [
                probabilities[positive] - probabilities[negative]
                for negative, positive in pairs
            ]
        )
        metrics.update(
            {
                "pair_ordering_accuracy": float((gaps > 0).float().mean()),
                "pair_probability_gap_mean": float(gaps.mean()),
                "pair_probability_gap_min": float(gaps.min()),
            }
        )
    if groups:
        drifts = torch.stack(
            [
                probabilities[group].max() - probabilities[group].min()
                for group in groups
            ]
        )
        metrics.update(
            {
                "semantic_variant_drift_mean": float(drifts.mean()),
                "semantic_variant_drift_max": float(drifts.max()),
            }
        )
    return metrics


def _batch_tensors(
    batch: list[tuple[list[int], list[int], int]],
) -> tuple[Tensor, Tensor, Tensor]:
    ids = torch.tensor([item[0] for item in batch], dtype=torch.long)
    mask = torch.tensor([item[1] for item in batch], dtype=torch.bool)
    labels = torch.tensor([item[2] for item in batch], dtype=torch.long)
    return ids, mask, labels


def _collect_logits(
    model: MicroMal,
    prepared: list[tuple[list[int], list[int], int]],
    batch_size: int,
) -> tuple[Tensor, Tensor]:
    logits_parts = []
    label_parts = []
    model.eval()
    with torch.inference_mode():
        for start in range(0, len(prepared), batch_size):
            ids, mask, labels = _batch_tensors(prepared[start : start + batch_size])
            logits, _ = model(ids, mask)
            logits_parts.append(logits.detach().cpu())
            label_parts.append(labels)
    return torch.cat(logits_parts), torch.cat(label_parts)


def _fit_conservative_temperature(logits: Tensor, labels: Tensor) -> float:
    """Fit a validation-only scalar that never sharpens confidence."""

    temperatures = torch.exp(torch.linspace(0.0, math.log(20.0), steps=241))
    scaled = logits.unsqueeze(0) / temperatures[:, None, None]
    log_probabilities = torch.log_softmax(scaled, dim=-1)
    row_indices = torch.arange(labels.shape[0])
    losses = -log_probabilities[:, row_indices, labels].mean(dim=1)
    best = int(losses.argmin())
    return float(temperatures[best])


def _classification_metrics(
    logits: Tensor,
    labels: Tensor,
    *,
    temperature: float = 1.0,
    bins: int = 10,
) -> dict[str, float]:
    probabilities = torch.softmax(logits / temperature, dim=-1)[:, 1]
    predictions = (probabilities >= 0.5).long()
    accuracy = float((predictions == labels).float().mean())
    recalls = []
    for label in (0, 1):
        selected = labels == label
        recalls.append(float((predictions[selected] == label).float().mean()))
    clipped = probabilities.clamp(1e-7, 1.0 - 1e-7)
    targets = labels.to(torch.float32)
    nll = float(
        -(
            targets * torch.log(clipped) + (1.0 - targets) * torch.log(1.0 - clipped)
        ).mean()
    )
    brier = float(((probabilities - targets) ** 2).mean())
    confidence = torch.where(predictions == 1, probabilities, 1.0 - probabilities)
    correct = (predictions == labels).to(torch.float32)
    ece = 0.0
    boundaries = torch.linspace(0.0, 1.0, bins + 1)
    for index in range(bins):
        lower = boundaries[index]
        upper = boundaries[index + 1]
        selected = (confidence > lower) & (confidence <= upper)
        if selected.any():
            weight = float(selected.float().mean())
            gap = abs(
                float(confidence[selected].mean()) - float(correct[selected].mean())
            )
            ece += weight * gap
    return {
        "accuracy": accuracy,
        "balanced_accuracy": sum(recalls) / 2.0,
        "nll": nll,
        "brier_score": brier,
        "ece_10": ece,
    }


def _mask_tokens(ids: Tensor, attention: Tensor) -> tuple[Tensor, Tensor]:
    candidates = attention & (ids >= FIRST_HASH_ID)
    selected = (torch.rand(ids.shape) < 0.15) & candidates
    if not selected.any() and candidates.any():
        first = candidates.nonzero()[0]
        selected[first[0], first[1]] = True
    targets = ids.clone()
    targets[~selected] = -100
    masked = ids.clone()
    masked[selected] = MASK_ID
    return masked, targets
