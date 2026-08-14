"""µMal: a tiny Transformer over MalIR behavior tokens.

PyTorch is an optional training dependency. The scanner imports this module only
when a micro-model checkpoint is explicitly requested.
"""

from __future__ import annotations

import hashlib
import random
from dataclasses import asdict, dataclass
from pathlib import Path

import torch
from torch import Tensor, nn

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

    def forward(
        self,
        input_ids: Tensor,
        attention_mask: Tensor,
    ) -> tuple[Tensor, Tensor]:
        positions = torch.arange(
            input_ids.shape[1],
            device=input_ids.device,
        ).unsqueeze(0)
        hidden = self.token_embedding(input_ids) + self.position_embedding(positions)
        hidden = self.encoder(
            hidden,
            src_key_padding_mask=~attention_mask.bool(),
        )
        hidden = self.norm(hidden)
        weights = attention_mask.unsqueeze(-1).to(hidden.dtype)
        pooled = (hidden * weights).sum(dim=1) / weights.sum(dim=1).clamp_min(1.0)
        return self.classifier(pooled), self.lm_head(hidden)


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
    def __init__(self, model: MicroMal) -> None:
        self.model = model.eval()
        self.tokenizer = HashedTokenizer(model.config)

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
        return cls(model)

    def predict_proba(self, tokens: list[str]) -> float:
        windows = self.tokenizer.encode_windows(tokens)
        input_ids = torch.tensor([ids for ids, _ in windows], dtype=torch.long)
        attention = torch.tensor([mask for _, mask in windows], dtype=torch.bool)
        with torch.inference_mode():
            logits, _ = self.model(input_ids, attention)
            return float(torch.softmax(logits, dim=-1)[:, 1].max())

    @property
    def parameter_count(self) -> int:
        return sum(parameter.numel() for parameter in self.model.parameters())


def train_micro(
    examples: list[tuple[list[str], int]],
    output_path: str | Path,
    config: MicroConfig | None = None,
    epochs: int = 5,
    batch_size: int = 16,
    learning_rate: float = 1e-3,
    mlm_weight: float = 0.05,
    threads: int = 2,
    seed: int = 13,
) -> dict[str, float | int]:
    config = config or MicroConfig()
    if epochs < 1 or batch_size < 1:
        raise ValueError("epochs and batch_size must be positive")
    if not 0.0 <= mlm_weight <= 1.0:
        raise ValueError("mlm_weight must be between 0 and 1")
    torch.set_num_threads(max(1, threads))
    torch.manual_seed(seed)
    random.seed(seed)
    model = MicroMal(config)
    tokenizer = HashedTokenizer(config)
    optimizer = torch.optim.AdamW(model.parameters(), lr=learning_rate)
    class_loss = nn.CrossEntropyLoss()
    language_loss = nn.CrossEntropyLoss(ignore_index=-100)
    prepared = [(*tokenizer.encode(tokens), label) for tokens, label in examples]
    indices = list(range(len(prepared)))
    last_loss = 0.0
    model.train()
    for _ in range(epochs):
        random.shuffle(indices)
        epoch_loss = 0.0
        batches = 0
        for start in range(0, len(indices), batch_size):
            batch = [prepared[index] for index in indices[start : start + batch_size]]
            ids = torch.tensor([item[0] for item in batch], dtype=torch.long)
            mask = torch.tensor([item[1] for item in batch], dtype=torch.bool)
            labels = torch.tensor([item[2] for item in batch], dtype=torch.long)
            masked_ids, targets = _mask_tokens(ids, mask)
            logits, token_logits = model(masked_ids, mask)
            loss = class_loss(logits, labels)
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
        last_loss = epoch_loss / max(1, batches)
    model.eval()
    correct = 0
    with torch.inference_mode():
        for start in range(0, len(prepared), batch_size):
            batch = prepared[start : start + batch_size]
            ids = torch.tensor([item[0] for item in batch], dtype=torch.long)
            mask = torch.tensor([item[1] for item in batch], dtype=torch.bool)
            labels = torch.tensor([item[2] for item in batch], dtype=torch.long)
            logits, _ = model(ids, mask)
            correct += int((logits.argmax(dim=-1) == labels).sum())
    checkpoint = {
        "schema": "malir.micro-transformer.v1",
        "config": asdict(config),
        "state_dict": model.state_dict(),
        "metadata": {
            "feature_schema": "malir.effect-context.v1",
            "training_examples": len(examples),
            "training_epochs": epochs,
            "training_accuracy": correct / len(prepared),
            "calibration": "uncalibrated-demo",
        },
    }
    torch.save(checkpoint, output_path)
    return {
        "examples": len(examples),
        "epochs": epochs,
        "parameters": sum(p.numel() for p in model.parameters()),
        "final_loss": last_loss,
        "training_accuracy": correct / len(prepared),
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
