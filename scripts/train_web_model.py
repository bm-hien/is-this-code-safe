"""Train and export the browser-only µMal Nano Transformer.

The exported ES module contains only a few thousand weights and needs no
runtime dependency. The bundled synthetic rows are a smoke-training corpus,
not evidence of real-world malware detection quality.
"""

from __future__ import annotations

import argparse
import json
import random
import re
from pathlib import Path

import torch
from torch import Tensor, nn
from torch.nn import functional as F

SPECIAL_TOKENS = ["<PAD>", "<BOS>", "<EOS>", "<MASK>", "<UNK>"]
OPS = [
    "IMPORT",
    "FILE_READ",
    "FILE_WRITE",
    "NETWORK_RECEIVE",
    "ENV_READ",
    "ENCODE",
    "DECODE",
    "SYSTEM_DISCOVERY",
    "PROCESS_EXEC",
    "NETWORK_SEND",
    "SENSITIVE_FILE_READ",
    "DYNAMIC_EXEC",
    "PERSISTENCE_WRITE",
    "UNSAFE_DESERIALIZE",
    "DYNAMIC_IMPORT",
    "FILE_DELETE",
]
MOTIFS = [
    "credential_or_file_exfil",
    "fingerprinting_transfer",
    "file_to_network",
    "download_execute",
    "encoded_execution",
    "install_time_execution",
    "persistence_write",
    "destructive_file_action",
]
VOCABULARY = [
    *SPECIAL_TOKENS,
    "PHASE:install",
    *(f"OP:{op}" for op in OPS),
    *(f"MOTIF:{motif}" for motif in MOTIFS),
]
TOKEN_TO_ID = {token: index for index, token in enumerate(VOCABULARY)}
PAD_ID, BOS_ID, EOS_ID, MASK_ID, UNK_ID = range(5)


class WebMicro(nn.Module):
    """One-layer behavior-language Transformer sized for JavaScript inference."""

    def __init__(self, max_length: int = 48, d_model: int = 16) -> None:
        super().__init__()
        self.max_length = max_length
        self.d_model = d_model
        self.n_heads = 2
        self.token_embedding = nn.Embedding(
            len(VOCABULARY),
            d_model,
            padding_idx=PAD_ID,
        )
        self.position_embedding = nn.Embedding(max_length, d_model)
        self.norm1 = nn.LayerNorm(d_model)
        self.attention = nn.MultiheadAttention(
            d_model,
            self.n_heads,
            dropout=0.0,
            batch_first=True,
        )
        self.norm2 = nn.LayerNorm(d_model)
        self.linear1 = nn.Linear(d_model, d_model * 2)
        self.linear2 = nn.Linear(d_model * 2, d_model)
        self.final_norm = nn.LayerNorm(d_model)
        self.classifier = nn.Linear(d_model, 2)

    def forward(self, ids: Tensor, mask: Tensor) -> tuple[Tensor, Tensor]:
        positions = torch.arange(ids.shape[1], device=ids.device).unsqueeze(0)
        hidden = self.token_embedding(ids) + self.position_embedding(positions)
        normalized = self.norm1(hidden)
        attended, _ = self.attention(
            normalized,
            normalized,
            normalized,
            key_padding_mask=~mask,
            need_weights=False,
        )
        hidden = hidden + attended
        normalized = self.norm2(hidden)
        hidden = hidden + self.linear2(
            F.gelu(self.linear1(normalized), approximate="tanh")
        )
        hidden = self.final_norm(hidden)
        weights = mask.unsqueeze(-1).to(hidden.dtype)
        pooled = (hidden * weights).sum(dim=1) / weights.sum(dim=1).clamp_min(1.0)
        class_logits = self.classifier(pooled)
        token_logits = hidden @ self.token_embedding.weight.transpose(0, 1)
        return class_logits, token_logits


def canonicalize(tokens: list[str]) -> list[str]:
    output: list[str] = []
    for token in tokens:
        if token.startswith("MOTIF:"):
            output.append(token if token in TOKEN_TO_ID else "<UNK>")
            continue
        operation = re.search(r"(?:^|\|)O:([^|]+)", token)
        if not operation:
            continue
        if token.startswith("P:install|"):
            output.append("PHASE:install")
        value = f"OP:{operation.group(1)}"
        output.append(value if value in TOKEN_TO_ID else "<UNK>")
    return output


def encode(tokens: list[str], max_length: int) -> tuple[list[int], list[bool]]:
    ids = [BOS_ID]
    ids.extend(TOKEN_TO_ID.get(token, UNK_ID) for token in tokens[: max_length - 2])
    ids.append(EOS_ID)
    mask = [True] * len(ids)
    padding = max_length - len(ids)
    ids.extend([PAD_ID] * padding)
    mask.extend([False] * padding)
    return ids, mask


def load_rows(path: Path) -> list[tuple[list[str], int]]:
    rows: list[tuple[list[str], int]] = []
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            row = json.loads(line)
            rows.append((canonicalize(row["tokens"]), int(row["label"])))
    if not rows:
        raise ValueError("dataset is empty")
    return rows


def mask_tokens(ids: Tensor, mask: Tensor) -> tuple[Tensor, Tensor]:
    candidates = mask & (ids >= len(SPECIAL_TOKENS))
    selected = (torch.rand(ids.shape) < 0.15) & candidates
    if not selected.any() and candidates.any():
        first = candidates.nonzero()[0]
        selected[first[0], first[1]] = True
    targets = ids.clone()
    targets[~selected] = -100
    masked = ids.clone()
    masked[selected] = MASK_ID
    return masked, targets


def nested(tensor: Tensor) -> list:
    return tensor.detach().cpu().tolist()


def export_model(
    model: WebMicro,
    output: Path,
    training_accuracy: float,
    epochs: int,
    example_count: int,
) -> None:
    state = model.state_dict()
    payload = {
        "schema": "itcs.web-micro.v1",
        "metadata": {
            "name": "µMal Nano",
            "architecture": "1-layer, 2-head behavior Transformer",
            "objective": "classification + masked behavior-token prediction",
            "parameters": sum(parameter.numel() for parameter in model.parameters()),
            "trainingExamples": example_count,
            "trainingAccuracy": round(training_accuracy, 6),
            "data": "bundled synthetic smoke corpus",
            "claim": "research demo; not a real-world efficacy claim",
        },
        "config": {
            "maxLength": model.max_length,
            "dModel": model.d_model,
            "heads": model.n_heads,
            "vocabulary": VOCABULARY,
        },
        "weights": {
            "tokenEmbedding": nested(state["token_embedding.weight"]),
            "positionEmbedding": nested(state["position_embedding.weight"]),
            "norm1Weight": nested(state["norm1.weight"]),
            "norm1Bias": nested(state["norm1.bias"]),
            "inProjWeight": nested(state["attention.in_proj_weight"]),
            "inProjBias": nested(state["attention.in_proj_bias"]),
            "outProjWeight": nested(state["attention.out_proj.weight"]),
            "outProjBias": nested(state["attention.out_proj.bias"]),
            "norm2Weight": nested(state["norm2.weight"]),
            "norm2Bias": nested(state["norm2.bias"]),
            "linear1Weight": nested(state["linear1.weight"]),
            "linear1Bias": nested(state["linear1.bias"]),
            "linear2Weight": nested(state["linear2.weight"]),
            "linear2Bias": nested(state["linear2.bias"]),
            "finalNormWeight": nested(state["final_norm.weight"]),
            "finalNormBias": nested(state["final_norm.bias"]),
            "classifierWeight": nested(state["classifier.weight"]),
            "classifierBias": nested(state["classifier.bias"]),
        },
        "training": {"epochs": epochs, "seed": 17},
    }
    serialized = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
    output.write_text(
        "// Generated by scripts/train_web_model.py; do not edit manually.\n"
        f"export const WEB_MODEL = Object.freeze({serialized});\n",
        encoding="utf-8",
    )


def train(
    dataset: Path, output: Path, epochs: int, threads: int
) -> dict[str, float | int]:
    torch.set_num_threads(max(1, threads))
    torch.manual_seed(17)
    random.seed(17)
    rows = load_rows(dataset)
    model = WebMicro()
    prepared = [(*encode(tokens, model.max_length), label) for tokens, label in rows]
    ids = torch.tensor([row[0] for row in prepared], dtype=torch.long)
    mask = torch.tensor([row[1] for row in prepared], dtype=torch.bool)
    labels = torch.tensor([row[2] for row in prepared], dtype=torch.long)
    optimizer = torch.optim.AdamW(model.parameters(), lr=0.01, weight_decay=0.001)
    class_loss = nn.CrossEntropyLoss()
    language_loss = nn.CrossEntropyLoss(ignore_index=-100)

    model.train()
    last_loss = 0.0
    for _ in range(epochs):
        masked, targets = mask_tokens(ids, mask)
        logits, token_logits = model(masked, mask)
        loss = class_loss(logits, labels)
        loss = loss + 0.05 * language_loss(
            token_logits.reshape(-1, len(VOCABULARY)),
            targets.reshape(-1),
        )
        optimizer.zero_grad(set_to_none=True)
        loss.backward()
        nn.utils.clip_grad_norm_(model.parameters(), 1.0)
        optimizer.step()
        last_loss = float(loss.detach())

    model.eval()
    with torch.inference_mode():
        logits, _ = model(ids, mask)
        accuracy = float((logits.argmax(dim=-1) == labels).float().mean())
    output.parent.mkdir(parents=True, exist_ok=True)
    export_model(model, output, accuracy, epochs, len(rows))
    return {
        "examples": len(rows),
        "epochs": epochs,
        "parameters": sum(parameter.numel() for parameter in model.parameters()),
        "training_accuracy": accuracy,
        "final_loss": last_loss,
        "bytes": output.stat().st_size,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "dataset",
        nargs="?",
        type=Path,
        default=Path("examples/synthetic_train.jsonl"),
    )
    parser.add_argument("-o", "--output", type=Path, default=Path("web/model.mjs"))
    parser.add_argument("--epochs", type=int, default=500)
    parser.add_argument("--threads", type=int, default=2)
    args = parser.parse_args()
    result = train(args.dataset, args.output, args.epochs, args.threads)
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
