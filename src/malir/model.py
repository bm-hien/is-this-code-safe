"""Tiny online sparse classifier for the first cascade stage."""

from __future__ import annotations

import json
import math
import random
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .features import vectorize


@dataclass(slots=True)
class OnlineLogisticModel:
    dimensions: int = 1 << 16
    learning_rate: float = 0.15
    l2: float = 1e-6
    weights: dict[int, float] = field(default_factory=dict)
    bias: float = 0.0
    updates: int = 0

    def predict_proba(self, tokens: list[str]) -> float:
        features = vectorize(tokens, self.dimensions)
        score = self.bias + sum(
            self.weights.get(index, 0.0) * value for index, value in features.items()
        )
        return _sigmoid(score)

    def partial_fit(
        self,
        examples: list[tuple[list[str], int]],
        epochs: int = 1,
        seed: int = 13,
    ) -> list[float]:
        if not examples:
            raise ValueError("training set is empty")
        positives = sum(label == 1 for _, label in examples)
        negatives = len(examples) - positives
        positive_weight = negatives / max(1, positives)
        losses: list[float] = []
        rng = random.Random(seed)
        order = list(range(len(examples)))
        for _ in range(epochs):
            rng.shuffle(order)
            total_loss = 0.0
            for position in order:
                tokens, label = examples[position]
                probability = self.predict_proba(tokens)
                sample_weight = positive_weight if label == 1 else 1.0
                error = (probability - label) * sample_weight
                features = vectorize(tokens, self.dimensions)
                rate = self.learning_rate / math.sqrt(1.0 + self.updates / 500.0)
                for index, value in features.items():
                    old = self.weights.get(index, 0.0)
                    updated = old - rate * (error * value + self.l2 * old)
                    if abs(updated) > 1e-10:
                        self.weights[index] = updated
                self.bias -= rate * error
                self.updates += 1
                probability = min(max(probability, 1e-9), 1.0 - 1e-9)
                total_loss -= sample_weight * (
                    label * math.log(probability)
                    + (1 - label) * math.log(1 - probability)
                )
            losses.append(total_loss / len(examples))
        return losses

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": "malir.sparse-logistic.v1",
            "dimensions": self.dimensions,
            "learning_rate": self.learning_rate,
            "l2": self.l2,
            "bias": self.bias,
            "updates": self.updates,
            "weights": {str(key): value for key, value in self.weights.items()},
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> OnlineLogisticModel:
        if data.get("schema") != "malir.sparse-logistic.v1":
            raise ValueError("unsupported model schema")
        return cls(
            dimensions=int(data["dimensions"]),
            learning_rate=float(data["learning_rate"]),
            l2=float(data["l2"]),
            weights={int(key): float(value) for key, value in data["weights"].items()},
            bias=float(data["bias"]),
            updates=int(data.get("updates", 0)),
        )

    def save(self, path: str | Path) -> None:
        Path(path).write_text(
            json.dumps(self.to_dict(), separators=(",", ":"), sort_keys=True),
            encoding="utf-8",
        )

    @classmethod
    def load(cls, path: str | Path) -> OnlineLogisticModel:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        return cls.from_dict(data)


def _sigmoid(value: float) -> float:
    if value >= 0:
        return 1.0 / (1.0 + math.exp(-min(value, 60.0)))
    exponent = math.exp(max(value, -60.0))
    return exponent / (1.0 + exponent)
