from collections import defaultdict, deque

import numpy as np


def _sigmoid(value: np.ndarray) -> np.ndarray:
    return 1.0 / (1.0 + np.exp(-np.clip(value, -30, 30)))


class GRUSequenceDetector:
    """Lightweight gated-recurrent reservoir with a learned reconstruction head.

    It preserves real GRU update/reset recurrence without requiring a heavyweight
    deep-learning runtime. Only normal chronological sequences fit the decoder and
    error normalization, making this a normal-only sequence anomaly detector.
    """

    def __init__(self, input_size: int, hidden_size: int = 24, window_size: int = 10,
                 ridge: float = 1e-3, random_state: int = 42):
        self.input_size, self.hidden_size, self.window_size = input_size, hidden_size, window_size
        self.ridge, self.random_state = ridge, random_state
        rng = np.random.default_rng(random_state); x_scale = 1 / np.sqrt(max(input_size, 1)); h_scale = 1 / np.sqrt(hidden_size)
        self.wz = rng.normal(0, x_scale, (input_size, hidden_size)); self.uz = rng.normal(0, h_scale, (hidden_size, hidden_size)); self.bz = np.zeros(hidden_size)
        self.wr = rng.normal(0, x_scale, (input_size, hidden_size)); self.ur = rng.normal(0, h_scale, (hidden_size, hidden_size)); self.br = np.zeros(hidden_size)
        self.wh = rng.normal(0, x_scale, (input_size, hidden_size)); self.uh = rng.normal(0, h_scale, (hidden_size, hidden_size)); self.bh = np.zeros(hidden_size)
        self.decoder = np.zeros((hidden_size + 1, input_size)); self.error_low = 0.0; self.error_high = 1.0

    def _encode(self, sequence: list[np.ndarray] | np.ndarray) -> np.ndarray:
        hidden = np.zeros(self.hidden_size)
        for vector in np.asarray(sequence, dtype=float)[-self.window_size:]:
            update = _sigmoid(vector @ self.wz + hidden @ self.uz + self.bz)
            reset = _sigmoid(vector @ self.wr + hidden @ self.ur + self.br)
            candidate = np.tanh(vector @ self.wh + (reset * hidden) @ self.uh + self.bh)
            hidden = (1 - update) * hidden + update * candidate
        return hidden

    def _predict(self, history: list[np.ndarray] | np.ndarray) -> np.ndarray:
        return np.r_[self._encode(history), 1.0] @ self.decoder

    def fit(self, scaled: np.ndarray, labels: np.ndarray, entities: np.ndarray):
        histories: dict[str, deque] = defaultdict(lambda: deque(maxlen=self.window_size)); hidden_rows, targets = [], []
        for vector, label, entity in zip(scaled, labels, entities):
            if label == "normal":
                hidden_rows.append(np.r_[self._encode(list(histories[str(entity)])), 1.0]); targets.append(vector)
                histories[str(entity)].append(vector)
        if not targets: raise ValueError("Normal sequences are required for GRU sequence fitting")
        design, target = np.asarray(hidden_rows), np.asarray(targets)
        regularizer = self.ridge * np.eye(design.shape[1]); regularizer[-1, -1] = 0
        self.decoder = np.linalg.solve(design.T @ design + regularizer, design.T @ target)
        predictions = design @ self.decoder; errors = np.mean(np.abs(predictions - target), axis=1)
        self.error_low, self.error_high = float(np.quantile(errors, .5)), float(np.quantile(errors, .995))
        return self

    def _normalize(self, errors: np.ndarray) -> np.ndarray:
        return np.clip((errors - self.error_low) / max(self.error_high - self.error_low, 1e-9), 0, 1)

    def score_one(self, previous_scaled: np.ndarray, current_scaled: np.ndarray) -> float:
        # A sequence model cannot make a defensible temporal judgment during cold start.
        # The peer/global tabular baseline still scores those events; sequence evidence is
        # activated only after three preceding events are available for this entity.
        if len(previous_scaled) < 3:
            return 0.0
        prediction = self._predict(previous_scaled)
        return float(self._normalize(np.asarray([np.mean(np.abs(prediction - current_scaled))]))[0])

    def score_stream(self, scaled: np.ndarray, entities: np.ndarray) -> np.ndarray:
        histories: dict[str, deque] = defaultdict(lambda: deque(maxlen=self.window_size)); errors = []
        for vector, entity in zip(scaled, entities):
            history = histories[str(entity)]
            errors.append(None if len(history) < 3 else np.mean(np.abs(self._predict(list(history)) - vector)))
            history.append(vector)
        numeric = np.asarray([self.error_low if value is None else value for value in errors])
        scores = self._normalize(numeric); scores[[value is None for value in errors]] = 0.0
        return scores

    def model_metadata(self) -> dict:
        return {"type": "GRUSequenceDetector", "hidden_size": self.hidden_size, "window_size": self.window_size,
                "training": "normal_sequences_only", "implementation": "gated_recurrent_reservoir_ridge_decoder"}
