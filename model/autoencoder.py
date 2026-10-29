"""Dense autoencoder over windowed syscall-ID sequences (Phase 5 decision:
dense first, per IMPLEMENTATION_PLAN.md -- sequence model is a stretch goal).

Each window position is embedded, flattened, and passed through an
encoder/decoder MLP that reconstructs a per-position vocab distribution.
Reconstruction error is per-position cross-entropy against the true token --
this is the anomaly score.
"""

import torch
import torch.nn as nn
import torch.nn.functional as F


class DenseAutoencoder(nn.Module):
    def __init__(self, vocab_size: int, window_size: int,
                 embed_dim: int = 16, hidden_dim: int = 128, bottleneck_dim: int = 32):
        super().__init__()
        self.vocab_size = vocab_size
        self.window_size = window_size

        self.embedding = nn.Embedding(vocab_size, embed_dim)
        input_dim = window_size * embed_dim

        self.encoder = nn.Sequential(
            nn.Linear(input_dim, hidden_dim),
            nn.ReLU(),
            nn.Linear(hidden_dim, bottleneck_dim),
            nn.ReLU(),
        )
        self.decoder = nn.Sequential(
            nn.Linear(bottleneck_dim, hidden_dim),
            nn.ReLU(),
            nn.Linear(hidden_dim, window_size * vocab_size),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        """x: (batch, window_size) int64 token indices.
        Returns logits: (batch, window_size, vocab_size)."""
        emb = self.embedding(x)
        flat = emb.view(emb.size(0), -1)
        z = self.encoder(flat)
        out = self.decoder(z)
        return out.view(-1, self.window_size, self.vocab_size)


def reconstruction_error(logits: torch.Tensor, targets: torch.Tensor) -> torch.Tensor:
    """Per-sample mean cross-entropy across window positions -- the anomaly
    score. logits: (batch, window_size, vocab_size), targets: (batch, window_size)."""
    batch, window_size, vocab_size = logits.shape
    ce = F.cross_entropy(
        logits.reshape(-1, vocab_size), targets.reshape(-1), reduction="none"
    )
    return ce.view(batch, window_size).mean(dim=1)
