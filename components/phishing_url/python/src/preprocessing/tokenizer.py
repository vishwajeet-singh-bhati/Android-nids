"""Character-level URL tokenizer with a fixed, versioned vocabulary.

Input is expected to be the `model_string` of a NormalizedURL (ASCII only),
but any str is accepted: unknown characters map to UNK. Pure Python + NumPy,
so it has no PyTorch dependency and can run on minimal edge installs.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Sequence

import numpy as np

FORMAT_VERSION = 1
TOKENIZER_TYPE = "char_ascii_head_tail"

PAD_ID = 0
UNK_ID = 1
TRUNC_ID = 2
NUM_RESERVED = 3

# Printable ASCII without the space: '!' (0x21) .. '~' (0x7E) = 94 characters.
DEFAULT_CHARSET = "".join(chr(c) for c in range(0x21, 0x7F))
DEFAULT_MAX_LENGTH = 256
DEFAULT_TAIL_LENGTH = 64
MIN_MAX_LENGTH = 8

_REQUIRED_KEYS = frozenset(
    {"format_version", "type", "max_length", "tail_length",
     "pad_id", "unk_id", "trunc_id", "charset"}
)


@dataclass(frozen=True, slots=True, eq=False)
class Encoded:
    """Result of encoding one string."""

    ids: np.ndarray        # shape (max_length,), int64, right-padded with PAD_ID
    length: int            # real tokens, including the TRUNC marker; excludes padding
    truncated: bool        # True if the input was longer than max_length
    original_length: int   # number of characters in the input


@dataclass(frozen=True, slots=True, eq=False)
class BatchEncoded:
    """Result of encoding many strings."""

    ids: np.ndarray        # shape (n, max_length), int64
    lengths: np.ndarray    # shape (n,), int64
    truncated: np.ndarray  # shape (n,), bool


class URLTokenizer:
    def __init__(
        self,
        max_length: int = DEFAULT_MAX_LENGTH,
        tail_length: int = DEFAULT_TAIL_LENGTH,
        charset: str = DEFAULT_CHARSET,
    ) -> None:
        for name, value in (("max_length", max_length), ("tail_length", tail_length)):
            if isinstance(value, bool) or not isinstance(value, int):
                raise TypeError(f"{name} must be an int")
        if not isinstance(charset, str):
            raise TypeError("charset must be a str")
        if max_length < MIN_MAX_LENGTH:
            raise ValueError(f"max_length must be >= {MIN_MAX_LENGTH}")
        if not 0 <= tail_length <= max_length - 2:
            raise ValueError("tail_length must satisfy 0 <= tail_length <= max_length - 2")
        if not charset:
            raise ValueError("charset must not be empty")
        if len(set(charset)) != len(charset):
            raise ValueError("charset contains duplicate characters")
        if any(ch.isspace() for ch in charset):
            raise ValueError("charset must not contain whitespace")

        self.max_length = max_length
        self.tail_length = tail_length
        self.charset = charset
        self._index = {ch: i + NUM_RESERVED for i, ch in enumerate(charset)}

    # ------------------------------------------------------------------ info
    @property
    def vocab_size(self) -> int:
        return NUM_RESERVED + len(self.charset)

    @property
    def head_length(self) -> int:
        """Characters kept from the start when truncating."""
        return self.max_length - self.tail_length - 1  # -1 for the TRUNC marker

    # -------------------------------------------------------------- encoding
    def _tokenize(self, text: str) -> tuple[list[int], bool, int]:
        if not isinstance(text, str):
            raise TypeError("text must be a str")
        get = self._index.get
        n = len(text)
        if n <= self.max_length:
            return [get(c, UNK_ID) for c in text], False, n
        head = text[: self.head_length]
        tail = text[n - self.tail_length:]  # safe when tail_length == 0
        ids = [get(c, UNK_ID) for c in head]
        ids.append(TRUNC_ID)
        ids.extend(get(c, UNK_ID) for c in tail)
        return ids, True, n

    def encode(self, text: str) -> Encoded:
        tokens, truncated, original_length = self._tokenize(text)
        ids = np.full(self.max_length, PAD_ID, dtype=np.int64)
        ids[: len(tokens)] = tokens
        return Encoded(ids=ids, length=len(tokens), truncated=truncated,
                       original_length=original_length)

    def encode_batch(self, texts: Sequence[str]) -> BatchEncoded:
        if isinstance(texts, str):
            raise TypeError("encode_batch expects a sequence of strings, not one str")
        ids = np.full((len(texts), self.max_length), PAD_ID, dtype=np.int64)
        lengths = np.zeros(len(texts), dtype=np.int64)
        truncated = np.zeros(len(texts), dtype=bool)
        for row, text in enumerate(texts):
            tokens, was_truncated, _ = self._tokenize(text)
            ids[row, : len(tokens)] = tokens
            lengths[row] = len(tokens)
            truncated[row] = was_truncated
        return BatchEncoded(ids=ids, lengths=lengths, truncated=truncated)

    def decode(self, ids: Sequence[int]) -> str:
        """Debugging aid: turn IDs back into text (PAD skipped)."""
        parts: list[str] = []
        for raw in ids:
            i = int(raw)
            if i == PAD_ID:
                continue
            if i == TRUNC_ID:
                parts.append("<TRUNC>")
            elif i == UNK_ID:
                parts.append("<UNK>")
            elif 0 <= i - NUM_RESERVED < len(self.charset):
                parts.append(self.charset[i - NUM_RESERVED])
            else:
                raise ValueError(f"token id out of range: {i}")
        return "".join(parts)

    # --------------------------------------------------------- serialization
    def to_config(self) -> dict[str, Any]:
        return {
            "format_version": FORMAT_VERSION,
            "type": TOKENIZER_TYPE,
            "max_length": self.max_length,
            "tail_length": self.tail_length,
            "pad_id": PAD_ID,
            "unk_id": UNK_ID,
            "trunc_id": TRUNC_ID,
            "charset": self.charset,
        }

    def fingerprint(self) -> str:
        """SHA-256 of the canonical config; store it with the model checkpoint."""
        canonical = json.dumps(self.to_config(), sort_keys=True,
                               separators=(",", ":"), ensure_ascii=True)
        return hashlib.sha256(canonical.encode("ascii")).hexdigest()

    @classmethod
    def from_config(cls, config: dict[str, Any]) -> "URLTokenizer":
        if not isinstance(config, dict):
            raise ValueError("tokenizer config must be a JSON object")
        missing = _REQUIRED_KEYS - config.keys()
        if missing:
            raise ValueError(f"tokenizer config missing keys: {sorted(missing)}")
        if config["format_version"] != FORMAT_VERSION:
            raise ValueError(f"unsupported tokenizer format_version: {config['format_version']!r}")
        if config["type"] != TOKENIZER_TYPE:
            raise ValueError(f"unsupported tokenizer type: {config['type']!r}")
        if (config["pad_id"], config["unk_id"], config["trunc_id"]) != (PAD_ID, UNK_ID, TRUNC_ID):
            raise ValueError("reserved token ids do not match this tokenizer version")
        return cls(max_length=config["max_length"], tail_length=config["tail_length"],
                   charset=config["charset"])

    def save(self, path: str | Path) -> None:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.to_config(), indent=2, ensure_ascii=True) + "\n",
                        encoding="utf-8")

    @classmethod
    def load(cls, path: str | Path) -> "URLTokenizer":
        try:
            config = json.loads(Path(path).read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise ValueError("tokenizer file is not valid JSON") from exc
        return cls.from_config(config)