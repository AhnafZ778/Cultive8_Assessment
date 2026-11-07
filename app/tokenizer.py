"""Exact local model tokenizer backed by Ollama /api/show GGUF BPE vocabulary."""
from __future__ import annotations

import math
import threading
from typing import Dict, Optional

import requests
import tokenizers

from . import DEFAULT_MODEL

OLLAMA_BASE_URL = "http://127.0.0.1:11434"


class ModelTokenizer:
    """Counts tokens using the local model's embedded GGUF BPE vocabulary from Ollama."""

    _cache_lock = threading.Lock()
    _bpe_cache: Dict[str, tokenizers.Tokenizer] = {}

    def __init__(self, model_name: str = DEFAULT_MODEL, base_url: str = OLLAMA_BASE_URL) -> None:
        self.model_name = model_name
        self.base_url = base_url.rstrip("/")
        self._tokenizer: Optional[tokenizers.Tokenizer] = None
        self.backend_source: str = "uninitialized"

    def _load_bpe(self) -> Optional[tokenizers.Tokenizer]:
        if self._tokenizer is not None:
            return self._tokenizer
        with self._cache_lock:
            cached = self._bpe_cache.get(self.model_name)
            if cached is not None:
                self._tokenizer = cached
                self.backend_source = f"ollama-gguf-bpe:{self.model_name}"
                return cached
        try:
            resp = requests.post(
                f"{self.base_url}/api/show",
                json={"model": self.model_name, "verbose": True},
                timeout=12,
            )
            resp.raise_for_status()
            data = resp.json()
            model_info = data.get("model_info") or {}
            tokens = model_info.get("tokenizer.ggml.tokens")
            merges_raw = model_info.get("tokenizer.ggml.merges")
            if isinstance(tokens, list) and isinstance(merges_raw, list) and tokens and merges_raw:
                vocab = {tok_str: idx for idx, tok_str in enumerate(tokens)}
                merges = []
                for item in merges_raw:
                    if isinstance(item, str) and " " in item:
                        a, b = item.split(" ", 1)
                        merges.append((a, b))
                    elif isinstance(item, (list, tuple)) and len(item) == 2:
                        merges.append((str(item[0]), str(item[1])))
                tok = tokenizers.Tokenizer(tokenizers.models.BPE(vocab=vocab, merges=merges))
                tok.pre_tokenizer = tokenizers.pre_tokenizers.ByteLevel(
                    add_prefix_space=False, use_regex=True
                )
                with self._cache_lock:
                    self._bpe_cache[self.model_name] = tok
                self._tokenizer = tok
                self.backend_source = f"ollama-gguf-bpe:{self.model_name}"
                return tok
        except Exception:
            pass
        self.backend_source = "conservative-utf8-fallback"
        return None

    def count_tokens(self, text: str) -> int:
        """Count tokens for text using exact model BPE tokenizer (or conservative fallback)."""
        if not text:
            return 0
        tok = self._load_bpe()
        if tok is not None:
            try:
                return len(tok.encode(text).ids)
            except Exception:
                pass
        # Conservative fallback: 1 token per 2.7 UTF-8 bytes + newline count
        byte_len = len(text.encode("utf-8", errors="replace"))
        return max(1, math.ceil(byte_len / 2.7))
