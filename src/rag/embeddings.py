"""Offline embedding model for LlamaIndex.

A deterministic feature-hashing embedding (unigrams + bigrams, sublinear TF,
L2-normalised) that implements LlamaIndex's ``BaseEmbedding`` interface.  It
lets the vector RAG pipeline run with no API key, in CI and in tests, while
production can switch to OpenAI embeddings with ``EMBEDDING_PROVIDER=openai``.
"""
from __future__ import annotations

import math
import re
import zlib
from typing import Dict, Iterable, List

from llama_index.core.base.embeddings.base import BaseEmbedding
from pydantic import Field

_TOKEN = re.compile(r"[A-Za-z][A-Za-z0-9]*|\d+")
_CAMEL = re.compile(r"(?<=[a-z])(?=[A-Z])")
STOPWORDS = frozenset(
    "a an and are as at be by for from has have in is it its of on or that the this to was were will with "
    "must should not never use using only any all every be been can may into than then them they you your".split()
)


def _stem(tok: str) -> str:
    for suffix in ("ing", "ion", "ed", "es", "s"):
        if len(tok) > len(suffix) + 2 and tok.endswith(suffix):
            return tok[: -len(suffix)]
    return tok


def tokenize(text: str) -> List[str]:
    tokens: List[str] = []
    for raw in _TOKEN.findall(text.replace("_", " ")):
        for part in _CAMEL.split(raw):
            t = part.lower()
            if t and t not in STOPWORDS:
                tokens.append(_stem(t))
    return tokens


class HashingEmbedding(BaseEmbedding):
    """Signed feature-hashing embedding; no network, no model download."""

    dim: int = Field(default=4096, description="Embedding dimensionality")
    idf: Dict[str, float] = Field(default_factory=dict, description="Feature IDF weights fitted on the corpus")
    default_idf: float = Field(default=1.0)

    @classmethod
    def class_name(cls) -> str:
        return "HashingEmbedding"

    @staticmethod
    def _features(text: str) -> List[str]:
        toks = tokenize(text)
        return toks + [f"{a}_{b}" for a, b in zip(toks, toks[1:])]

    def fit(self, corpus: Iterable[str]) -> "HashingEmbedding":
        """Fit smoothed IDF weights so rare, discriminative terms dominate."""
        docs = [set(self._features(t)) for t in corpus]
        n = len(docs) or 1
        df: Dict[str, int] = {}
        for d in docs:
            for f in d:
                df[f] = df.get(f, 0) + 1
        self.idf = {f: math.log((1 + n) / (1 + c)) + 1.0 for f, c in df.items()}
        self.default_idf = math.log(1 + n) + 1.0
        return self

    def _embed(self, text: str) -> List[float]:
        vec = [0.0] * self.dim
        feats = self._features(text)
        counts: dict = {}
        for f in feats:
            counts[f] = counts.get(f, 0) + 1
        for feat, c in counts.items():
            h = zlib.crc32(feat.encode("utf-8"))
            idx = h % self.dim
            sign = 1.0 if (h >> 31) & 1 == 0 else -1.0
            idf = self.idf.get(feat, self.default_idf) if self.idf else 1.0
            weight = (1.0 + math.log(c)) * idf * (0.6 if "_" in feat else 1.0)
            vec[idx] += sign * weight
        norm = math.sqrt(sum(v * v for v in vec)) or 1.0
        return [v / norm for v in vec]

    def _get_query_embedding(self, query: str) -> List[float]:
        return self._embed(query)

    def _get_text_embedding(self, text: str) -> List[float]:
        return self._embed(text)

    async def _aget_query_embedding(self, query: str) -> List[float]:
        return self._embed(query)

    async def _aget_text_embedding(self, text: str) -> List[float]:
        return self._embed(text)
