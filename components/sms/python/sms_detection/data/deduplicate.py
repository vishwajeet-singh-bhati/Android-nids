"""Exact and near-duplicate detection, plus leakage-resistant split groups.

SMS campaigns reuse templates with different OTPs, URLs and phone numbers. We
therefore group by:
  1. exact normalized text;
  2. a skeleton with URLs/phones/emails/digits masked (template variants);
  3. MinHash-LSH near-duplicate clusters (paraphrases and small edits).

The resulting ``split_group`` is used by the splitter so no template or campaign
can appear in both training and evaluation.
"""

from __future__ import annotations

import hashlib
import random
import re
from collections import defaultdict
from dataclasses import dataclass
from typing import Iterable, Sequence

import pandas as pd

from ..config import RANDOM_STATE
from ..preprocessing.normalize import normalize_text


@dataclass(frozen=True)
class DuplicateStats:
    rows: int
    exact_duplicate_rows: int
    exact_duplicate_groups: int
    template_groups: int
    near_duplicate_clusters: int
    near_duplicate_pairs: int
    largest_cluster: int


MAX_TEMPLATE_GROUP = 200


def add_dedup_columns(
    frame: pd.DataFrame,
    *,
    near_duplicate: bool = True,
    drop_exact_duplicates: bool = False,
) -> pd.DataFrame:
    if frame.empty:
        return frame.copy()
    frame = frame.copy()
    exact_keys: list[str] = []
    template_keys: list[str] = []
    normalized_texts: list[str] = []
    for text in frame["text"].tolist():
        normalized = normalize_text(text).normalized.lower()
        normalized_texts.append(normalized)
        exact_keys.append(_sha1(normalized))
        template_keys.append(_sha1(_template_skeleton(normalized)))
    frame["exact_key"] = exact_keys
    frame["template_key"] = template_keys
    frame["is_exact_duplicate"] = frame.duplicated(subset=["exact_key"], keep="first")
    frame["exact_duplicate_count"] = frame.groupby("exact_key")["exact_key"].transform("size")
    frame["template_duplicate_count"] = frame.groupby("template_key")[
        "template_key"
    ].transform("size")
    frame["duplicate_of"] = _duplicate_of(frame, exact_keys)

    original_rows = len(frame)
    exact_duplicate_rows = int(frame["is_exact_duplicate"].sum())
    exact_groups = frame.groupby("exact_key").size()
    exact_duplicate_groups = int((exact_groups > 1).sum())
    template_groups = int(frame["template_key"].nunique())

    if drop_exact_duplicates:
        # Cluster only unique texts. Campaign duplicates otherwise create
        # enormous template buckets and distort split-group sizes.
        frame = frame[~frame["is_exact_duplicate"]].reset_index(drop=True)
        exact_keys = frame["exact_key"].tolist()
        template_keys = frame["template_key"].tolist()
        normalized_texts = [
            normalize_text(text).normalized.lower() for text in frame["text"].tolist()
        ]

    if near_duplicate:
        clusters, pair_count = _cluster_messages(
            normalized_texts,
            exact_keys=exact_keys,
            template_keys=template_keys,
        )
    else:
        clusters, pair_count = _cluster_by_keys(exact_keys, template_keys), 0

    frame["near_dup_cluster"] = clusters
    frame["split_group"] = ["grp-" + cluster for cluster in clusters]
    frame.attrs["near_duplicate_pairs"] = pair_count
    frame.attrs["original_rows"] = original_rows
    frame.attrs["exact_duplicate_rows"] = exact_duplicate_rows
    frame.attrs["exact_duplicate_groups"] = exact_duplicate_groups
    frame.attrs["template_groups"] = template_groups
    return frame


def duplicate_stats(frame: pd.DataFrame) -> DuplicateStats:
    cluster_sizes = frame.groupby("near_dup_cluster").size()
    return DuplicateStats(
        rows=int(frame.attrs.get("original_rows", len(frame))),
        exact_duplicate_rows=int(
            frame.attrs.get("exact_duplicate_rows", frame["is_exact_duplicate"].sum())
        ),
        exact_duplicate_groups=int(
            frame.attrs.get(
                "exact_duplicate_groups",
                int((frame.groupby("exact_key").size() > 1).sum()),
            )
        ),
        template_groups=int(frame.attrs.get("template_groups", frame["template_key"].nunique())),
        near_duplicate_clusters=int(frame["near_dup_cluster"].nunique()),
        near_duplicate_pairs=int(frame.attrs.get("near_duplicate_pairs", 0)),
        largest_cluster=int(cluster_sizes.max()) if len(cluster_sizes) else 0,
    )


def _duplicate_of(frame: pd.DataFrame, exact_keys: Sequence[str]) -> list[str | None]:
    first: dict[str, str] = {}
    result: list[str | None] = []
    for key, message_id in zip(exact_keys, frame["message_id"].tolist()):
        if key in first:
            result.append(first[key])
        else:
            first[key] = message_id
            result.append(None)
    return result


def _template_skeleton(normalized: str) -> str:
    text = normalized.lower()
    text = re.sub(r"url_present|email_present|phone_present", " entity ", text)
    text = re.sub(r"\d+", " # ", text)
    text = re.sub(r"[^\w#]+", " ", text, flags=re.UNICODE)
    text = re.sub(r"\s+", " ", text).strip()
    return text


def _sha1(value: str) -> str:
    return hashlib.sha1(value.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# MinHash-LSH
# ---------------------------------------------------------------------------

_NUM_PERM = 64
_BAND_ROWS = 4
_SEEDS = [random.Random(RANDOM_STATE + i).getrandbits(64) for i in range(_NUM_PERM)]


def _shingles(text: str) -> set[tuple[str, ...]]:
    tokens = re.findall(r"\w+", text.lower(), flags=re.UNICODE)
    if len(tokens) < 3:
        return {tuple(tokens)} if tokens else {("",)}
    return {tuple(tokens[i : i + 3]) for i in range(len(tokens) - 2)}


def _base_hash(shingle: tuple[str, ...]) -> int:
    value = " ".join(shingle).encode("utf-8")
    return int.from_bytes(hashlib.blake2b(value, digest_size=8).digest(), "big")


def _minhash(shingle_set: Iterable[tuple[str, ...]]) -> tuple[int, ...]:
    hashes = [_base_hash(shingle) for shingle in shingle_set]
    if not hashes:
        return tuple([0] * _NUM_PERM)
    return tuple(min(h ^ seed for h in hashes) for seed in _SEEDS)


def _jaccard(left: set[tuple[str, ...]], right: set[tuple[str, ...]]) -> float:
    if not left and not right:
        return 1.0
    union = len(left | right)
    return len(left & right) / union if union else 1.0


def _cluster_messages(
    texts: Sequence[str],
    *,
    exact_keys: Sequence[str],
    template_keys: Sequence[str],
    threshold: float = 0.8,
) -> tuple[list[str], int]:
    n = len(texts)
    parent = list(range(n))
    rank = [0] * n

    def find(index: int) -> int:
        while parent[index] != index:
            parent[index] = parent[parent[index]]
            index = parent[index]
        return index

    def union(a: int, b: int) -> None:
        root_a, root_b = find(a), find(b)
        if root_a == root_b:
            return
        if rank[root_a] < rank[root_b]:
            root_a, root_b = root_b, root_a
        parent[root_b] = root_a
        if rank[root_a] == rank[root_b]:
            rank[root_a] += 1

    # Exact and template grouping are cheap and high precision. A template
    # bucket that is too large is left to MinHash instead of merging unrelated
    # messages into one giant split group.
    for kind, keys in (("exact", exact_keys), ("template", template_keys)):
        buckets: dict[str, list[int]] = defaultdict(list)
        for index, key in enumerate(keys):
            buckets[key].append(index)
        for members in buckets.values():
            if kind == "template" and len(members) > MAX_TEMPLATE_GROUP:
                continue
            first = members[0]
            for index in members[1:]:
                union(index, first)

    # MinHash-LSH candidates, verified with exact Jaccard.
    shingle_sets = [_shingles(text) for text in texts]
    signatures = [_minhash(shingle_set) for shingle_set in shingle_sets]
    buckets: dict[tuple[int, tuple[int, ...]], list[int]] = defaultdict(list)
    for index, signature in enumerate(signatures):
        for band in range(_NUM_PERM // _BAND_ROWS):
            start = band * _BAND_ROWS
            key = (band, signature[start : start + _BAND_ROWS])
            buckets[key].append(index)

    seen_pairs: set[tuple[int, int]] = set()
    pair_count = 0
    for members in buckets.values():
        if len(members) < 2:
            continue
        for i in range(len(members)):
            for j in range(i + 1, len(members)):
                a, b = members[i], members[j]
                if a > b:
                    a, b = b, a
                if (a, b) in seen_pairs:
                    continue
                seen_pairs.add((a, b))
                if find(a) == find(b):
                    continue
                if _jaccard(shingle_sets[a], shingle_sets[b]) >= threshold:
                    union(a, b)
                    pair_count += 1

    roots = [find(index) for index in range(n)]
    return [f"c{root:06d}" for root in roots], pair_count


def _cluster_by_keys(exact_keys: Sequence[str], template_keys: Sequence[str]) -> list[str]:
    parent = list(range(len(exact_keys)))

    def find(index: int) -> int:
        while parent[index] != index:
            parent[index] = parent[parent[index]]
            index = parent[index]
        return index

    def union(a: int, b: int) -> None:
        root_a, root_b = find(a), find(b)
        if root_a != root_b:
            parent[root_b] = root_a

    for kind, keys in (("exact", exact_keys), ("template", template_keys)):
        buckets: dict[str, list[int]] = defaultdict(list)
        for index, key in enumerate(keys):
            buckets[key].append(index)
        for members in buckets.values():
            if kind == "template" and len(members) > MAX_TEMPLATE_GROUP:
                continue
            first = members[0]
            for index in members[1:]:
                union(index, first)
    return [f"c{find(index):06d}" for index in range(len(exact_keys))]
