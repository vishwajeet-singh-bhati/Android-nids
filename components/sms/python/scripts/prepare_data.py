"""Build the unified, provenance-aware dataset and leakage-resistant splits.

Split policy
------------
* UCI + LSDST groups form the main pool.
* 10% of those groups are reserved as ``external_holdout`` before training.
* The remaining pool is split by group into train / validation / test.
* NCSU phishing messages are an ``external_source`` test set.
* Hand-written Hinglish rows (the subset not derived from UCI) are an
  ``external_seed`` robustness set.
* Any external row whose template/campaign group also appears in the main pool
  is removed and reported as leakage risk.

No group (template, near-duplicate cluster or campaign) can appear in more than
one split.
"""

from __future__ import annotations

import argparse
import json
import math
import random
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd

from sms_detection.config import PROCESSED_DIR, RANDOM_STATE, RAW_DIR
from sms_detection.data.deduplicate import add_dedup_columns, duplicate_stats
from sms_detection.data.load_sources import load_all_sources

MAIN_SOURCES = {"uci_sms_spam", "lsdst_2022"}
EXTERNAL_SOURCE = "ncsu_sms_phishing"
SEED_SOURCE = "hinglish_scam"


def build_dataset(
    raw_dir: str | Path = RAW_DIR,
    output_dir: str | Path = PROCESSED_DIR,
    *,
    seed: int = RANDOM_STATE,
    near_duplicate: bool = True,
    external_holdout_fraction: float = 0.10,
) -> dict:
    raw_dir = Path(raw_dir)
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    print("[1/6] loading sources")
    frame = load_all_sources(raw_dir)
    print(f"      {len(frame):,} rows from {frame['source_dataset'].nunique()} sources")

    print("[2/6] exact/template/near-duplicate grouping")
    # Keep the best-provenance representative when exact duplicates span
    # sources: main training sources first, then external, then Hinglish.
    source_priority = {
        "uci_sms_spam": 0,
        "lsdst_2022": 1,
        "ncsu_sms_phishing": 2,
        "hinglish_scam": 3,
    }
    frame = frame.sort_values(
        by="source_dataset", key=lambda series: series.map(source_priority)
    ).reset_index(drop=True)
    frame = add_dedup_columns(
        frame,
        near_duplicate=near_duplicate,
        drop_exact_duplicates=True,
    )
    stats = duplicate_stats(frame)
    print(
        f"      exact duplicates={stats.exact_duplicate_rows:,}; "
        f"near-dup clusters={stats.near_duplicate_clusters:,}; "
        f"largest cluster={stats.largest_cluster}"
    )
    deduped = frame.copy()
    dropped_exact = stats.exact_duplicate_rows

    # Campaign IDs are a stronger grouping key than text for NCSU.
    campaign_mask = deduped["campaign_id"].notna() & (
        deduped["source_dataset"] == EXTERNAL_SOURCE
    )
    deduped.loc[campaign_mask, "split_group"] = (
        deduped.loc[campaign_mask, "source_dataset"].astype(str)
        + "-campaign-"
        + deduped.loc[campaign_mask, "campaign_id"].astype(str).str.replace(r"\.0$", "", regex=True)
    )

    print("[3/6] assigning external components")
    deduped["split"] = None
    deduped["external_component"] = None

    ncsu = deduped[deduped["source_dataset"] == EXTERNAL_SOURCE].copy()
    ncsu["split"] = "external"
    ncsu["external_component"] = "ncsu_smishing"

    hinglish_seed = deduped[
        (deduped["source_dataset"] == SEED_SOURCE) & (~deduped["derived_from_uci"])
    ].copy()
    hinglish_seed["split"] = "external"
    hinglish_seed["external_component"] = "hinglish_seed"

    pool = deduped[deduped["source_dataset"].isin(MAIN_SOURCES)].copy()
    if pool.empty:
        raise RuntimeError("Main training pool is empty; check UCI/LSDST raw files.")
    if "smishing" not in set(pool["label"]):
        raise RuntimeError(
            "No smishing rows in the main pool. LSDST-2022 is required for a 3-class model."
        )

    # Reserve a stratified external holdout by split_group, then split the rest.
    holdout_groups = _reserve_groups(
        pool,
        fraction=external_holdout_fraction,
        seed=seed,
        label_priority=("smishing", "spam", "ham"),
    )
    holdout = pool[pool["split_group"].isin(holdout_groups)].copy()
    holdout["split"] = "external"
    holdout["external_component"] = "classic_holdout"

    remaining = pool[~pool["split_group"].isin(holdout_groups)].copy()
    assignments = _assign_groups(
        remaining,
        fractions={"train": 0.70, "val": 0.15, "test": 0.15},
        seed=seed,
    )
    remaining["split"] = remaining["split_group"].map(assignments)
    if remaining["split"].isna().any():
        missing = remaining[remaining["split"].isna()]
        raise RuntimeError(f"{len(missing)} rows were not assigned to a split")

    print("[4/6] checking cross-source group leakage")
    main_groups = set(remaining["split_group"]) | set(holdout["split_group"])
    external = pd.concat([ncsu, hinglish_seed, holdout], ignore_index=True)
    leaked = external["split_group"].isin(main_groups) & (external["external_component"] != "classic_holdout")
    leaked_count = int(leaked.sum())
    if leaked_count:
        print(f"      dropping {leaked_count} external rows sharing a group with training")
        external = external[~leaked].copy()

    print("[5/6] finalising splits")
    all_rows = pd.concat([remaining, external], ignore_index=True)
    all_rows["split"] = all_rows["split"].fillna("unassigned")
    all_rows = all_rows.sort_values(["split", "source_dataset", "label", "message_id"]).reset_index(drop=True)

    split_frames = {
        "train": all_rows[all_rows["split"] == "train"].copy(),
        "val": all_rows[all_rows["split"] == "val"].copy(),
        "test": all_rows[all_rows["split"] == "test"].copy(),
        "external": all_rows[all_rows["split"] == "external"].copy(),
    }
    for name, split_frame in split_frames.items():
        path = output_dir / f"{name}.csv"
        split_frame.to_csv(path, index=False, encoding="utf-8")
        print(f"      wrote {path} ({len(split_frame):,} rows)")

    all_rows.to_csv(output_dir / "all.csv", index=False, encoding="utf-8")
    for component in ("ncsu_smishing", "classic_holdout", "hinglish_seed"):
        component_frame = all_rows[all_rows["external_component"] == component]
        component_frame.to_csv(output_dir / f"external_{component}.csv", index=False, encoding="utf-8")

    manifest = _manifest(
        all_rows,
        split_frames,
        stats,
        dropped_exact=dropped_exact,
        leaked_external=leaked_count,
        seed=seed,
        external_holdout_fraction=external_holdout_fraction,
    )
    (output_dir / "split_manifest.json").write_text(
        json.dumps(manifest, indent=2), encoding="utf-8"
    )

    print("[6/6] split summary")
    print(_summary_table(all_rows))
    print(f"\n      manifest: {output_dir / 'split_manifest.json'}")
    return manifest


def _reserve_groups(
    frame: pd.DataFrame,
    *,
    fraction: float,
    seed: int,
    label_priority: tuple[str, ...],
) -> set[str]:
    rng = random.Random(seed)
    group_labels = _group_labels(frame)
    reserved: set[str] = set()
    for label in label_priority:
        groups = sorted(group_labels[group_labels == label].index)
        if not groups:
            continue
        rng.shuffle(groups)
        count = max(1, int(math.ceil(len(groups) * fraction))) if len(groups) > 1 else 0
        reserved.update(groups[:count])
    return reserved


def _assign_groups(
    frame: pd.DataFrame,
    *,
    fractions: dict[str, float],
    seed: int,
) -> dict[str, str]:
    rng = random.Random(seed)
    group_labels = _group_labels(frame)
    group_sizes = frame.groupby("split_group").size()
    total = int(group_sizes.sum())
    targets = {name: fraction * total for name, fraction in fractions.items()}
    assigned: dict[str, str] = {}

    for label in ("smishing", "spam", "ham"):
        groups = sorted(group_labels[group_labels == label].index)
        rng.shuffle(groups)
        groups.sort(key=lambda group: group_sizes.get(group, 0), reverse=True)
        counts = {name: 0 for name in fractions}
        for group in groups:
            size = int(group_sizes.get(group, 0))
            # Assign to the split with the largest remaining deficit. This keeps
            # class proportions stable when template group sizes vary.
            choice = max(
                fractions,
                key=lambda name: (targets[name] - counts[name]) / max(1.0, targets[name]),
            )
            assigned[group] = choice
            counts[choice] += size
    return assigned


def _group_labels(frame: pd.DataFrame) -> pd.Series:
    # A group should normally have one label. If not, prefer the most harmful
    # label so the group is never treated as benign in evaluation.
    priority = {"smishing": 3, "spam": 2, "ham": 1}
    rows = frame[["split_group", "label"]].copy()
    rows["priority"] = rows["label"].map(priority).fillna(0)
    index = rows.groupby("split_group")["priority"].idxmax()
    return frame.loc[index].set_index("split_group")["label"]


def _manifest(
    frame: pd.DataFrame,
    splits: dict[str, pd.DataFrame],
    stats,
    *,
    dropped_exact: int,
    leaked_external: int,
    seed: int,
    external_holdout_fraction: float,
) -> dict:
    def counts(subset: pd.DataFrame) -> dict:
        return {
            "rows": int(len(subset)),
            "labels": {str(k): int(v) for k, v in subset["label"].value_counts().items()},
            "sources": {
                str(k): int(v) for k, v in subset["source_dataset"].value_counts().items()
            },
            "groups": int(subset["split_group"].nunique()),
        }

    return {
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "seed": seed,
        "policy": {
            "main_sources": sorted(MAIN_SOURCES),
            "external_source": EXTERNAL_SOURCE,
            "seed_source": SEED_SOURCE,
            "external_holdout_fraction": external_holdout_fraction,
            "train_val_test": {"train": 0.70, "val": 0.15, "test": 0.15},
            "group_key": "split_group (exact text + masked template + MinHash near-duplicate + NCSU campaign)",
            "no_group_overlap": True,
        },
        "duplicates": {
            "exact_duplicate_rows": stats.exact_duplicate_rows,
            "exact_duplicate_groups": stats.exact_duplicate_groups,
            "template_groups": stats.template_groups,
            "near_duplicate_clusters": stats.near_duplicate_clusters,
            "near_duplicate_pairs": stats.near_duplicate_pairs,
            "largest_cluster": stats.largest_cluster,
            "dropped_exact_rows": dropped_exact,
            "dropped_external_leakage_rows": leaked_external,
        },
        "splits": {name: counts(subset) for name, subset in splits.items()},
    }


def _summary_table(frame: pd.DataFrame) -> str:
    table = pd.crosstab(frame["split"], frame["label"], margins=True, margins_name="total")
    return table.to_string()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Prepare unified dataset and splits")
    parser.add_argument("--raw-dir", default=str(RAW_DIR))
    parser.add_argument("--output-dir", default=str(PROCESSED_DIR))
    parser.add_argument("--seed", type=int, default=RANDOM_STATE)
    parser.add_argument("--no-near-duplicate", action="store_true")
    args = parser.parse_args(argv)
    build_dataset(
        args.raw_dir,
        args.output_dir,
        seed=args.seed,
        near_duplicate=not args.no_near_duplicate,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
