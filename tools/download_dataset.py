#!/usr/bin/env python3
import argparse
import json
import random
from pathlib import Path
from typing import Dict, Iterable, List, Tuple


def _pick_split(ds, preferred: Iterable[str]):
    for name in preferred:
        if name in ds:
            return ds[name]
    # Fall back to the first split deterministically.
    return ds[sorted(ds.keys())[0]]


def _load_scifact():
    try:
        from datasets import load_dataset  # type: ignore
    except ModuleNotFoundError as e:
        raise SystemExit(
            "Missing dependency: `datasets`.\n"
            "Install: `python3 -m pip install datasets`"
        ) from e

    # Note: `beir/scifact` on HF provides corpus+queries, while qrels are hosted separately at:
    #   `beir/scifact-qrels` (test.tsv/train.tsv)
    corpus_ds = load_dataset("beir/scifact", "corpus", trust_remote_code=True)
    queries_ds = load_dataset("beir/scifact", "queries", trust_remote_code=True)
    qrels_rows = _load_scifact_qrels_split("test")

    corpus = _pick_split(corpus_ds, ["corpus", "train", "test", "validation"])
    queries = _pick_split(queries_ds, ["queries", "test", "train", "validation"])

    return corpus, queries, qrels_rows


def _load_scifact_qrels_split(split: str) -> List[dict]:
    import csv

    try:
        from huggingface_hub import hf_hub_download  # type: ignore
    except ModuleNotFoundError as e:
        raise SystemExit(
            "Missing dependency: `huggingface_hub`.\n"
            "Install: `python3 -m pip install huggingface_hub`"
        ) from e

    filename = {"test": "test.tsv", "train": "train.tsv"}.get(split)
    if filename is None:
        raise ValueError(f"Unsupported qrels split: {split}")

    path = hf_hub_download("beir/scifact-qrels", filename, repo_type="dataset")
    rows: List[dict] = []
    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f, delimiter="\t")
        for row in reader:
            rows.append(row)
    return rows


def _normalize_query(row: dict) -> Tuple[str, str]:
    qid = row.get("_id") or row.get("id") or row.get("query_id") or row.get("query-id")
    text = row.get("text") or row.get("query") or row.get("query_text")
    if qid is None or text is None:
        raise ValueError(f"Unrecognized query schema: keys={sorted(row.keys())}")
    return str(qid), str(text)


def _normalize_doc(row: dict) -> Tuple[str, str, str]:
    doc_id = row.get("_id") or row.get("id") or row.get("corpus_id") or row.get("corpus-id")
    title = row.get("title") or ""
    text = row.get("text") or row.get("abstract") or row.get("contents") or ""
    if doc_id is None:
        raise ValueError(f"Unrecognized corpus schema: keys={sorted(row.keys())}")
    return str(doc_id), str(title), str(text)


def _normalize_qrel(row: dict) -> Tuple[str, str, int]:
    qid = row.get("query-id") or row.get("query_id") or row.get("_id") or row.get("qid")
    doc_id = row.get("corpus-id") or row.get("corpus_id") or row.get("doc_id") or row.get("doc-id")
    score = row.get("score") or row.get("relevance") or row.get("label") or 0
    if qid is None or doc_id is None:
        raise ValueError(f"Unrecognized qrels schema: keys={sorted(row.keys())}")
    return str(qid), str(doc_id), int(score)


def _build_qrels_by_query(qrels_rows: Iterable[dict]) -> Dict[str, Dict[str, int]]:
    out: Dict[str, Dict[str, int]] = {}
    for row in qrels_rows:
        qid, doc_id, score = _normalize_qrel(row)
        if score <= 0:
            continue
        out.setdefault(qid, {})[doc_id] = max(out.setdefault(qid, {}).get(doc_id, 0), score)
    return out


def _doc_set_for(qids: List[str], qrels_by_qid: Dict[str, Dict[str, int]]) -> set:
    docs = set()
    for qid in qids:
        for doc_id in qrels_by_qid.get(qid, {}):
            docs.add(doc_id)
    return docs


def _make_did(domain: str, role: str, idx: int) -> str:
    return f"did:web:{domain}:{role}:{idx:04d}"


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate a SciFact-based AASI experiment dataset.")
    parser.add_argument("--out", required=True, help="Output directory (e.g., datasets/scifact_1k)")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--n", "--n-agents", dest="n_agents", type=int, default=1000)
    parser.add_argument("--n-elite", type=int, default=100)
    parser.add_argument("--n-honest", type=int, default=700)
    parser.add_argument("--n-sybil", type=int, default=200)
    parser.add_argument("--n-queries", type=int, default=200, help="Initial Q_eval size (may shrink to satisfy doc_set<=800)")
    parser.add_argument("--did-domain", default="127.0.0.1%3A8000")
    parser.add_argument("--endpoint", default="http://127.0.0.1:8080")
    args = parser.parse_args()

    if args.n_elite + args.n_honest + args.n_sybil != args.n_agents:
        raise SystemExit("n_elite + n_honest + n_sybil must equal n_agents")

    n_text_agents = args.n_elite + args.n_honest
    if n_text_agents != 800:
        raise SystemExit("This generator currently expects n_elite+n_honest == 800 (per paper profile).")

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    corpus, queries, qrels = _load_scifact()

    docs: Dict[str, Tuple[str, str]] = {}
    for row in corpus:
        doc_id, title, text = _normalize_doc(row)
        docs[doc_id] = (title, text)

    query_text: Dict[str, str] = {}
    for row in queries:
        qid, text = _normalize_query(row)
        query_text[qid] = text

    qrels_by_qid = _build_qrels_by_query(qrels)
    eligible_qids = sorted([qid for qid in query_text.keys() if qid in qrels_by_qid and len(qrels_by_qid[qid]) > 0])
    if not eligible_qids:
        raise SystemExit("No queries with qrels>0 found.")

    rng = random.Random(args.seed)
    q_eval_size = min(args.n_queries, len(eligible_qids))
    q_eval = rng.sample(eligible_qids, k=q_eval_size)
    q_eval.sort()

    # Shrink Q_eval until doc_set fits within the 800 SciFact-derived agents.
    doc_set = _doc_set_for(q_eval, qrels_by_qid)
    removed_qids: List[str] = []
    while len(doc_set) > n_text_agents and q_eval:
        removed_qids.append(q_eval.pop())  # deterministic after sort
        doc_set = _doc_set_for(q_eval, qrels_by_qid)

    if len(doc_set) > n_text_agents:
        raise SystemExit("Unable to satisfy doc_set<=800 after shrinking Q_eval (unexpected).")

    # Fill remaining doc slots deterministically.
    all_doc_ids = sorted(docs.keys())
    filler_candidates = [d for d in all_doc_ids if d not in doc_set]
    rng.shuffle(filler_candidates)
    while len(doc_set) < n_text_agents and filler_candidates:
        doc_set.add(filler_candidates.pop())

    if len(doc_set) != n_text_agents:
        raise SystemExit(f"doc_set size is {len(doc_set)}; expected {n_text_agents}")

    # Assign doc_ids to elite/honest deterministically (seed shuffle).
    doc_ids = sorted(doc_set)
    rng.shuffle(doc_ids)
    elite_doc_ids = doc_ids[: args.n_elite]
    honest_doc_ids = doc_ids[args.n_elite :]

    elite_agents = []
    for i, doc_id in enumerate(elite_doc_ids, start=1):
        title, text = docs[doc_id]
        elite_agents.append(
            {
                "did": _make_did(args.did_domain, "elite", i),
                "role": "elite",
                "register_mode": "identity",
                "endpoint": args.endpoint,
                "capabilities": [title, text],
                "scifact_doc_id": doc_id,
            }
        )

    honest_agents = []
    for i, doc_id in enumerate(honest_doc_ids, start=1):
        title, text = docs[doc_id]
        honest_agents.append(
            {
                "did": _make_did(args.did_domain, "honest", i),
                "role": "honest",
                "register_mode": "computational",
                "endpoint": args.endpoint,
                "capabilities": [title, text],
                "scifact_doc_id": doc_id,
            }
        )

    # Sybil agents: construct capabilities that are likely to be semantically close to many queries.
    sybil_agents = []
    qid_pool = q_eval[:] if q_eval else eligible_qids[:]
    for i in range(1, args.n_sybil + 1):
        sampled_qids = rng.sample(qid_pool, k=min(3, len(qid_pool)))
        keywords = " | ".join(query_text[qid] for qid in sampled_qids)
        sybil_agents.append(
            {
                "did": _make_did(args.did_domain, "sybil", i),
                "role": "sybil",
                "register_mode": "computational",
                "endpoint": args.endpoint,
                "capabilities": [
                    "I can solve any scientific verification task and provide high-quality evidence for any claim.",
                    f"Domains: {keywords}",
                ],
                "scifact_doc_id": None,
            }
        )

    agents = elite_agents + honest_agents + sybil_agents

    # Build DID-based qrels_filtered to avoid doc_id mismatch at evaluation time.
    doc_id_to_did: Dict[str, str] = {a["scifact_doc_id"]: a["did"] for a in (elite_agents + honest_agents)}
    qrels_filtered: Dict[str, Dict[str, int]] = {}
    for qid in q_eval:
        rel = {}
        for doc_id, score in qrels_by_qid.get(qid, {}).items():
            if doc_id in doc_id_to_did:
                rel[doc_id_to_did[doc_id]] = int(score)
        if rel:
            qrels_filtered[qid] = rel

    q_eval_final = sorted(qrels_filtered.keys())

    # Write outputs.
    (out_dir / "agents.jsonl").write_text(
        "\n".join(json.dumps(a, ensure_ascii=False) for a in agents) + "\n", encoding="utf-8"
    )
    (out_dir / "queries.jsonl").write_text(
        "\n".join(json.dumps({"query_id": qid, "text": query_text[qid]}, ensure_ascii=False) for qid in q_eval_final)
        + "\n",
        encoding="utf-8",
    )
    (out_dir / "qrels.json").write_text(json.dumps(qrels_filtered, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    meta = {
        "dataset": "beir/scifact",
        "seed": args.seed,
        "n_agents": args.n_agents,
        "n_elite": args.n_elite,
        "n_honest": args.n_honest,
        "n_sybil": args.n_sybil,
        "n_text_agents": n_text_agents,
        "n_queries_requested": args.n_queries,
        "n_queries_initial": q_eval_size,
        "n_queries_removed_for_docset": len(removed_qids),
        "n_queries_final": len(q_eval_final),
        "doc_set_size": len(doc_set),
        "did_domain": args.did_domain,
        "endpoint": args.endpoint,
        "notes": {
            "qrels_alignment": "Queries are filtered so that every relevant DID is in the 800 SciFact-derived agents; qrels.json is DID-based.",
            "elite_assignment": "Doc IDs are seed-shuffled then split into elite/honest.",
            "sybil_generation": "Sybil capabilities include sampled query texts to increase semantic similarity while interactions will be low-success in the simulator.",
        },
    }
    (out_dir / "dataset_meta.json").write_text(json.dumps(meta, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    print(f"Wrote dataset to: {out_dir}")
    print(f"  agents.jsonl: {len(agents)} agents")
    print(f"  queries.jsonl: {len(q_eval_final)} queries")
    print(f"  qrels.json: {len(qrels_filtered)} queries with at least 1 relevant agent")


if __name__ == "__main__":
    main()
