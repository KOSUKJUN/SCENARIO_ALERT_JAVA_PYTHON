"""테스트용 작은 D3FEND 릴리스를 만든다 (공식 릴리스에서 일부만 잘라 낸다. 구조는 공식 파일과 같다).

d3fend.json: 온톨로지 노드, 전술, 방어 기법(D3-xxx) 전부, ATT&CK 완화(M) 노드를 남긴다. 기법의 정의·설명은 짧게 자르고
            아티팩트·참고문헌 같은 나머지 노드는 버린다 (상위 기법·전술 관계는 그대로).
d3fend-full-mappings.csv: 기본 룰·순서도가 참조하는 ATT&CK 기법(과 상위 기법)의 행만, (방어 기법, ATT&CK 기법) 쌍마다 한 행만 남기고
            IRI 열은 버린다 (서버는 이름 열과 framework_root_iri 만 쓴다).

실행 (표준 라이브러리만 사용, data/d3fend/<버전>/ 에 공식 파일이 있어야 한다):
    docker run --rm --entrypoint python3 -v "$PWD:/w" -w /w scenario-engine-java/server:0.3.0 -I scripts/make_d3fend_fixture.py 1.5.0 1.6.0
출력: src/test/resources/d3fend/<버전>/d3fend.json, d3fend-full-mappings.csv
"""
from __future__ import annotations

import csv
import io
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "data" / "d3fend"
OUT = ROOT / "src" / "test" / "resources" / "d3fend"
KEEP_KEYS = {"@id", "@type", "rdfs:label", "d3f:d3fend-id", "d3f:definition", "d3f:kb-article", "d3f:synonym",
             "rdfs:subClassOf", "d3f:enables", "d3f:display-order", "d3f:related", "owl:versionInfo", "d3f:release-date",
             "dcterms:title", "dcterms:license"}
KEEP_COLS = ["query_def_tech_label", "top_def_tech_label", "def_tactic_label", "def_tech_label", "def_artifact_rel_label",
             "def_artifact_label", "off_artifact_label", "off_artifact_rel_label", "off_tech_label", "off_tech_id",
             "framework_root_iri", "off_tech_parent_label", "off_tactic_label"]


def builtin_ids() -> set[str]:
    ids: set[str] = set()
    for f in (ROOT / "rules" / "builtin" / "single").glob("*.yaml"):
        m = re.search(r"^attack:\s*\[(.*)\]\s*$", f.read_text(encoding="utf-8"), re.M)
        if m:
            ids |= {x.strip() for x in m.group(1).split(",") if x.strip()}
    for f in (ROOT / "rules" / "builtin" / "scenarios").glob("*.json"):
        for n in json.loads(f.read_text(encoding="utf-8"))["nodes"]:
            ids |= set(n.get("attack", []))
    return ids | {i.split(".")[0] for i in ids}


def cut(s, n):
    return s if not isinstance(s, str) or len(s) <= n else s[:n].rstrip() + " …"


def ontology(src: Path, dst: Path) -> None:
    doc = json.loads(src.read_text(encoding="utf-8"))
    graph = doc["@graph"]
    by_id = {n.get("@id"): n for n in graph}
    tech_ids = {i for i, n in by_id.items() if str(n.get("d3f:d3fend-id", "")).startswith("D3-")}
    out = []
    for n in graph:
        types = n.get("@type", [])
        types = types if isinstance(types, list) else [types]
        i = n.get("@id", "")
        keep = ("owl:Ontology" in types or "d3f:DefensiveTactic" in types or i in tech_ids
                or re.fullmatch(r"d3f:M\d{4}", i or ""))
        if not keep:
            continue
        m = {k: v for k, v in n.items() if k in KEEP_KEYS}
        if "d3f:definition" in m:
            m["d3f:definition"] = cut(m["d3f:definition"], 300)
        if "d3f:kb-article" in m:
            m["d3f:kb-article"] = cut(m["d3f:kb-article"], 400)
        if "rdfs:subClassOf" in m:
            sc = m["rdfs:subClassOf"] if isinstance(m["rdfs:subClassOf"], list) else [m["rdfs:subClassOf"]]
            m["rdfs:subClassOf"] = [x for x in sc if isinstance(x, dict) and not str(x.get("@id", "")).startswith("_:")]
        out.append(m)
    dst.write_text(json.dumps({"@context": doc.get("@context", {}), "@graph": out}, ensure_ascii=False, indent=0) + "\n",
                   encoding="utf-8")


def mappings(src: Path, dst: Path, ids: set[str]) -> None:
    seen: set[tuple[str, str]] = set()
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(KEEP_COLS)
    with src.open(encoding="utf-8", newline="") as f:
        for r in csv.DictReader(f):
            key = (r["query_def_tech_label"], r["off_tech_id"])
            if r["off_tech_id"] not in ids or "ATTACKEnterprise" not in r["framework_root_iri"] or key in seen:
                continue
            seen.add(key)
            w.writerow([r[c] for c in KEEP_COLS])
    dst.write_text(buf.getvalue(), encoding="utf-8")
    print(dst, len(seen), "pairs")


def main(versions: list[str]) -> None:
    ids = builtin_ids()
    for v in versions:
        o = OUT / v
        o.mkdir(parents=True, exist_ok=True)
        ontology(SRC / v / "d3fend.json", o / "d3fend.json")
        mappings(SRC / v / "d3fend-full-mappings.csv", o / "d3fend-full-mappings.csv", ids)


if __name__ == "__main__":
    main(sys.argv[1:] or ["1.5.0", "1.6.0"])
