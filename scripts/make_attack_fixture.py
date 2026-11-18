"""테스트용 작은 ATT&CK 번들을 만든다 (공식 STIX 번들에서 일부만 잘라 낸다. 구조는 공식 번들과 같다).

기본 룰·순서도가 참조하는 기법과 그 상위 기법, T1110 의 하위 기법, 두 버전 사이에 추가된 기법을 남기고,
그 기법에 걸린 완화·탐지 전략·그룹·소프트웨어를 기법마다 몇 개씩만 남긴다. 전술·매트릭스·컬렉션은 그대로 둔다.

실행 (표준 라이브러리만 사용, data/attack 에 공식 번들이 있어야 한다):
    docker run --rm --entrypoint python3 -v "$PWD:/w" -w /w scenario-engine-java/server:0.3.0 -I scripts/make_attack_fixture.py 19.2 20.1
출력: src/test/resources/attack/enterprise-attack-mini-<버전>.json
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "data" / "attack"
OUT = ROOT / "src" / "test" / "resources" / "attack"
PER_TECH = 2  # 기법마다 남길 완화·탐지 전략·그룹·소프트웨어 수
EXTRA = {"T1110.001", "T1110.002", "T1110.003", "T1110.004",  # 매트릭스의 하위 기법 표시
         "T1696", "T1697", "T1698", "T1699", "T1608.007", "T1696.001", "T1696.002", "T1685.007"}  # 19.2 → 20.1 추가


def builtin_ids() -> set[str]:
    ids: set[str] = set()
    for f in (ROOT / "rules" / "builtin" / "single").glob("*.yaml"):
        m = re.search(r"^attack:\s*\[(.*)\]\s*$", f.read_text(encoding="utf-8"), re.M)
        if m:
            ids |= {x.strip() for x in m.group(1).split(",") if x.strip()}
    for f in (ROOT / "rules" / "builtin" / "scenarios").glob("*.json"):
        for n in json.loads(f.read_text(encoding="utf-8"))["nodes"]:
            ids |= set(n.get("attack", []))
    return ids


def ext_id(o: dict) -> str | None:
    for r in o.get("external_references", []):
        if r.get("source_name", "").startswith("mitre-") and r.get("external_id"):
            return r["external_id"]
    return None


def make(version: str, wanted: set[str]) -> None:
    src = json.loads((SRC / f"enterprise-attack-{version}.json").read_text(encoding="utf-8"))
    objs = src["objects"]
    by_id = {o["id"]: o for o in objs}
    want = wanted | {i.split(".")[0] for i in wanted}
    keep = {o["id"] for o in objs if o["type"] == "attack-pattern" and ext_id(o) in want}
    keep |= {o["id"] for o in objs if o["type"] in ("x-mitre-tactic", "x-mitre-matrix", "x-mitre-collection")}
    rels = [o for o in objs if o["type"] == "relationship"]
    picked: dict[tuple[str, str], int] = {}
    for r in sorted(rels, key=lambda r: r["id"]):
        if r["target_ref"] not in keep or by_id.get(r["target_ref"], {}).get("type") != "attack-pattern":
            continue
        s = by_id.get(r["source_ref"])
        if not s or s["type"] not in ("course-of-action", "x-mitre-detection-strategy", "intrusion-set", "malware", "tool"):
            continue
        if s.get("revoked") or s.get("x_mitre_deprecated"):
            continue
        k = (r["target_ref"], s["type"])
        if s["id"] in keep or picked.get(k, 0) < PER_TECH:
            if s["id"] not in keep:
                picked[k] = picked.get(k, 0) + 1
            keep.add(s["id"])
    out = []
    for o in objs:
        if o["id"] in keep:
            o = dict(o)
            if o["type"] == "x-mitre-collection":
                o.pop("x_mitre_contents", None)
            # 크기 줄이기: 출처 목록은 ATT&CK ID 만 남기고, 기법 외에는 설명도 줄인다
            if o["type"] != "attack-pattern" and len(o.get("description", "")) > 300:
                o["description"] = o["description"][:300] + "…"
            if "external_references" in o:
                o["external_references"] = [r for r in o.get("external_references", [])
                                             if r.get("source_name", "").startswith("mitre-")]
            out.append(o)
    for r in rels:
        if r["source_ref"] in keep and r["target_ref"] in keep and by_id[r["target_ref"]]["type"] == "attack-pattern":
            r = {k: r[k] for k in ("type", "spec_version", "id", "relationship_type", "source_ref", "target_ref",
                                   "description", "modified") if k in r}
            if len(r.get("description", "")) > 120:
                r["description"] = r["description"][:120] + "…"
            out.append(r)
    OUT.mkdir(parents=True, exist_ok=True)
    dst = OUT / f"enterprise-attack-mini-{version}.json"
    dst.write_text(json.dumps({"type": "bundle", "id": src["id"], "objects": out}, ensure_ascii=False, separators=(",", ":")) + "\n",
                   encoding="utf-8")
    kinds: dict[str, int] = {}
    for o in out:
        kinds[o["type"]] = kinds.get(o["type"], 0) + 1
    print(dst.name, dst.stat().st_size, kinds)


def main() -> None:
    wanted = builtin_ids() | EXTRA
    for v in sys.argv[1:] or ["20.1"]:
        make(v, wanted)


if __name__ == "__main__":
    main()
