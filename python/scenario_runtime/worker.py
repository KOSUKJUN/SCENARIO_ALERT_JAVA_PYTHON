"""시나리오 평가 상주 프로세스. Java(PythonScenarioEngine)가 띄우고 표준 입출력 JSON 한 줄씩 주고받는다.

실행: python3 -I -B -u python/scenario_runtime/worker.py   (-I: 환경 변수·사용자 site 를 보지 않는 격리 모드, -B: .pyc 를 쓰지 않음)

요청 (한 줄)
  {"id": 1, "op": "ping"}
  {"id": 2, "op": "evaluate", "module": "/app/data/scenarios/SC_SMB_WORM/v3.py", "sha256": "...",
   "cases": [{"org_id": "ORG001", "entity": "10.0.0.1", "hits": [...], "asset_tags": [...],
              "new_hit_keys": [[rule_id, org_id, entity, hit_bucket], ...] | null}]}
  {"id": 3, "op": "describe", "module": "...", "sha256": "..."}
응답 (한 줄)
  {"id": 2, "ok": true, "results": [{"node_status": {...}, "reached_alerts": [...], "chosen": {...} | null}]}
  {"id": 2, "ok": false, "error": "..."}

모듈은 (경로, sha256) 으로 캐시한다. 파일 내용의 sha256 이 요청과 다르면 거부한다 (Java 가 다시 만든다).
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
import traceback
from pathlib import Path
from types import ModuleType
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scenario_runtime.runtime import Hit, choose_alert, chosen_json, hit_key_from_json  # noqa: E402

PROTOCOL = 1
_cache: dict[tuple[str, str], ModuleType] = {}


def load_module(path: str, sha256: str) -> ModuleType:
    key = (path, sha256)
    mod = _cache.get(key)
    if mod is not None:
        return mod
    data = Path(path).read_bytes()
    actual = hashlib.sha256(data).hexdigest()
    if sha256 and actual != sha256:
        raise ValueError(f"코드 해시가 다릅니다: {path} (기대 {sha256[:12]}, 실제 {actual[:12]})")
    name = "scenario_gen_" + actual[:16]
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"모듈을 읽을 수 없습니다: {path}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    if getattr(mod, "PROTOCOL", None) != PROTOCOL or not callable(getattr(mod, "evaluate", None)):
        raise ImportError(f"생성 코드 형식이 아닙니다: {path}")
    if len(_cache) > 512:
        _cache.clear()
    _cache[key] = mod
    return mod


def evaluate_case(mod: ModuleType, case: dict[str, Any]) -> dict[str, Any]:
    hits = [Hit.from_json(h) for h in case.get("hits") or []]
    tags = set(case.get("asset_tags") or [])
    res = mod.evaluate(hits, tags)
    nk = case.get("new_hit_keys")
    new_keys = None if nk is None else {hit_key_from_json(k) for k in nk}
    chosen = choose_alert(res, new_keys)
    return {
        "node_status": res.node_status,
        "reached_alerts": sorted({r.node_id for r in res.reached}),
        "chosen": chosen_json(chosen, str(case.get("org_id", "")), str(case.get("entity", ""))),
    }


def handle(req: dict[str, Any]) -> dict[str, Any]:
    op = req.get("op")
    if op == "ping":
        return {"ok": True, "protocol": PROTOCOL, "python": sys.version.split()[0]}
    mod = load_module(str(req["module"]), str(req.get("sha256") or ""))
    if op == "describe":
        return {"ok": True, "scenario_id": mod.SCENARIO_ID, "version": mod.VERSION, "rule_ids": list(mod.RULE_IDS)}
    if op == "evaluate":
        return {"ok": True, "results": [evaluate_case(mod, c) for c in req.get("cases") or []]}
    raise ValueError(f"알 수 없는 op: {op!r}")


def main() -> None:
    for s in (sys.stdin, sys.stdout, sys.stderr):
        s.reconfigure(encoding="utf-8")  # type: ignore[union-attr]
    out = sys.stdout
    sys.stdout = sys.stderr  # 생성 코드의 print 가 응답 줄을 깨지 않도록
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        rid: Any = None
        try:
            req = json.loads(line)
            rid = req.get("id")
            resp = handle(req)
        except Exception as e:  # noqa: BLE001 - 오류는 응답으로 돌려준다
            traceback.print_exc(file=sys.stderr)
            resp = {"ok": False, "error": f"{type(e).__name__}: {e}"}
        resp["id"] = rid
        out.write(json.dumps(resp, ensure_ascii=False, default=str) + "\n")
        out.flush()


if __name__ == "__main__":
    main()
