"""scenario_runtime 단위 테스트 (표준 라이브러리 unittest 만 쓴다).

실행: python3 -I -m unittest discover -s python/tests -t python -v
생성 코드 전체의 기대 결과는 Java 쪽 ScenarioEvaluationTest 가 실제 생성 코드로 확인한다.
여기서는 런타임 연산과 worker 프로토콜(모듈 캐시, 해시 검사, 오류 응답)을 본다.
"""
from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import tempfile
import textwrap
import unittest
from datetime import datetime, timedelta
from pathlib import Path

from scenario_runtime import runtime as rt
from scenario_runtime import worker

T0 = datetime(2026, 11, 12, 10, 0, 0)
WORKER = Path(worker.__file__).resolve()

# Java ScenarioCodeGenerator 가 만드는 것과 같은 모양의 모듈 (시작 → 룰 → 자산 마름모 → 경보 2개)
SAMPLE = textwrap.dedent('''\
    from scenario_runtime import runtime as rt

    PROTOCOL = 1
    GENERATOR = "test"
    SCENARIO_ID = "SC_SAMPLE"
    VERSION = 1
    RULE_IDS = ("SR_A",)


    def evaluate(hits, asset_tags):
        ev = rt.Evaluation(hits, asset_tags)
        t0_n0 = ev.start("n0")
        t1_n1 = ev.rule("n1", "SR_A", t0_n0, within=None)
        t2_n2_yes, t2_n2_no = ev.asset("n2", ("legacy_os",), t1_n1)
        ev.alert("a1", "critical", "고위험 {{entity}}", "격리", (t2_n2_yes,))
        ev.alert("a2", "high", "의심 {{entity}}", "", (t2_n2_no,))
        return ev.result()
    ''')


def hit(rule: str, minutes: float, window: int = 600) -> rt.Hit:
    t = T0 + timedelta(minutes=minutes)
    return rt.Hit(rule, 1, "ORG001", "10.0.0.1", t, t, t, 10.0, 5.0, ("e1",), t, window)


class RuntimeTest(unittest.TestCase):
    def test_rule_within_and_order(self) -> None:
        ev = rt.Evaluation([hit("SR_A", 0), hit("SR_B", 20)], [])
        a = ev.rule("n1", "SR_A", ev.start("n0"), within=None)
        b = ev.rule("n2", "SR_B", a, within=1800)
        self.assertEqual(len(b), 1)
        ev = rt.Evaluation([hit("SR_A", 0), hit("SR_B", 45)], [])
        b = ev.rule("n2", "SR_B", ev.rule("n1", "SR_A", ev.start("n0"), within=None), within=1800)
        self.assertEqual(b, [])
        self.assertEqual(ev.out.node_status["n2"]["reason"], "timeout")

    def test_check_lookaround_both_sides(self) -> None:
        ev = rt.Evaluation([hit("SR_A", 60), hit("SR_C", 0)], [])
        yes, no = ev.check("c", ["SR_C"], ev.rule("n1", "SR_A", ev.start("n0"), within=None), lookaround=3600)
        self.assertEqual((len(yes), len(no)), (1, 0))

    def test_and_branch_missing(self) -> None:
        ev = rt.Evaluation([hit("SR_A", 0)], [])
        s = ev.start("n0")
        a = ev.rule("n1", "SR_A", s, within=None)
        b = ev.rule("n2", "SR_B", s, within=None)
        self.assertEqual(ev.and_("j", [a, b], ["n1", "n2"], within=3600), [])
        self.assertEqual(ev.out.node_status["j"]["reason"], "branch_missing")

    def test_choose_highest_and_new_hits(self) -> None:
        ns: dict = {}
        exec(compile(SAMPLE, "sample", "exec"), ns)  # noqa: S102 - 테스트용 고정 코드
        h = hit("SR_A", 0)
        res = ns["evaluate"]([h], {"legacy_os"})
        chosen = rt.choose_alert(res)
        assert chosen is not None
        self.assertEqual(chosen.severity, "critical")
        self.assertIsNone(rt.choose_alert(res, {hit("SR_Z", 0).key}))
        j = rt.chosen_json(chosen, "ORG001", "10.0.0.1")
        assert j is not None
        self.assertEqual(j["title"], "고위험 10.0.0.1")
        self.assertEqual(j["path"][-1], {"node": "a1", "type": "alert", "severity": "critical"})


class WorkerProtocolTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.mod = Path(self.tmp.name) / "v1.py"
        self.mod.write_text(SAMPLE, encoding="utf-8")
        self.sha = hashlib.sha256(SAMPLE.encode("utf-8")).hexdigest()

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def run_worker(self, *reqs: dict) -> list[dict]:
        p = subprocess.run([sys.executable, "-I", "-u", str(WORKER)], input="\n".join(json.dumps(r) for r in reqs) + "\n",
                           capture_output=True, text=True, encoding="utf-8", timeout=30, check=True)
        return [json.loads(line) for line in p.stdout.splitlines() if line.strip()]

    def test_evaluate_batch(self) -> None:
        case = {"org_id": "ORG001", "entity": "10.0.0.1", "asset_tags": [],
                "hits": [{"rule_id": "SR_A", "rule_version": 1, "org_id": "ORG001", "entity": "10.0.0.1",
                          "hit_bucket": "2026-11-12T10:00:00.000", "first_seen": "2026-11-12T10:00:01.000",
                          "last_seen": "2026-11-12T10:05:00.000", "value": 25, "threshold": 20,
                          "sample_event_ids": ["e1"], "win_to": "2026-11-12T10:10:00.000", "window_sec": 600}],
                "new_hit_keys": [["SR_A", "ORG001", "10.0.0.1", "2026-11-12T10:00:00.000"]]}
        tagged = dict(case, asset_tags=["legacy_os"])
        empty = dict(case, hits=[])
        out = self.run_worker({"id": 1, "op": "ping"},
                              {"id": 2, "op": "evaluate", "module": str(self.mod), "sha256": self.sha,
                               "cases": [case, tagged, empty]})
        self.assertTrue(out[0]["ok"])
        r = out[1]
        self.assertTrue(r["ok"], r)
        self.assertEqual(r["id"], 2)
        sev = [x["chosen"]["severity"] if x["chosen"] else None for x in r["results"]]
        self.assertEqual(sev, ["high", "critical", None])
        self.assertEqual(r["results"][0]["chosen"]["first_seen"], "2026-11-12T10:00:01.000+09:00")

    def test_hash_mismatch_rejected(self) -> None:
        out = self.run_worker({"id": 7, "op": "evaluate", "module": str(self.mod), "sha256": "0" * 64, "cases": []})
        self.assertFalse(out[0]["ok"])
        self.assertIn("해시", out[0]["error"])
        self.assertEqual(out[0]["id"], 7)

    def test_bad_request_keeps_worker_alive(self) -> None:
        out = self.run_worker({"id": 1, "op": "nope"}, {"id": 2, "op": "ping"})
        self.assertFalse(out[0]["ok"])
        self.assertTrue(out[1]["ok"])


if __name__ == "__main__":
    unittest.main()
