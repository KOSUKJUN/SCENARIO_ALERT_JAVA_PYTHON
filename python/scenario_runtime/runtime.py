"""시나리오(순서도) 평가 런타임 — 생성된 시나리오별 Python 코드가 쓰는 노드 연산 모음.

Java(ScenarioCodeGenerator)가 순서도 하나마다 Python 모듈 하나를 만든다. 그 모듈의 evaluate(hits, asset_tags) 는
노드를 위상 순서대로 이 모듈의 연산(start/rule/check/asset/or_/and_/alert)으로 펼친 직선 코드다.
DB 접근이 없는 순수 함수이며, 실시간·백테스트·화면 시뮬레이션이 같은 생성 코드를 쓴다.

평가 방식 (Python 원본 server/scenario/evaluator.py 와 같다)
- 같은 (기관, 대상)의 히트만 넘겨받는다. 히트의 시각은 hit_bucket (수집 시각 기준 창의 시작)이다.
  hit_bucket 은 룰마다 자기 집계 창 단위로 잘려 있어(1분 룰과 10분 룰), 순서 판정은 히트를
  [hit_bucket, hit_bucket + 창) 구간으로 보고 한다: "앞 노드 이후" = 구간 끝이 앞 시각보다 뒤,
  "within 안" = 구간 시작이 앞 시각 + within 이전.
- 노드마다 "토큰"(성립 시각 + 지나온 경로)을 다음 노드로 넘긴다.
  · start  : 시각 없는 토큰 1개
  · rule   : 앞 토큰 시각 이후 within 안의 히트마다 새 토큰 (시작 바로 뒤면 모든 히트)
  · check  : 토큰 시각 앞뒤 lookaround 안에 참조 룰 히트가 하나라도 있으면 yes, 아니면 no (시각 유지)
  · asset  : 대상 자산 태그가 지정 태그 중 하나라도 있으면 yes (시각 유지)
  · or     : 들어온 토큰을 모두 통과
  · and    : 가지마다 토큰 하나씩 골라 within 안에 모두 있으면 성립, 성립 시각은 가장 늦은 가지
  · alert  : 토큰이 도달하면 경보 후보
- 한 번의 평가에서 여러 경보 노드에 도달하면 가장 높은 등급 하나를 고른다 (choose_alert).
"""
from __future__ import annotations

import itertools
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable, Sequence

MAX_TOKENS_PER_NODE = 64
MAX_AND_COMBINATIONS = 5000
SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}
KST = timezone(timedelta(hours=9))

HitKey = tuple[str, str, str, datetime]  # (rule_id, org_id, entity, hit_bucket)


def parse_time(v: Any) -> datetime | None:
    if v is None or v == "":
        return None
    if isinstance(v, datetime):
        t = v
    else:
        t = datetime.fromisoformat(str(v).replace("Z", "+00:00").replace(" ", "T"))
    if t.tzinfo is not None:
        t = t.astimezone(KST).replace(tzinfo=None)
    return t


def iso(t: datetime | None) -> str | None:
    if t is None:
        return None
    return t.replace(tzinfo=KST).isoformat(timespec="milliseconds")


@dataclass(frozen=True)
class Hit:
    rule_id: str
    rule_version: int
    org_id: str
    entity: str
    hit_bucket: datetime
    first_seen: datetime
    last_seen: datetime
    value: float
    threshold: float
    sample_event_ids: tuple[str, ...] = ()
    win_to: datetime | None = None
    window_sec: int = 0  # 룰의 집계 창. 히트는 [hit_bucket, hit_bucket + 창) 구간으로 본다

    @property
    def key(self) -> HitKey:
        return (self.rule_id, self.org_id, self.entity, self.hit_bucket)

    @property
    def end(self) -> datetime:
        return self.hit_bucket + timedelta(seconds=self.window_sec)

    @staticmethod
    def from_json(d: dict[str, Any]) -> "Hit":
        hb = parse_time(d["hit_bucket"])
        assert hb is not None
        return Hit(
            rule_id=str(d["rule_id"]), rule_version=int(d.get("rule_version") or 0), org_id=str(d["org_id"]),
            entity=str(d["entity"]), hit_bucket=hb,
            first_seen=parse_time(d.get("first_seen")) or hb, last_seen=parse_time(d.get("last_seen")) or hb,
            value=float(d.get("value") or 0), threshold=float(d.get("threshold") or 0),
            sample_event_ids=tuple(d.get("sample_event_ids") or ()), win_to=parse_time(d.get("win_to")),
            window_sec=int(d.get("window_sec") or 0),
        )


def hit_key_from_json(k: Sequence[Any]) -> HitKey:
    t = parse_time(k[3])
    assert t is not None
    return (str(k[0]), str(k[1]), str(k[2]), t)


@dataclass(frozen=True)
class Token:
    time: datetime | None
    path: tuple[dict[str, Any], ...]
    hits: frozenset[HitKey]


@dataclass
class Reached:
    node_id: str
    severity: str
    title: str
    playbook: str
    token: Token

    def path_json(self) -> list[dict[str, Any]]:
        return [*self.token.path, {"node": self.node_id, "type": "alert", "severity": self.severity}]


@dataclass
class EvalResult:
    reached: list[Reached] = field(default_factory=list)
    node_status: dict[str, dict[str, Any]] = field(default_factory=dict)


Tokens = list[Token]


def _hit_step(node_id: str, h: Hit) -> dict[str, Any]:
    return {
        "node": node_id, "type": "rule", "rule_id": h.rule_id, "at": iso(h.hit_bucket),
        "value": h.value, "threshold": h.threshold, "first_seen": iso(h.first_seen), "last_seen": iso(h.last_seen),
        "sample_event_ids": list(h.sample_event_ids),
    }


def _cap(tokens: Iterable[Token]) -> Tokens:
    uniq: dict[tuple[Any, ...], Token] = {}
    for t in tokens:
        k = (t.time, tuple(sorted(t.hits)), tuple(s.get("node") for s in t.path), tuple(s.get("result") for s in t.path))
        uniq.setdefault(k, t)
    out = sorted(uniq.values(), key=lambda t: (t.time or datetime.min))
    if len(out) > MAX_TOKENS_PER_NODE:
        half = MAX_TOKENS_PER_NODE // 2
        out = out[:half] + out[-half:]
    return out


def _merge_paths(tokens: Sequence[Token]) -> tuple[dict[str, Any], ...]:
    seen: set[tuple[Any, ...]] = set()
    merged: list[dict[str, Any]] = []
    for t in tokens:
        for s in t.path:
            k = (s.get("node"), s.get("at"), s.get("result"))
            if k not in seen:
                seen.add(k)
                merged.append(s)
    return tuple(merged)


class Evaluation:
    """한 (기관, 대상)에 대한 한 번의 평가. 생성 코드가 노드 순서대로 메서드를 부른다."""

    def __init__(self, hits: Iterable[Hit], asset_tags: Iterable[str]) -> None:
        self.by_rule: dict[str, list[Hit]] = {}
        for h in sorted(hits, key=lambda x: x.hit_bucket):
            self.by_rule.setdefault(h.rule_id, []).append(h)
        self.asset_tags = frozenset(asset_tags)
        self.out = EvalResult()

    # ------------------------------------------------------------ 노드
    def start(self, nid: str) -> Tokens:
        self.out.node_status[nid] = {"status": "reached"}
        return [Token(None, (), frozenset())]

    def rule(self, nid: str, rule_id: str, ins: Tokens, within: int | None) -> Tokens:
        cands = self.by_rule.get(rule_id, [])
        outs: Tokens = []
        for tok in ins:
            for h in cands:
                tm = h.hit_bucket
                if tok.time is not None:
                    if (h.end <= tok.time) if h.window_sec else (h.hit_bucket < tok.time):
                        continue
                    if within is not None and h.hit_bucket > tok.time + timedelta(seconds=within):
                        continue
                    tm = max(tok.time, h.hit_bucket)
                outs.append(Token(tm, (*tok.path, _hit_step(nid, h)), tok.hits | {h.key}))
        outs = _cap(outs)
        if outs:
            st: dict[str, Any] = {"status": "reached", "at": iso(min(o.time for o in outs if o.time)),
                                  "hits": len(cands)}
        elif not ins:
            st = {"status": "not_reached"}
        elif not cands:
            st = {"status": "blocked", "reason": "no_hit", "message": "히트 없음"}
        else:
            st = {"status": "blocked", "reason": "timeout", "message": "허용 시간 밖의 히트만 있음", "hits": len(cands)}
        self.out.node_status[nid] = st
        return outs

    def check(self, nid: str, rule_ids: Sequence[str], ins: Tokens, lookaround: int) -> tuple[Tokens, Tokens]:
        look = timedelta(seconds=lookaround)
        cands = [h for r in rule_ids for h in self.by_rule.get(r, [])]
        yes: Tokens = []
        no: Tokens = []
        for tok in ins:
            if tok.time is None:
                matched = cands
            else:
                matched = [h for h in cands
                           if h.hit_bucket <= tok.time + look and max(h.end, h.hit_bucket) >= tok.time - look]
            if matched:
                m = min(matched, key=lambda h: h.hit_bucket)
                step = {"node": nid, "type": "check", "result": "yes", "matched_rule_id": m.rule_id,
                        "at": iso(m.hit_bucket), "value": m.value, "sample_event_ids": list(m.sample_event_ids)}
                yes.append(Token(tok.time, (*tok.path, step), tok.hits | {h.key for h in matched}))
            else:
                no.append(Token(tok.time, (*tok.path, {"node": nid, "type": "check", "result": "no"}), tok.hits))
        st: dict[str, Any] = {"status": "not_reached"}
        if ins:
            st = {"status": "reached", "result": "yes" if yes else "no", "yes": len(yes), "no": len(no)}
        self.out.node_status[nid] = st
        return _cap(yes), _cap(no)

    def asset(self, nid: str, tags: Sequence[str], ins: Tokens) -> tuple[Tokens, Tokens]:
        matched_tags = sorted(set(tags) & self.asset_tags)
        branch = "yes" if matched_tags else "no"
        step = {"node": nid, "type": "asset", "result": branch, "matched_tags": matched_tags}
        outs = [Token(tok.time, (*tok.path, step), tok.hits) for tok in ins]
        st: dict[str, Any] = {"status": "not_reached"}
        if ins:
            st = {"status": "reached", "result": branch, "matched_tags": matched_tags}
        self.out.node_status[nid] = st
        return (outs, []) if branch == "yes" else ([], outs)

    def or_(self, nid: str, groups: Sequence[Tokens]) -> Tokens:
        outs = _cap(t for g in groups for t in g)
        st: dict[str, Any] = {"status": "not_reached"}
        if outs:
            st = {"status": "reached", "at": iso(min((o.time for o in outs if o.time), default=None))}
        self.out.node_status[nid] = st
        return outs

    def and_(self, nid: str, groups: Sequence[Tokens], sources: Sequence[str], within: int) -> Tokens:
        w = timedelta(seconds=within)
        outs: Tokens = []
        if all(groups):
            for combo in itertools.islice(itertools.product(*groups), MAX_AND_COMBINATIONS):
                times = [c.time for c in combo if c.time is not None]
                if times and max(times) - min(times) > w:
                    continue
                tm = max(times) if times else None
                hk: frozenset[HitKey] = frozenset().union(*(c.hits for c in combo))
                outs.append(Token(tm, _merge_paths(combo), hk))
        outs = _cap(outs)
        st: dict[str, Any] = {"status": "not_reached"}
        if outs:
            st = {"status": "reached", "at": iso(min((o.time for o in outs if o.time), default=None))}
        elif any(groups):
            missing = [s for s, g in zip(sources, groups, strict=True) if not g]
            st = {"status": "blocked", "reason": "timeout" if not missing else "branch_missing",
                  "message": "가지가 within 안에 모두 성립하지 않음" if not missing else
                  f"성립하지 않은 가지: {', '.join(missing)}"}
        self.out.node_status[nid] = st
        return outs

    def alert(self, nid: str, severity: str, title: str, playbook: str, groups: Sequence[Tokens]) -> None:
        ins = [t for g in groups for t in g]
        for tok in _cap(ins):
            self.out.reached.append(Reached(nid, severity, title, playbook, tok))
        self.out.node_status[nid] = {"status": "reached"} if ins else {"status": "not_reached"}

    def result(self) -> EvalResult:
        return self.out


# ------------------------------------------------------------ 결과 선택·표현
def choose_alert(result: EvalResult, new_hits: set[HitKey] | None = None) -> Reached | None:
    """가장 높은 등급의 경보 하나. new_hits 를 주면 그 히트를 하나 이상 쓴 경로만 고른다
    (이미 처리한 옛 히트만으로 같은 경보를 반복해 만들지 않도록)."""
    cands = result.reached
    if new_hits is not None:
        cands = [r for r in cands if r.token.hits & new_hits]
    if not cands:
        return None
    return max(cands, key=lambda r: (SEVERITY_RANK[r.severity],
                                     -r.token.time.timestamp() if r.token.time else 0))


def render_title(template: str, org_id: str, entity: str) -> str:
    return template.replace("{{entity}}", entity).replace("{{org_id}}", org_id)[:300]


def path_seen_range(r: Reached) -> tuple[datetime | None, datetime | None]:
    fs: list[datetime] = []
    ls: list[datetime] = []
    for s in r.token.path:
        if s.get("type") == "rule":
            a, b = parse_time(s.get("first_seen")), parse_time(s.get("last_seen"))
            if a:
                fs.append(a)
            if b:
                ls.append(b)
    return (min(fs) if fs else None, max(ls) if ls else None)


def chosen_json(chosen: Reached | None, org_id: str, entity: str) -> dict[str, Any] | None:
    if chosen is None:
        return None
    fs, ls = path_seen_range(chosen)
    return {
        "node": chosen.node_id, "severity": chosen.severity,
        "title": render_title(chosen.title, org_id, entity), "playbook": chosen.playbook,
        "path": chosen.path_json(), "time": iso(chosen.token.time), "first_seen": iso(fs), "last_seen": iso(ls),
        "hit_keys": [[k[0], k[1], k[2], iso(k[3])] for k in sorted(chosen.token.hits)],
    }
