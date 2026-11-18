"""사고 사례(docs/cases.md) 기반 순서도의 통합 테스트 데이터를 만든다.

testdata/scenarios/<SC_ID>/events.jsonl, expected.yaml 을 쓴다. 통합 테스트(AcceptanceIT)가 디렉터리를 자동으로 찾는다.
실행 (표준 라이브러리만 사용):
    docker run --rm -v "$PWD:/w" -w /w scenario_alert_java_python-server python3 -I scripts/gen_case_testdata.py

규칙
- IP 는 사설 대역(10.10.6~8.x)과 문서용 대역(192.0.2.x, 198.51.100.x, 203.0.113.x)만 쓴다. 실제 기관·IP 는 넣지 않는다.
- 시간은 기준 시각(정시)으로부터의 offset_ms. 통합 테스트 시간축은 110분이다.
- 1분 창 룰(WAF)은 분 경계 +2초부터 45초 안에, 10분 창 룰은 같은 10분 구간 안에 넣는다.
"""
from __future__ import annotations

import json
import random
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "testdata" / "scenarios"
ORG = "ORG001"
PRODUCTS = {"FIREWALL": "TestFW", "IPS": "TestIPS", "IDS": "TestIDS", "TMS": "TestTMS", "UTM": "TestUTM", "WAF": "TestWAF"}
HAS_DPORT = {"DDos", "FIREWALL", "IPS", "TMS"}
HAS_SPORT = {"DDos", "FIREWALL", "IPS"}
NO_COUNT = {"TMS", "VPN", "WAF"}
HAS_PAYLOAD = {"DDos", "IDS", "IPS", "TMS", "UTM", "WAF"}
MIN = 60_000


def ev(r: random.Random, dtp: str, t_ms: int, src: str, dst: str, *, dport=None, direction="", action="allow", method="",
       attack="", payload="", risk="low", uri="", url_method="") -> dict:
    # 운영 원본 키: _data_type, _asset_id(로그 수집원, 기관은 log_sources 매핑), 공통 필드 + fields(JSON, 값은 문자열).
    # 값이 없는 키는 생략한다 (운영처럼 NULL). count 는 fields 안에 있다.
    e = {"_data_type": dtp, "_asset_id": f"{ORG}_{dtp}_LOGSRC", "src_ip": src, "dst_ip": dst,
         "src_port": (30000 + r.randint(0, 35000)) if dtp in HAS_SPORT else None,
         "dst_port": dport if dtp in HAS_DPORT else None,
         "protocol": "tcp", "method": method, "attack": attack}
    fields = {"count": None if dtp in NO_COUNT else "1", "log": dtp.lower(), "product": PRODUCTS[dtp], "action": action,
              "direction": direction, "risk": risk, "uri": uri, "url_method": url_method,
              "payload": payload if dtp in HAS_PAYLOAD else ""}
    out = {k: v for k, v in e.items() if v not in (None, "")}
    out["fields"] = {k: v for k, v in fields.items() if v not in (None, "")}
    out["offset_ms"] = t_ms + 300 + r.randint(0, 2200)
    out["event_offset_ms"] = t_ms
    return out


def ext(r: random.Random, n: int, third: str = "198.51.100") -> list[str]:
    return [f"{third}.{i}" for i in r.sample(range(1, 254), n)]


# ---- 패턴 (SampleDataService 의 빌더와 같은 모양)
def waf_src_burst(r, t0, attacker, server, n):
    return [ev(r, "WAF", t0 + i * 45_000 // n, attacker, server, direction="inbound", action="block", method="WAF Rule 920350",
               attack=r.choice(["Error Handling", "SQL Injection", "Scanner Detection"]),
               uri=r.choice(["/index.php?id=1'", "/.env", "/wp-login.php"]), url_method="GET", payload="GET /index.php")
            for i in range(n)]


def killswitch(r, t0, host):
    return [ev(r, "TMS", t0, host, "203.0.113.80", dport=80, direction="outbound", action="alert",
               method="워너크라이 킬스위치 접속 시도 탐지",
               payload="GET / HTTP/1.1 Host: iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com", risk="high")]


def wannacry_internal(r, t0, host, dst):
    return [ev(r, "IDS", t0, host, dst, direction="internal", action="alert", method="HISC_WannaCry 랜섬웨어(PAT)",
               payload="SMB1 Trans2 SESSION_SETUP", risk="high")]


def smb_out(r, t0, host, n):
    dsts = ext(r, n // 2, "198.51.100") + ext(r, n - n // 2, "192.0.2")
    return [ev(r, r.choice(["FIREWALL", "FIREWALL", "IPS", "TMS"]), t0 + i * 7_000, host, d, dport=445, direction="outbound",
               action=r.choice(["deny", "block", "allow"]), method="SMB Connection Attempt") for i, d in enumerate(dsts)]


def ti_contact(r, t0, host):
    return [ev(r, "FIREWALL", t0, host, "203.0.113.66", dport=443, direction="outbound")]


def remote_scan(r, t0, host):
    dsts = ext(r, 6, "198.51.100") + ext(r, 6, "192.0.2")
    return [ev(r, "FIREWALL", t0 + i * 9_000, host, d, dport=r.choice([3389, 3389, 33890, 3390]), direction="outbound",
               action="deny") for i, d in enumerate(dsts)]


def p2p(r, t0, host, n):
    dsts = ext(r, 3)
    out = [ev(r, r.choice(["FIREWALL", "IPS", "TMS"]), t0 + i * 20_000, host, r.choice(dsts), dport=r.choice([6881, 6969]),
              direction="outbound", action=r.choice(["allow", "deny"])) for i in range(n - 1)]
    out.append(ev(r, "IDS", t0 + n * 20_000, host, dsts[0], direction="outbound", action="alert", method="Utorrent",
                  payload="BitTorrent protocol"))
    return out


def admin_port_multi(r, t0, server, srcs):
    out = []
    i = 0
    for a in ext(r, srcs):
        for _ in range(2):
            out.append(ev(r, r.choice(["FIREWALL", "IPS"]), t0 + i * 8_000, a, server, dport=22, direction="inbound",
                          action=r.choice(["deny", "allow"]), method="SSH Connection"))
            i += 1
    return out


def ssh_success(r, t0, server):
    return [ev(r, "IDS", t0, "198.51.100.31", server, direction="inbound", action="alert", method="SSH Login Successful",
               payload="Accepted password for root", risk="medium")]


# ---- PHP2Shell (CVE-2026-109618/109619). SampleDataService 의 php2shellExploit / webCmdOutput / webDownload 와 같은 모양
def php2shell_exploit(r, t0, attacker, server, scanner=False):
    if scanner:
        return [ev(r, "IPS", t0, attacker, server, dport=443, direction="inbound", action="detect",
                   method="HTTP POST Multipart Upload", attack="Suspicious File Upload", uri="/", url_method="POST",
                   payload='POST / HTTP/1.1 User-Agent: php2shell-scan/109618 Content-Type: multipart/form-data '
                           'name="PHP_SESSION_UPLOAD_PROGRESS" P2SFNAME P2SVALUE', risk="high")]
    return [ev(r, "WAF", t0, attacker, server, direction="inbound", action="detect",
               method="PHP2Shell Upload Progress Use-After-Free (CVE-2026-109619)", attack="Remote Code Execution",
               uri="/index.php", url_method="POST",
               payload='POST /index.php Content-Type: multipart/form-data name="PHP_SESSION_UPLOAD_PROGRESS" t[]=AAAA t[]=AAAA',
               risk="high")]


def web_cmd_output(r, t0, server, attacker, out="PHP2SHELL_CONFIRMED uid=33(www-data) gid=33(www-data) groups=33(www-data)"):
    return [ev(r, "IDS", t0, server, attacker, direction="outbound", action="alert", method="HTTP Response Command Output",
               payload="HTTP/1.1 200 OK " + out, risk="high")]


def web_download(r, t0, server, dst):
    return [ev(r, "IPS", t0, server, dst, dport=80, direction="outbound", action="allow", method="HTTP GET",
               payload="GET /nfs-setup HTTP/1.1 Host: dl.example User-Agent: Wget/1.21.4", risk="medium")]


def alert(sid, entity, sev, case, counterexample=False):
    a = {"source_id": sid, "entity": entity, "severity": sev, "case": case}
    if counterexample:  # 낮은 가지로 간 경우: 통합 테스트는 이것도 반례로 센다 (반례 3개 이상 규칙)
        a["counterexample"] = True
    return a


def write(sid: str, events: list[dict], expected: dict) -> None:
    d = OUT / sid
    d.mkdir(parents=True, exist_ok=True)
    events.sort(key=lambda e: e["offset_ms"])
    (d / "events.jsonl").write_text("".join(json.dumps(e, ensure_ascii=False) + "\n" for e in events), encoding="utf-8")
    (d / "expected.yaml").write_text(to_yaml(expected), encoding="utf-8")
    print(f"{sid}: {len(events)} events, {len(expected['alerts'])} alerts, {len(expected['no_alert'])} no_alert")


def to_yaml(v, ind=0) -> str:
    """기대값 파일용 최소 YAML (문자열은 따옴표로 감싼다)."""
    sp = "  " * ind
    if isinstance(v, dict):
        if not v:
            return "{}"
        lines = []
        for k, x in v.items():
            if isinstance(x, (dict, list)) and x:
                lines.append(f"{sp}{k}:\n{to_yaml(x, ind + 1)}")
            else:
                lines.append(f"{sp}{k}: {to_yaml(x, ind + 1)}")
        return "\n".join(lines)
    if isinstance(v, list):
        if not v:
            return "[]"
        lines = []
        for x in v:
            if isinstance(x, dict):
                body = to_yaml(x, ind + 1).lstrip()
                lines.append(f"{sp}- {body}")
            elif isinstance(x, list):
                lines.append(f"{sp}-\n{to_yaml(x, ind + 1)}")
            else:
                lines.append(f"{sp}- {to_yaml(x, ind + 1)}")
        return "\n".join(lines)
    if isinstance(v, str):
        return json.dumps(v, ensure_ascii=False)
    return json.dumps(v)


def main() -> None:
    r = random.Random(20261113)

    # ---- SC_WAF_ATTACKER: 대상 = 공격자(외부) IP. 서버 10.10.6.20 (webserver) 는 SR_WAF_BURST 히트만 생기고 경보는 없다.
    srv = "10.10.6.20"
    ev_ = []
    ev_ += waf_src_burst(r, 10 * MIN + 2_000, "203.0.113.50", srv, 1100)   # 1분 300 이상 + 10분 1,000 이상 → 높음
    ev_ += waf_src_burst(r, 12 * MIN + 2_000, "203.0.113.51", srv, 350)    # 1분 300 이상만 → 중간
    ev_ += waf_src_burst(r, 14 * MIN + 2_000, "203.0.113.52", srv, 250)    # 임계치 미달
    ev_ += waf_src_burst(r, 16 * MIN + 2_000, "203.0.113.53", srv, 400)    # 예외 리스트
    for m in range(3):                                                      # 3분에 걸쳐 400건 (분당 134) → 창 밖
        ev_ += waf_src_burst(r, (18 + m) * MIN + 2_000, "203.0.113.54", srv, 134)
    write("SC_WAF_ATTACKER", ev_, {
        "setup": {"assets": [[srv, ["webserver"]]], "list_items": [["false_positive_hosts", "203.0.113.53"]]},
        "alerts": [alert("SC_WAF_ATTACKER", "203.0.113.50", "high", "1분 1,100건 → 10분 1,000건 이상 지속"),
                   alert("SC_WAF_ATTACKER", "203.0.113.51", "medium", "1분 350건, 지속 아님", counterexample=True)],
        "no_alert": [{"entity": "203.0.113.52", "case": "임계치 바로 아래 (250건)"},
                     {"entity": "203.0.113.53", "case": "예외 리스트"},
                     {"entity": "203.0.113.54", "case": "허용 시간 밖 (3분에 걸쳐 402건, 분당 134건)"}],
        "hits": {"SR_WAF_SRC_BURST": ["203.0.113.50", "203.0.113.51"], "SR_WAF_SRC_SUSTAINED": ["203.0.113.50"]},
        "note": "사례: 해외 IP 에서 WAF 공격 999건/분 → 출발지 차단. 서버(10.10.6.20)는 SR_WAF_BURST 히트만 있고 외부 접속이 없어 경보 없음",
    })

    # ---- SC_WANNACRY_HOST
    ev_ = []
    ev_ += killswitch(r, 20 * MIN, "10.10.6.30")                       # 의료장비 → 높음
    ev_ += killswitch(r, 22 * MIN, "10.10.6.31")                       # + 외부 445 다수 → 긴급 (SC_SMB_WORM 도 긴급)
    ev_ += smb_out(r, 25 * MIN, "10.10.6.31", 25)
    ev_ += wannacry_internal(r, 30 * MIN, "10.10.6.32", "10.10.6.40")  # 출발지 일반 PC → 중간, 목적지 파일서버 → 높음
    ev_ += killswitch(r, 32 * MIN, "10.10.6.33")                       # 예외 리스트
    ev_ += wannacry_internal(r, 34 * MIN, "10.10.6.35", "203.0.113.90")  # 목적지가 외부 → DST 룰 미대상 (출발지는 경보)
    ev_ += [ev(r, r.choice(["FIREWALL", "IPS"]), 36 * MIN + i * 5_000, "10.10.6.36", "10.10.6.40", dport=445, direction="internal",
               method="SMB Connection Attempt") for i in range(3)]      # 일반 SMB 3건: 시그니처 없음 → 히트 없음
    write("SC_WANNACRY_HOST", ev_, {
        "setup": {"assets": [["10.10.6.30", ["legacy_os", "medical_device"]], ["10.10.6.40", ["fileserver"]]],
                  "list_items": [["false_positive_hosts", "10.10.6.33"]]},
        "alerts": [alert("SC_WANNACRY_HOST", "10.10.6.30", "high", "킬스위치 접속, 의료장비 자산"),
                   alert("SR_WANNACRY_SIG", "10.10.6.30", "high", "단독 경보"),
                   alert("SC_WANNACRY_HOST", "10.10.6.31", "critical", "킬스위치 접속 + 외부 445 다수 접근"),
                   alert("SC_SMB_WORM", "10.10.6.31", "critical", "외부 445 다수 + WannaCry 확인"),
                   alert("SR_WANNACRY_SIG", "10.10.6.31", "high", "단독 경보"),
                   alert("SC_WANNACRY_HOST", "10.10.6.32", "medium", "내부 시그니처, 출발지 일반 PC", counterexample=True),
                   alert("SR_WANNACRY_SIG", "10.10.6.32", "high", "단독 경보"),
                   alert("SC_WANNACRY_HOST", "10.10.6.40", "high", "내부 시그니처의 목적지 = 파일서버"),
                   alert("SC_WANNACRY_HOST", "10.10.6.35", "medium", "외부 목적지 시그니처, 출발지 일반 PC", counterexample=True),
                   alert("SR_WANNACRY_SIG", "10.10.6.35", "high", "단독 경보")],
        "no_alert": [{"entity": "10.10.6.33", "case": "예외 리스트"},
                     {"entity": "203.0.113.90", "case": "목적지가 외부 (목적지 기준 룰은 내부 목적지만)"},
                     {"entity": "10.10.6.36", "case": "시그니처 없는 일반 SMB 통신 3건"}],
        "hits": {"SR_WANNACRY_SIG": ["10.10.6.30", "10.10.6.31", "10.10.6.32", "10.10.6.35"],
                 "SR_WANNACRY_SIG_DST": ["10.10.6.40"], "SR_SMB_OUT_FANOUT": ["10.10.6.31"]},
        "note": "사례: 킬스위치 접속 → 감염 확인 / 내부 IP → 파일서버 WannaCry 시그니처",
    })

    # ---- SC_TI_CONTACT
    ev_ = []
    ev_ += ti_contact(r, 20 * MIN, "10.10.7.10")
    ev_ += remote_scan(r, 21 * MIN, "10.10.7.10")       # + 원격포트 스캔 → 높음 (SC_REMOTE_SCAN_OUT 높음도)
    ev_ += ti_contact(r, 24 * MIN, "10.10.7.11")        # 레거시 → 중간
    ev_ += ti_contact(r, 26 * MIN, "10.10.7.12")        # 일반 → 낮음
    ev_ += ti_contact(r, 28 * MIN, "10.10.7.13")        # 예외 리스트
    ev_ += [ev(r, "FIREWALL", 29 * MIN, "10.10.7.15", "203.0.113.99", dport=443, direction="outbound")]  # 리스트에 없는 IP
    write("SC_TI_CONTACT", ev_, {
        "setup": {"assets": [["10.10.7.11", ["legacy_os"]]], "list_items": [["false_positive_hosts", "10.10.7.13"]]},
        "alerts": [alert("SC_TI_CONTACT", "10.10.7.10", "high", "유해 IP 통신 + 외부 원격포트 다수 접근"),
                   alert("SC_REMOTE_SCAN_OUT", "10.10.7.10", "high", "외부 원격포트 다수 접근 (일반 자산)"),
                   alert("SC_TI_CONTACT", "10.10.7.11", "medium", "유해 IP 통신만, 레거시 자산", counterexample=True),
                   alert("SC_TI_CONTACT", "10.10.7.12", "low", "유해 IP 통신만, 일반 자산", counterexample=True)],
        "no_alert": [{"entity": "10.10.7.13", "case": "예외 리스트"},
                     {"entity": "10.10.7.15", "case": "유해 IP 리스트에 없는 외부 IP"}],
        "hits": {"SR_TI_HIT": ["10.10.7.10", "10.10.7.11", "10.10.7.12"], "SR_REMOTE_PORT_FANOUT": ["10.10.7.10"]},
        "note": "사례: C-TAS 유해 IP 통신 이력 → 445 지속 통신 → 감염 확인 (Windows 7 PC 다수)",
    })

    # ---- SC_P2P_USAGE
    ev_ = []
    ev_ += p2p(r, 30 * MIN, "10.10.7.20", 8)
    ev_ += ti_contact(r, 35 * MIN, "10.10.7.20")        # + 유해 IP → 높음 (SC_TI_CONTACT 낮음도)
    ev_ += p2p(r, 32 * MIN, "10.10.7.21", 6)            # → 낮음
    ev_ += p2p(r, 34 * MIN, "10.10.7.22", 3)            # 임계치 미달
    ev_ += p2p(r, 36 * MIN, "10.10.7.23", 8)            # 예외 리스트
    ev_ += [ev(r, "FIREWALL", 38 * MIN + i * 10_000, "198.51.100.9", "10.10.7.24", dport=6881, direction="inbound", action="deny")
            for i in range(8)]                          # 외부에서 들어오는 6881: 아웃바운드 조건 불충족
    write("SC_P2P_USAGE", ev_, {
        "setup": {"assets": [], "list_items": [["false_positive_hosts", "10.10.7.23"]]},
        "alerts": [alert("SC_P2P_USAGE", "10.10.7.20", "high", "토렌트 + 유해 IP 통신"),
                   alert("SC_TI_CONTACT", "10.10.7.20", "low", "유해 IP 통신만 (일반 자산)"),
                   alert("SC_P2P_USAGE", "10.10.7.21", "low", "토렌트 6건", counterexample=True)],
        "no_alert": [{"entity": "10.10.7.22", "case": "임계치 바로 아래 (3건)"}, {"entity": "10.10.7.23", "case": "예외 리스트"},
                     {"entity": "10.10.7.24", "case": "인바운드 6881 (아웃바운드 조건 불충족)"}],
        "hits": {"SR_P2P_PORTS": ["10.10.7.20", "10.10.7.21"], "SR_TI_HIT": ["10.10.7.20"]},
        "note": "사례: 토렌트 관련 다수 메소드 탐지 → 토렌트 프로그램 및 이용 내역 확인",
    })

    # ---- SC_EXPOSED_ADMIN_PORT (대상 = 내부 서버)
    ev_ = []
    ev_ += admin_port_multi(r, 40 * MIN, "10.10.8.10", 6)
    ev_ += ssh_success(r, 46 * MIN, "10.10.8.10")       # → 긴급
    ev_ += admin_port_multi(r, 42 * MIN, "10.10.8.11", 6)   # → 중간
    ev_ += admin_port_multi(r, 44 * MIN, "10.10.8.12", 3)   # 임계치 미달
    ev_ += admin_port_multi(r, 46 * MIN, "10.10.8.13", 6)   # 예외 리스트
    ev_ += [ev(r, "FIREWALL", 48 * MIN + i * 8_000, a, "10.10.8.14", dport=8080, direction="inbound")
            for i, a in enumerate(ext(r, 6))]               # 관리 포트가 아닌 8080
    write("SC_EXPOSED_ADMIN_PORT", ev_, {
        "setup": {"assets": [], "list_items": [["false_positive_hosts", "10.10.8.13"]]},
        "alerts": [alert("SC_EXPOSED_ADMIN_PORT", "10.10.8.10", "critical", "외부 출발지 6개 SSH 접근 + 로그인 성공"),
                   alert("SC_EXPOSED_ADMIN_PORT", "10.10.8.11", "medium", "외부 출발지 6개 SSH 접근", counterexample=True)],
        "no_alert": [{"entity": "10.10.8.12", "case": "임계치 바로 아래 (출발지 3개)"}, {"entity": "10.10.8.13", "case": "예외 리스트"},
                     {"entity": "10.10.8.14", "case": "관리 포트가 아닌 8080 으로 출발지 6개"}],
        "hits": {"SR_ADMIN_PORT_MULTI_SRC": ["10.10.8.10", "10.10.8.11"], "SR_AUTH_SUCCESS": ["10.10.8.10"]},
        "note": "사례: 국내외 IP 에서 TCP/22 접근 시도 → 외부 접근 가능 확인 → 로그인 시도 이력. 12건이라 대입 공격 룰(30건)은 안 걸린다",
    })

    # ---- SC_ORG_OUTBREAK (대상 = 기관 ORG001). 호스트별 임계치(20) 미만인 PC 5대가 같은 시간대에 외부 445 접근.
    #      기관 단위 히트의 대상은 "ORG001" 이라 hits 검사(IP 기준)에는 넣지 않는다. 통합 테스트 전체 데이터가 한 기관이므로
    #      다른 시나리오의 445·유해 IP 이벤트도 같은 집계에 들어간다.
    ev_ = []
    for i, h in enumerate(["10.10.9.10", "10.10.9.11", "10.10.9.12", "10.10.9.13", "10.10.9.14"]):
        ev_ += smb_out(r, (50 + i) * MIN, h, 5)
    ev_ += ti_contact(r, 56 * MIN, "10.10.9.10")
    ev_ += ti_contact(r, 57 * MIN, "10.10.9.11")
    write("SC_ORG_OUTBREAK", ev_, {
        "setup": {"assets": [], "list_items": []},
        "alerts": [alert("SC_ORG_OUTBREAK", "ORG001", "critical", "외부 445 접근 호스트 3대 이상 + 유해 IP 통신 호스트 2대 이상 (기관 단위)"),
                   alert("SC_TI_CONTACT", "10.10.9.10", "low", "유해 IP 통신만"),
                   alert("SC_TI_CONTACT", "10.10.9.11", "low", "유해 IP 통신만")],
        "no_alert": [{"entity": "10.10.9.12", "case": "호스트별로는 목적지 5개 (임계치 20 미만)"},
                     {"entity": "10.10.9.13", "case": "호스트별로는 목적지 5개"},
                     {"entity": "10.10.9.14", "case": "호스트별로는 목적지 5개"}],
        "hits": {"SR_TI_HIT": ["10.10.9.10", "10.10.9.11"]},
        "note": "사례: PC 4대 동시 감염 (호스트 단위 룰로는 각각 임계치 미달). 새 기능: 대상 유형 org (기관 단위 집계)",
    })

    # ---- SC_PHP2SHELL (대상 = 공격받은 내부 서버). 10.10.11.x 대역, 공격자 203.0.113.120~, 내려받기 서버 203.0.113.130
    ev_ = []
    ev_ += php2shell_exploit(r, 60 * MIN, "203.0.113.120", "10.10.11.10")              # + 3분 뒤 응답에 명령 실행 결과 → 긴급
    ev_ += web_cmd_output(r, 63 * MIN, "10.10.11.10", "203.0.113.120")
    ev_ += php2shell_exploit(r, 64 * MIN, "203.0.113.121", "10.10.11.11", scanner=True)  # 스캐너 + 6분 뒤 Wget 내려받기 → 긴급
    ev_ += web_download(r, 70 * MIN, "10.10.11.11", "203.0.113.130")
    ev_ += php2shell_exploit(r, 66 * MIN, "203.0.113.122", "10.10.11.12")              # 공격만, 웹서버 → 높음
    ev_ += php2shell_exploit(r, 68 * MIN, "203.0.113.123", "10.10.11.13")              # 공격만, 웹서버 아님 → 중간
    # 91분 뒤 내려받기 (허용 1시간 밖) → 높음. 10분 창 룰은 1분마다 미끄러지며 평가돼 히트 구간이 다음 10분까지 남으므로
    # (5분 공격 → 구간 [0,10), [10,20)) 실제 판정 범위는 최대 1시간 10분이다. 경계에서 충분히 떨어뜨린다.
    ev_ += php2shell_exploit(r, 5 * MIN, "203.0.113.124", "10.10.11.14")
    ev_ += web_download(r, 96 * MIN, "10.10.11.14", "203.0.113.130")
    ev_ += [ev(r, "WAF", 72 * MIN, "203.0.113.125", "10.10.11.15", direction="inbound", action="detect",
               method="File Upload Inspection", attack="File Upload", uri="/board/upload.php", url_method="POST",
               payload='POST /board/upload.php Content-Type: multipart/form-data name="attach" filename="report.pdf"')]  # 정상 업로드
    ev_ += php2shell_exploit(r, 74 * MIN, "203.0.113.126", "10.10.11.16")              # 예외 리스트
    ev_ += php2shell_exploit(r, 76 * MIN, "10.10.11.17", "198.51.100.240", scanner=True)  # 내부 → 외부 (목적지가 외부)
    ev_ += web_cmd_output(r, 78 * MIN, "10.10.11.18", "203.0.113.127",
                          out="uid=0(root) gid=0(root) groups=0(root)")                   # 명령 결과만, 앞선 공격 없음
    # v2 (ATT&CK 단계 연계): 단계가 차례로 보이면 경보의 기법이 누적된다 (순서 무관)
    ev_ += php2shell_exploit(r, 80 * MIN, "203.0.113.128", "10.10.11.19")              # 초기 침투 → 실행·정찰 → 도구 반입
    ev_ += web_cmd_output(r, 82 * MIN, "10.10.11.19", "203.0.113.128")
    ev_ += web_download(r, 88 * MIN, "10.10.11.19", "203.0.113.131")
    ev_ += php2shell_exploit(r, 84 * MIN, "203.0.113.129", "10.10.11.20")              # 초기 침투 → 도구 반입 → 실행·정찰
    ev_ += web_download(r, 86 * MIN, "10.10.11.20", "203.0.113.132")
    ev_ += web_cmd_output(r, 92 * MIN, "10.10.11.20", "203.0.113.129")
    ev_ += php2shell_exploit(r, 94 * MIN, "203.0.113.133", "10.10.11.21")              # uname -a 결과만 (T1082)
    ev_ += web_cmd_output(r, 96 * MIN, "10.10.11.21", "203.0.113.133",
                          out="Linux web01 5.15.0-91-generic #101-Ubuntu SMP Tue Nov 14 13:30:08 UTC 2023 x86_64 GNU/Linux")
    ev_ += php2shell_exploit(r, 98 * MIN, "203.0.113.134", "10.10.11.22")              # 내려받기 표지 없는 처음 보는 외부 접속 (C2)
    ev_ += [ev(r, "IPS", 100 * MIN, "10.10.11.22", "203.0.113.135", dport=443, direction="outbound", method="TLS Client Hello",
               payload="TLS ClientHello SNI=cdn-update.example")]
    write("SC_PHP2SHELL", ev_, {
        "setup": {"assets": [[h, ["webserver"]] for h in
                             ["10.10.11.10", "10.10.11.11", "10.10.11.12", "10.10.11.14", "10.10.11.15", "10.10.11.16",
                              "10.10.11.18", "10.10.11.19", "10.10.11.20", "10.10.11.21", "10.10.11.22"]],
                  "list_items": [["false_positive_hosts", "10.10.11.16"]]},
        "alerts": [alert("SC_PHP2SHELL", "10.10.11.10", "critical", "WAF PHP2Shell 탐지 + 3분 뒤 응답에 id 실행 결과"),
                   alert("SC_PHP2SHELL", "10.10.11.11", "critical", "php2shell-scan 요청 + 6분 뒤 웹서버의 Wget 내려받기"),
                   alert("SC_PHP2SHELL", "10.10.11.12", "high", "공격만, 웹서버", counterexample=True),
                   alert("SC_PHP2SHELL", "10.10.11.13", "medium", "공격만, 웹서버 아님", counterexample=True),
                   alert("SC_PHP2SHELL", "10.10.11.14", "high", "공격 91분 뒤 내려받기 (허용 1시간 밖)", counterexample=True),
                   alert("SC_PHP2SHELL", "10.10.11.19", "critical", "실행·정찰 뒤 도구 반입 (ATT&CK 단계 누적)"),
                   alert("SC_PHP2SHELL", "10.10.11.20", "critical", "도구 반입 뒤 실행·정찰 (순서 반대, 누적)"),
                   alert("SC_PHP2SHELL", "10.10.11.21", "critical", "uname -a 결과만 (T1082)"),
                   alert("SC_PHP2SHELL", "10.10.11.22", "critical", "처음 보는 외부 접속 (C2, T1071)")],
        "no_alert": [{"entity": "10.10.11.15", "case": "표지 없는 정상 멀티파트 업로드"},
                     {"entity": "10.10.11.16", "case": "예외 리스트"},
                     {"entity": "198.51.100.240", "case": "목적지가 외부 (공격 대상이 내부 서버가 아님)"},
                     {"entity": "10.10.11.17", "case": "외부로 공격 요청을 보낸 내부 출발지 (대상은 목적지)"},
                     {"entity": "10.10.11.18", "case": "명령 실행 결과만 있고 앞선 PHP2Shell 공격 없음"}],
        "hits": {"SR_PHP2SHELL_EXPLOIT": ["10.10.11.10", "10.10.11.11", "10.10.11.12", "10.10.11.13", "10.10.11.14",
                                          "10.10.11.19", "10.10.11.20", "10.10.11.21", "10.10.11.22"],
                 "SR_WEB_CMD_OUTPUT": ["10.10.11.10", "10.10.11.18", "10.10.11.19", "10.10.11.20", "10.10.11.21"],
                 "SR_WEB_SERVER_DOWNLOAD": ["10.10.11.11", "10.10.11.14", "10.10.11.19", "10.10.11.20"],
                 "SR_NEW_OUTBOUND": ["10.10.11.11", "10.10.11.14", "10.10.11.19", "10.10.11.20", "10.10.11.22"]},
        "note": "사례: PHP2Shell (CVE-2026-109618/109619, 2026-10). 업로드 진행 세션 멀티파트 공격 → 명령 실행 확인(PHP2SHELL_CONFIRMED, id) "
                "→ /tmp 로 Wget 내려받기(Mirai 계열 봇넷). 기존 SC_WEB_ATTACK_SUCCESS 는 WAF 300건/분 폭증이 전제라 요청 몇 건의 표적 공격을 놓친다",
    })


if __name__ == "__main__":
    main()
