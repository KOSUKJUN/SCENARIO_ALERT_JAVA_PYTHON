# 사고 사례 → 단일룰·순서도 매핑

관제 보고서의 사고 사례 12건(웹해킹 1, 악성코드 6, 유해 IP 2, 네트워크침입 3)을 이 시스템으로 탐지할 수 있는지 대입한 결과다.
사례의 **행위 패턴만** 가져왔고, 기관명·담당자·실제 IP 는 어디에도 넣지 않았다. 테스트 데이터는 사설 대역(10.10.x.x)과
문서용 대역(192.0.2.x, 198.51.100.x, 203.0.113.x)만 쓴다.

원칙 (CLAUDE.md): 탐지명·포트·임계치는 코드가 아니라 **룰 정의와 리스트**에만 둔다. 사례에 나온 장비 탐지명은
`signature_map` 리스트에 "탐지명 → 분류"로 넣고, 룰은 분류(`signature_category`)만 본다.

## 1. 사례별 매핑

| # | 사례 (보고서 제목 요약) | 네트워크에서 보이는 행위 | 단일룰 | 순서도 | 기대 경보 |
|---|---|---|---|---|---|
| 1 | 웹해킹 — 해외 IP 에서 WAF 공격 300건 이상(999건/분), 출발지 차단 | WAF 공격 탐지가 한 출발지에서 1분 999건 | **SR_WAF_SRC_BURST** (신규, 출발지 기준 300/1분), **SR_WAF_SRC_SUSTAINED** (신규, 1,000/10분) | **SC_WAF_ATTACKER** (신규) | 지속이면 높음(차단 권고), 아니면 중간 |
| 2 | 악성코드 — 킬스위치 접근 시도 → WannaCry 감염 확인 (안구 검사 장비, Windows Embedded) | TMS 킬스위치 도메인 접속 1건 | SR_WANNACRY_SIG (기존, 단독 경보 높음) | **SC_WANNACRY_HOST** (신규) | SMB 전파 있으면 긴급 / 레거시·의료장비·파일서버면 높음 / 그 외 중간 |
| 3 | 유해 IP — C-TAS 유해 IP 접근 이력 → 해외 445 지속 통신 → WannaCry (Windows 7 PC 4대) | 유해 IP 통신 + 외부 445 다수 접근, 여러 PC 동시 | SR_TI_HIT, SR_SMB_OUT_FANOUT (기존), **SR_ORG_SMB_OUTBREAK**, **SR_ORG_TI_MULTI** (신규, 기관 단위) | SC_SMB_WORM (기존), **SC_TI_CONTACT**, **SC_ORG_OUTBREAK** (신규) | 호스트별 긴급 + 기관 단위 "동시다발 감염 의심" 긴급 |
| 4 | 네트워크침입 — SMTP 무차별 대입 → 인증 성공(235) → 메일 계정 탈취 | 인바운드 25/587 다수 + 페이로드 "235 Authentication successful" | SR_AUTH_BRUTEFORCE, SR_AUTH_SUCCESS (기존) | SC_BRUTEFORCE_SUCCESS (기존) | 높음 (기존 그대로 맞음) |
| 5 | 악성코드 — 채굴 풀 통신 → 암호화폐 채굴 감염 (XMRig, algo rx/0) | TMS/IPS 채굴 시그니처, 페이로드에 XMRig | SR_COINMINER, SR_COINMINER_REPEAT (기존) + signature_map 에 탐지명 추가 | SC_COINMINER (기존) | 중간 → 반복이면 높음 |
| 6 | 웹해킹 — 토렌트 다수 메소드 → 토렌트 프로그램·이용 내역 확인 (6969, 6881) | 외부 6969/6881 아웃바운드 다수 | **SR_P2P_PORTS** (신규) | **SC_P2P_USAGE** (신규) | 유해 IP·악성 징후 있으면 높음, 아니면 낮음(업무 외 프로그램 확인) |
| 7 | 악성코드 — 내부 IP 에서 해외 다수 IP 원격포트(3389/33890/3390) 접근 → mimikatz 확인 | 외부 원격포트 다수 접근 (7,579건), PC 2대 | SR_REMOTE_PORT_FANOUT (기존) | SC_REMOTE_SCAN_OUT (기존) | 레거시면 긴급, 아니면 높음 (기존 그대로 맞음) |
| 8 | 유해 IP — 블랙리스트 IP 445 접근 → WannaCry 확인 + 내부 445 통신 (Windows 7 진단검사 PC) | 유해 IP(445) 통신 + 외부 445 다수 + 내부 445 | SR_TI_HIT, SR_SMB_OUT_FANOUT (기존) | SC_SMB_WORM, **SC_TI_CONTACT** | 긴급 (SMB 웜) + 높음 (유해 IP + 전파 징후) |
| 9 | 악성코드 — 내부 IP → 내부 파일서버(EMR) WannaCry 시그니처 → 악성 의심 파일 확인 | IDS "HISC_WannaCry 랜섬웨어(PAT)" 내부 → 내부 | SR_WANNACRY_SIG (출발지), **SR_WANNACRY_SIG_DST** (신규, 목적지 기준) | **SC_WANNACRY_HOST** | 출발지 중간 + 단독 높음, 목적지(파일서버) 높음 |
| 10 | 악성코드 — 내부 사설 IP 대역 445 통신 시도 (SMB IPC$) → mssecsvc.exe (엘리베이터 LCD) | IDS "SMB IPC$ Share Unicode Access-1" 내부 | SR_SMB_SIG (기존) + signature_map 에 탐지명 추가 | SC_SMB_LATERAL (기존) | 높음 (파일서버가 아니면) |
| 11 | 네트워크침입 — 해외 IP 로 AnyDesk(TCP/6568) → 원격제어 프로그램·트로이목마 확인 | 6568 아웃바운드 (악성 징후는 호스트에서만 확인) | SR_REMOTE_TOOL (기존) | SC_REMOTE_TOOL_MALICIOUS (**v2**: 도구만 있어도 낮음 경보 추가) | 유해 IP·악성코드 동반이면 높음, 도구만이면 낮음(설치 경위 확인) |
| 12 | 네트워크침입 — 국내외 IP 에서 TCP/22 접근 시도 → 실제 접근 가능 → root 로그인 시도 이력 | 인바운드 22 로 다수 출발지 (595건), 로그인 성공 없음 | **SR_ADMIN_PORT_MULTI_SRC** (신규, 출발지 5개/10분) | **SC_EXPOSED_ADMIN_PORT** (신규) | 인증 성공 있으면 긴급, 아니면 중간(접근 제한 권고) |

굵은 글씨가 이번에 추가한 것이다. 신규 단일룰 7개, 신규 순서도 6개, 기존 순서도 수정 1개(SC_REMOTE_TOOL_MALICIOUS v2),
`signature_map` 리스트 항목 9개 추가.

## 2. 사례가 요구해서 추가한 기능

### 대상 유형 `org` (기관 단위 집계)

사례 3·7 은 "PC 여러 대가 같은 시간대에 같은 행위"를 한다. 호스트 단위 룰은 PC 한 대의 목적지 수(20개)를 세므로,
PC 4대가 각각 목적지 5개씩이면 아무 것도 잡지 못한다. 그래서 단일룰 `entity` 에 `{type: org, field: org_id}` 를 추가했다.

- 룰: `aggregate: {func: distinct_count, field: src_ip}` 로 "기관 안에서 그 행위를 한 호스트 수"를 센다. 히트·경보의 대상(entity)은 `ORG001` 같은 기관 ID 다.
- 순서도: `entity_type: org` 인 순서도는 org 대상 룰만 참조한다. 경보 제목에 `{{org_id}}` 를 쓴다.
- 바뀐 코드: `meta/Fields.ENTITY_TYPES` 한 곳. 검증기·컴파일러·화면(대상 유형 목록은 `/meta/fields` 에서 받음)은 그대로 동작한다.
- 한계: org 대상에는 자산 태그가 없어 순서도의 `asset` 노드는 항상 no 로 간다. 예외 리스트(IP 리스트)도 org 에는 의미가 없다.

### 목적지 기준 시그니처 룰

사례 9 는 "통신을 받은" 파일서버가 조사 대상이다. 룰 하나를 `entity.field: dst_ip` 로 두면(`SR_WANNACRY_SIG_DST`) 같은 이벤트가
출발지·목적지 양쪽 대상으로 평가된다. 새 기능은 아니고 기존 구조(`entity.field` 선택)를 쓴 것이다.

## 3. 테스트

- 통합 테스트 데이터: `testdata/scenarios/SC_*/` (6개 디렉터리 추가). `scripts/gen_case_testdata.py` 가 만든다.
  각 시나리오마다 경보 대상, 반례 3개 이상(임계치 바로 아래, 허용 시간 밖, 예외 리스트, 방향·포트 불일치 등), 히트 대상을 적어 두었고
  `AcceptanceIT` 가 실시간 → 서버 2대 따라잡기 → 백테스트 동일성까지 확인한다.
- 화면 "테스트 데이터" 주입 항목(`[사례] …` 로 시작, 15개)으로 실행 중인 서버에서 1~2분 안에 같은 경보를 볼 수 있다.
- 새 룰의 컴파일 스냅샷: `src/test/resources/snapshots/SR_*.sql`. Python 원본에 없는 룰이라 Java 컴파일러 출력을 검토해 고정했다
  (`SnapshotWriterTest`, `-Dsnapshots.write=true` 일 때만 빈 스냅샷을 쓴다).

## 4. 사례에서 네트워크로는 알 수 없는 것

보고서의 결론 상당수는 호스트 점검(CIDER·Syscheck 로그, 백신 결과)에서 나온다: mimikatz, mssecsvc.exe, rdpchh.xsl, 토렌트 다운로드 내역,
별도 인터넷 회선. 이 시스템은 네트워크 이벤트만 보므로 그 단계까지는 가지 못한다. 순서도의 playbook 에 "호스트 점검 로그 채증 요청"을
넣어 두는 것으로 대신했다. 호스트 점검 결과를 이벤트(예: data_tp `APT` 또는 별도 유형)로 받으면 `check` 노드 하나로 이어 붙일 수 있다.

## 5. 최신 공격: PHP2Shell (CVE-2026-109618 / CVE-2026-109619, 2026-10)

PHP 코어의 원격 코드 실행 취약점 2건(CVSS 4.0 9.2). 2026-10-21 패치(8.5.12 / 8.4.27 / 8.3.36 / 8.2.35), 2026-10-26 CISA KEV 등재.
CVE-2026-109619 는 업로드 진행 기능(`session.upload_progress`)의 use-after-free, CVE-2026-109618 은 메모리 부족(OOM) 처리 중 메모리 오염이다.
공개 분석(Akamai, Arctic Wolf, Unit 42)에서 네트워크로 보이는 것만 가져왔다.

| 단계 | 공개 분석의 관측 | 단일룰 | 리스트 |
|---|---|---|---|
| 공격 요청 | `PHP_SESSION_UPLOAD_PROGRESS` 필드 + `t[]` 패딩 멀티파트 POST, 스캐너 UA `php2shell-scan/…`, 표지 `P2SFNAME`/`P2SVALUE`, `sess_p2sopchain`, `system(base64_decode(…))` | **SR_PHP2SHELL_EXPLOIT** (대상 = 공격받은 내부 서버) | `php2shell_request_markers`, `signature_map` → `php2shell` |
| 실행 확인 | 응답에 `PHP2SHELL_CONFIRMED`, `id` 결과(`uid=…(…) gid=…`) | **SR_WEB_CMD_OUTPUT** (대상 = 응답한 내부 서버, 일반 룰) | `web_cmd_output_markers` |
| 2단계 내려받기 | `/tmp` 로 `wget` 내려받기 (Mirai 계열 봇넷) | **SR_WEB_SERVER_DOWNLOAD** (webserver 자산, 일반 룰), SR_NEW_OUTBOUND, SR_TI_HIT (기존) | `web_downloader_markers` |

순서도 **SC_PHP2SHELL** (대상 = 서버, 억제 6시간):

- 공격 뒤 1시간 안에 응답에 명령 실행 결과 → **긴급** "원격 코드 실행 성공"
- 공격 뒤 1시간 안에 외부 내려받기·처음 보는 외부 접속·유해 IP 통신 → **긴급** "공격 후 외부 내려받기·접속"
- 공격만: webserver 자산이면 **높음**(PHP 버전 확인·패치), 아니면 **중간**. 뒤에 후속 행위가 보이면 같은 경보가 긴급으로 올라간다.

기존 SC_WEB_ATTACK_SUCCESS 는 WAF 300건/분 폭증이 시작 조건이라, 요청 몇 건으로 끝나는 PHP2Shell 같은 표적 공격을 놓친다. 그 공백을 메운다.

주의
- `signature_map` 의 PHP2Shell 탐지명 3개는 **예시**다. 운영 장비(WAF/IPS)의 실제 탐지명을 같은 리스트에 추가해야 분류로 잡힌다.
  문자열 표지(`php2shell_request_markers`)는 탐지명과 상관없이 페이로드가 기록되는 장비에서 동작한다.
- `PHP_SESSION_UPLOAD_PROGRESS` 는 정상 업로드 진행 표시에도 쓰일 수 있다. 보안 장비가 탐지로 남긴 이벤트만 보므로 대부분 걸러지지만,
  오탐이면 대상 서버를 `false_positive_hosts` 에 넣는다.
- Arctic Wolf 는 PHP2Shell 이름을 단 요청 상당수가 실제 메모리 오염이 아니라 예전 세션 오염·역직렬화 기법이라고 했다. 이 순서도는 기법과 상관없이
  "공격 → 실행 확인 → 내려받기" 흐름을 보므로 둘 다 잡는다. 공격만 있는 경보(높음·중간)는 성공을 뜻하지 않는다.
- 10분 창 룰은 1분마다 평가돼 히트 구간이 다음 10분까지 남는다. 그래서 "1시간 안"의 실제 판정 범위는 최대 1시간 10분이다.

### v2: MITRE ATT&CK 단계 연계 (2026-11-17)

| ATT&CK 전술 | 기법 | 순서도 노드 | 경보 노드 |
|---|---|---|---|
| TA0001 초기 침투 | T1190 | n1 SR_PHP2SHELL_EXPLOIT | a3 높음 / a4 중간 (공격 시도) |
| TA0002 실행 · TA0007 정찰 | T1059.004, T1033(id), **T1082(uname -a, 신규)** | n2 SR_WEB_CMD_OUTPUT | a1 긴급 "실행·정찰" |
| TA0011 C2: 도구 반입 | T1105 | n3 SR_WEB_SERVER_DOWNLOAD | a2 긴급 "도구 반입" |
| TA0011 C2: 통신 | T1071 | n4 SR_NEW_OUTBOUND, n5 SR_TI_HIT | **a5 긴급 "C2 통신 의심" (v1 의 a2 에서 분리)** |
| TA0004 권한 상승 | T1068 (커널 취약점 연계, 공개 분석) | 네트워크로 볼 수 없음 | a1 대응 절차의 호스트 점검 |

- 경보 제목에 단계(`[초기 침투 → 실행·정찰]` 등), 경보 노드에 단계 기법, 대응 절차에 ATT&CK 완화(M1051, M1050, M1038, M1031, M1037, M1016)와
  탐지 전략(DET0080, DET0384, DET0060, DET0444)을 넣었다. DET0080(요청 → 후속 실행 → 외부 통신 상관)이 이 순서도와 같은 모양이다.
- **경보의 기법 누적**: v1 에서는 실행(긴급) 경보가 난 뒤 같은 서버의 도구 반입·C2(같은 긴급)가 보여도 억제되어 경보의 ATT&CK 이 첫 단계에 머물렀다
  (실서버에서 재현: T1190·T1059.004·T1033 만 남음). 이제 억제 시간 안에 같은 대상의 다음 단계가 보이면 기법을 더하고 사고처리 시스템에 다시 보낸다
  (등급·억제·경로는 그대로). 한 번의 평가에서 여러 결론이 함께 성립하면(따라잡기 등) 그 경보 노드들의 기법도 더한다.
- 경보 상세의 "지나온 경로"는 처음 성립한 결론의 경로다. 뒤에 관측된 단계는 ATT&CK 목록과 횟수로 보인다.

테스트: `testdata/scenarios/SC_PHP2SHELL/` (긴급 6, 높음 2, 중간 1, 경보 없음 5: 정상 업로드, 예외 리스트, 외부 목적지, 외부로 공격을 보낸 내부 출발지,
앞선 공격 없는 명령 결과). v2 에서 긴급 4건 추가: 단계 누적 2건(실행 → 반입, 반입 → 실행), uname 결과만, C2 가지.
통합 테스트가 각 경보의 ATT&CK 기법 집합까지 확인한다. 화면 "테스트 데이터"에 `[사례] PHP2Shell …` 3개.
