# 시나리오 기반 탐지 엔진 설계안

> 변경 이력 (2026-11-13): 관리 화면을 React + React Flow 대신 Vue 3 + Vue Flow 로 구현한다 (요청에 따른 변경). 서버와 주고받는 그래프 JSON(5장)과 화면 구성(10장)은 그대로다. 원본 설계안 PDF 는 바꾸지 않았다.


(원본: 설계안 PDF에서 추출)

시나리오  기반  탐지  엔진  설계안  (Claude Code 구
현용 )
 Nov 12, 2026  ·  @Someone
1. 개요
ClickHouse 에  저장된  이벤트를  조회해  단일룰 ( 카운트 , 시그니처 ) 로  탐지하고 , 단일룰을  순서도로  조합
한  시나리오  룰로  경보를  만드는  탐지  서버와  관리  화면을  만든다 . 새  룰과  시나리오는  코드  수정  없이  화
면에서  등록한다 .
범위
입력 : ClickHouse 에  저장된  네트워크  계층  이벤트  ( 방화벽 , IDS/IPS/TMS, WAF, UTM)
단일룰 : 화면  양식으로  정의하면  서버가  ClickHouse SQL 로  변환해  주기  실행  ( 카운트형 , 시그니처
형 )
시나리오  룰 : 단일룰을  순서도로  조합  ( 순서 , 분기 , 합류 , 등급별  경보 )
출력 : 경보를  사고처리  시스템으로  전달
관리 : 단일룰  편집기 , 순서도  편집기 , 리스트 · 자산 · 기관별  설정 , 백테스트 , 정오탐  피드백
범위  밖 : ClickHouse 로의  로그  적재 , 호스트 ( 엔드포인트 ) 로그  수집 , 자동  차단  조치
전제  ( 확인  전까지  어댑터로  추상화 )
미결  사항
항목 가정 확정되면  바꿀  곳
이벤트  저장소 codlog.log_integrated_success_all (12 개  데이터  유형  통합 , 30 일
보관 ). 적재  경로는  기존  파이프라인의  syslog 또는
Kafka 토픽  구독
clickhouse/views
사고처리  시스템
연동
REST webhook 으로  경보  등록 adapters/case
과거  로그  조회 ClickHouse 보관  기간  안에서  직접  조회 backtest
운영망 폐쇄망 . 외부  인터넷과  외부  LLM 호출  불가 배포  방식 , 오프라인  패키
지
관제  대상 다수  산하기관  ( 기관별  임계치 · 예외  필요 ) org_id  기반  멀티테넌시
운영  데이터에서도  IDS, UTM, WAF 이벤트에  포트가  비어  있는지  ( 포트  기반  룰의  적용  범위가  달
라짐 )
inst_id  값과  산하기관  대응표 , 기관별  내부  대역
시나리오  기반  탐지  엔진  설계안  (Claude Code 구현용 )
2. 아키텍처
탐지  서버는  ClickHouse 에  SQL 을  주기  실행해  단일룰  히트를  만들고 , 그  히트를  순서도에  대입해  시나
리오  경보를  만든다 . 중간  결과를  모두  ClickHouse 에  두므로  서버는  메모리  상태가  없고  여러  대로  늘릴
수  있다 .
룰 , 순서도 , 자산 , 리스트는  MariaDB 에  저장하고  ClickHouse 딕셔너리로  60 초마다  동기화한다 . 사고
처리  시스템의  종결  판정은  탐지  서버  API 로  돌아와  룰별  정탐률에  반영된다 .
ClickHouse 버전과  클러스터  구성  ( 분산  테이블  여부 )
사고처리  시스템의  경보  등록  API 규격
초당  이벤트  수 (EPS) 평균과  최대치
기관별  자산  정보 ( 용도 , OS) 보유  형태
구성  요소와  데이터  흐름  · 6 개  요소
구성  요소 책임
ClickHouse 이벤트  저장 ( v_events ), 단일룰  SQL 실행 , 히트  저장
( rule_hits )
룰  컴파일러 단일룰  정의를  검증하고  ClickHouse SQL 로  변환
스케줄러 주기가  된  단일룰을  실행하고  실행  이력을  기록
순서도  평가기 새  히트가  생긴  대상의  히트를  모아  순서도를  따라가며  경보
노드  도달  여부를  판정
경보  관리 경보  생성 , 등급  상향 , 중복  억제 , 사고처리  시스템  전달과  재
시도
API 서버 룰 · 순서도 · 리스트 · 자산 · 기관  설정 , 미리보기 , 백테스트 , 판정
시나리오  기반  탐지  엔진  설계안  (Claude Code 구현용 )
3. ClickHouse 이벤트  저장소
원본은  codlog.log_integrated_success_all  한  테이블이다 . 12 개  데이터  유형 ( data_tp ) 의  필드  367 개를  공통
필드  65 개로  합친  구조라 , 유형마다  비어  있는  필드가  다르다 . 단일룰은  원본을  직접  읽지  않고  탐지  전용
뷰  detect.v_events 만  조회한다 .
원본  테이블  요약
탐지에  쓰는  필드가  채워지는  데이터  유형
구성  요소 책임
관리  화면 단일룰  양식  편집기 , 순서도  편집기 , 경보  조회
MariaDB 설정 , 버전  이력 , 경보 , 실행  이력 , 감사  로그
항목 값 탐지  설계에  주는  영향
정렬  키 (mgr_time, data_tp) 모든  쿼리는  mgr_time  범위와  data_tp
조건을  먼저  건다
파티션 toYYYYMMDD(mgr_time) 평가  구간이  하루를  넘지  않으면  파티션  1~2
개만  읽는다
보관 mgr_time  + 30 일 백테스트와  순서도  조회  기간은  최대  30 일
시간대 Asia/Seoul 히트 , 경보 , 화면  모두  같은  시간대로  저장하
고  표시
기관 inst_id 탐지  서버의  org_id 는  inst_id  값을  그
대로  쓴다
IP IPv6  타입  (IPv4 는  ::ffff:  형태 ) 뷰에서  IPv4 문자열로  바꿔  대상  키와  리스
트  비교에  쓴다
이벤트
수
count  ( 한  행이  여러  건을  묶은  경우  있음 ) 건수  집계는  행  수가  아니라
sum(ifNull(count, 1))
텍스트
검색
search_text  ( 소문자  결합 , ngram 인덱스 ) 문자열  포함  조건은  이  컬럼을  우선  쓴다
보조  인
덱스
s_info , d_info , attack  bloom filter,
risk , action  set
IP· 공격명  조건이  빠르다
시나리오  기반  탐지  엔진  설계안  (Claude Code 구현용 )
이  표는  스키마  파일의  유형별  생성  규칙에서  뽑았다 . 실제  운영  데이터에서도  같은지  M1 에서  유형별  채
움  비율을  조회해  확인한다 .
설계에  반영한  제약
포트  조건은  FIREWALL, IPS, TMS, DDos 에서만  동작한다 . IDS, UTM, WAF 이벤트에는  포트가
없으므로  445·3389 같은  포트  기반  룰은  이  유형을  대상으로  삼지  않는다 . 화면은  조건에  쓴  필드가
없는  유형을  고르면  경고한다 .
IDS 에는  공격명 ( attack ) 이  없다 . 시그니처형  룰은  모든  유형에  있는  method ( 시그니처명 ) 를  기
본으로  쓰고 , 분류는  매핑  리스트로  붙인다 .
도메인 , 바이트  수 , 세션  시간  필드가  없다 . 킬스위치  도메인이나  SMTP 응답  코드는  search_text
또는  payload  문자열  조건으로  찾고 , 대용량  유출처럼  바이트가  필요한  룰은  1 차  범위에서  뺀다 .
평가  시간축은  mgr_time ( 수집  시각 ) 이다 . 정렬  키라서  빠르고 , 늦게  들어온  이벤트도  수집된  순간
다음  평가에  잡힌다 . 장비  시각  event_time 은  경보  표시와  근거에만  쓴다 .
탐지  전용  뷰
필드 값이  있는  유형 없는  유형
s_info , d_info
(IP)
APT, DDos, DPX, FIREWALL, IDS,
IPS, TMS, UTM, VPN, WAF, WEB
WFILTER
d_port DDos, FIREWALL, IPS, TMS APT, DPX, IDS, UTM, VPN, WAF,
WEB, WFILTER
s_port DDos, FIREWALL, IPS 나머지
direction DDos, DPX, FIREWALL, IDS, IPS,
TMS, UTM, WAF, WFILTER
APT, VPN, WEB
method  ( 시그니처
명 )
APT, VPN 을  뺀  10 종 APT, VPN
attack  ( 공격명 ) DDos, FIREWALL, IPS, TMS, UTM,
WAF, WEB, WFILTER
APT, DPX, IDS, VPN
action APT, WFILTER 를  뺀  10 종  (UTM 은
maction 도  있음 )
APT, WFILTER ( mstatus  사용 )
count APT, DDos, DPX, FIREWALL, IDS,
IPS, UTM, WEB, WFILTER
TMS, VPN, WAF (1 건으로  계산 )
payload DDos, IDS, IPS, TMS, UTM, WAF 나머지
event_time APT 를  뺀  11 종 APT
시나리오  기반  탐지  엔진  설계안  (Claude Code 구현용 )
CREATE DATABASE IF NOT EXISTS detect;
CREATE VIEW detect.v_events AS
SELECT
  event_id,
  mgr_time,                                              -- 평가  시간축
  coalesce(event_time, mgr_time)            AS event_time,
  inst_id                                   AS org_id,
  data_tp, log, sublog, product,
  s_info, d_info,                                        -- 원본  IPv6 ( 인덱스용 )
  if(isNull(s_info), '', 
replaceRegexpOne(IPv6NumToString(assumeNotNull(s_info)), '^::ffff:', '')) AS 
src_ip,
  if(isNull(d_info), '', 
replaceRegexpOne(IPv6NumToString(assumeNotNull(d_info)), '^::ffff:', '')) AS 
dst_ip,
  s_port                                    AS src_port,   -- Nullable
  d_port                                    AS dst_port,   -- Nullable
  lower(protocol)                           AS protocol,
  lower(multiIf(action != '', action, maction != '', maction, mstatus)) AS 
action,
  s_country                                 AS src_country,
  d_country                                 AS dst_country,
  method                                    AS signature_name,
  attack,
  risk,
  toUInt64(ifNull(count, 1))                AS event_count,
  uri, url_method, payload, search_text,
  -- 보강 : 방향  ( 장비  값  우선 , 없으면  기관  내부  대역으로  판정 )
  arrayExists(c -> isIPAddressInRange(src_ip, c),
              arrayFilter(x -> x != '', splitByChar(',', 
dictGetOrDefault('detect.dict_orgs', 'internal_cidrs', inst_id, '')))) AS 
src_internal,
  arrayExists(c -> isIPAddressInRange(dst_ip, c),
              arrayFilter(x -> x != '', splitByChar(',', 
dictGetOrDefault('detect.dict_orgs', 'internal_cidrs', inst_id, '')))) AS 
dst_internal,
  multiIf(direction != '', direction,
          mdirection != '', mdirection,
          src_internal AND dst_internal, 'internal',
          src_internal, 'outbound',
          dst_internal, 'inbound', 'external') AS net_direction,
  -- 보강 : 자산 , 유해  IP, 시그니처  분류
  arrayFilter(x -> x != '', splitByChar(',', 
시나리오  기반  탐지  엔진  설계안  (Claude Code 구현용 )
dictGetOrDefault('detect.dict_assets', 'tags', (inst_id, src_ip), ''))) AS 
src_asset_tags,
  arrayFilter(x -> x != '', splitByChar(',', 
dictGetOrDefault('detect.dict_assets', 'tags', (inst_id, dst_ip), ''))) AS 
dst_asset_tags,
  dictHas('detect.dict_threat_ip', src_ip)  AS src_ti_hit,
  dictHas('detect.dict_threat_ip', dst_ip)  AS dst_ti_hit,
  dictGetOrDefault('detect.dict_signature_map', 'category', (data_tp, 
method), '') AS signature_category
FROM codlog.log_integrated_success_all;
방향  값은  원본과  같이  inbound , outbound , internal ( 내부  간 ) 을  쓴다 . 장비가  방향을  주지
않는  APT, VPN, WEB 만  기관  대역으로  판정한다 .
기관  내부  대역은  기관마다  사설  대역이  겹칠  수  있어  IP 단독  딕셔너리 (ip_trie) 로  만들지  않고 , 기관
ID 로  대역  목록을  꺼내  비교한다 .
딕셔너리  원본은  MariaDB 테이블이고 (ClickHouse 의  MySQL 딕셔너리  소스 ), 60 초마다  갱신한
다 . 대역 · 태그처럼  여러  값인  항목은  MariaDB 쿼리에서  GROUP_CONCAT 으로  쉼표  문자열을  만
들어  넘기고  뷰에서  나눈다 . 화면에서  자산  태그나  분류를  고치면  다음  평가부터  반영된다 .
원본  테이블  구조가  바뀌면  이  뷰만  고친다 . 룰은  뷰  컬럼명만  참조한다 .
단일룰  히트  테이블
CREATE TABLE detect.rule_hits (
  hit_bucket       DateTime('Asia/Seoul'),                -- 집계  창  단위로  자른 
시각  ( 중복  제거  키 )
  rule_id          LowCardinality(String),
  rule_version     UInt32,
  org_id           LowCardinality(String),
  entity_type      LowCardinality(String),  -- host 등
  entity           String,                  -- 예 : 10.1.2.3
  first_seen       DateTime64(3, 'Asia/Seoul'),   -- 장비  시각  기준
  last_seen        DateTime64(3, 'Asia/Seoul'),
  value            Float64,                 -- 건수 , 고유  개수 , 합계
  threshold        Float64,
  sample_event_ids Array(String),           -- 근거  이벤트  ID ( 최대  20 개 )
  run_id           UUID,
  inserted_at      DateTime DEFAULT now()
) ENGINE = ReplacingMergeTree(inserted_at)
PARTITION BY toYYYYMMDD(hit_bucket)
ORDER BY (org_id, rule_id, entity, hit_bucket)
TTL hit_bucket + INTERVAL 90 DAY;
같은  대상이  같은  창에서  여러  번  평가돼도  (org_id, rule_id, entity, hit_bucket) 당  한
행만  남는다 . 조회는  FINAL 을  붙인다 .
시나리오  기반  탐지  엔진  설계안  (Claude Code 구현용 )
백테스트  결과는  같은  구조에  job_id 를  더한  rule_hits_backtest 에  쓴다  (TTL 7 일 ).
탐지  서버  계정은  v_events  읽기와  rule_hits  쓰기  권한만  갖는다 .
" 처음  보는  목적지 " 조건은  (org_id, src_ip, dst_ip) 별  최초  관측  시각을  모으는  구체화  뷰
peer_first_seen 으로  구현한다  (2 단계  기능 ).
4. 단일룰
단일룰은  ClickHouse 조회  한  번으로  판정되는  조건이다 . 화면  양식으로  정의하면  서버가  SQL 로  변환
해  주기  실행하고 , 조건을  넘은  대상을  rule_hits 에  기록한다 .
정의  형식  ( 카운트형 )
id: SR_SMB_OUT_FANOUT
name: 내부에서  외부  445 다수  접근
type: count                     # signature | count
entity: {type: host, field: src_ip}   # 탐지  대상 . 순서도에서  룰을  잇는  기준
data_tp: [FIREWALL, IPS, TMS]   # 필수 . 조건  필드가  채워지는  유형만  고른다  (3 장  표 )
filter:                         # 조건  트리 : all / any / not
  all:
    - {field: net_direction, op: eq, value: outbound}
    - {field: dst_port, op: eq, value: 445}
    # action 조건  없음 : 차단 (deny, block) 로그도  감염  증거로  센다
aggregate: {func: distinct_count, field: dst_ip}   # count | distinct_count | 
sum
window: 10m                     # 집계  창  (mgr_time 기준 )
threshold: 20                   # 기관별로  덮어쓸  수  있음
exclude_lists: [smb_allowed_sources]   # 대상이  리스트에  있으면  제외
schedule: 1m                    # 평가  주기
alert_on_hit: false             # true 면  순서도  없이  단독  경보도  생성
severity: medium
status: draft                   # draft | silent | active | disabled
정의  형식  ( 시그니처형 )
유형 히트  조건 예
signature 조건 ( 탐지명 , 분류 , 리스트  일치 ) 에  맞는  이벤트
가  창  안에  min_count 건  이상  ( 기본  1)
WannaCry 시그니처 , 채굴  풀  통신 , 유
해  IP 통신
count 조건에  맞는  이벤트를  대상별로  집계한  값이  임
계치  이상
10 분  내  외부  445 목적지  20 개  이상
시나리오  기반  탐지  엔진  설계안  (Claude Code 구현용 )
id: SR_WANNACRY_SIG
name: WannaCry 시그니처  또는  킬스위치  접속
type: signature
entity: {type: host, field: src_ip}
data_tp: [IDS, IPS, TMS, UTM, FIREWALL]
filter:
  any:
    - {field: signature_category, op: eq, value: ransomware_wannacry}
    - {field: search_text, op: contains_list, value: 
wannacry_killswitch_domains}
min_count: 1                    # 건수는  event_count 합계로  센다
window: 5m
schedule: 1m
alert_on_hit: true
severity: high
status: draft
서버가  만드는  SQL ( 위  카운트형  예 )
INSERT INTO detect.rule_hits
  (hit_bucket, rule_id, rule_version, org_id, entity_type, entity,
   first_seen, last_seen, value, threshold, sample_event_ids, run_id)
SELECT
  toStartOfInterval({win_to:DateTime}, INTERVAL 10 MINUTE) AS hit_bucket,
  'SR_SMB_OUT_FANOUT', 3, org_id, 'host',
  src_ip                            AS entity,
  min(event_time), max(event_time),
  toFloat64(uniqExact(dst_ip))      AS value,
  dictGetOrDefault('detect.dict_org_rule_params', 'threshold',
                   (org_id, 'SR_SMB_OUT_FANOUT'), 20.) AS threshold,
  groupArraySample(20)(toString(event_id)),
  {run_id:UUID}
FROM detect.v_events
WHERE mgr_time >= {win_from:DateTime64(3)} AND mgr_time < 
{win_to:DateTime64(3)}   -- 정렬  키
  AND data_tp IN ('FIREWALL', 'IPS', 'TMS')                                    
-- 정렬  키
  AND src_ip != ''
  AND net_direction = 'outbound'
  AND dst_port = 445
  AND NOT dictHas('detect.dict_list_items', ('smb_allowed_sources', src_ip))
GROUP BY org_id, entity
HAVING value >= threshold
SETTINGS max_execution_time = 30;
시나리오  기반  탐지  엔진  설계안  (Claude Code 구현용 )
집계  함수가  count 인  룰은  count() 가  아니라  sum(event_count) 로  변환한다 . 원본  한  행이  여러
건을  묶은  경우가  있기  때문이다 .
조건  연산자와  SQL 대응
변환  규칙
필드명은  v_events  컬럼  허용  목록에  있어야  하고 , 값은  타입  검증  후  쿼리  파라미터로  넘긴다 . 사
용자가  쓴  문자열을  SQL 에  그대로  잇지  않는다 .
data_tp 는  필수다 . 조건에  쓴  필드가  고른  유형에서  비어  있으면 (3 장  표 ) 저장할  때  경고하고 , 모
든  유형에서  비어  있으면  거부한다 .
평가  구간은  mgr_time  기준으로  win_to = 현재  − 15 초 , win_from = win_to − window
다 . 수집  시각  기준이라  적재  지연  보정이  필요  없다 .
임계치는  dict_org_rule_params 에  기관별  값이  있으면  그  값을 , 없으면  룰의  기본값을  쓴다 .
entity.field 가  달라도  entity.type 이  같으면  순서도에서  같은  대상으로  잇는다 . 예 : 공격받
은  서버 ( dst_ip ) 와  그  서버의  외부  접속 ( src_ip ) 은  둘  다  host 다 .
모든  쿼리에  실행  시간  제한 (30 초 ) 과  결과  행  제한 (10 만  행 ) 을  건다 .
SQL 직접  입력은  1 차  범위에서  제외한다 . 필요해지면  관리자  전용으로  추가하되  SELECT 만  허용하
고  결과  컬럼  규격을  강제한다 .
연산자 SQL
eq , ne , gte , lte = , != , >= , <=
in , not_in IN (...) , NOT IN (...)
cidr isIPAddressInRange(src_ip, '10.0.0.0/8')
contains search_text 이면  hasToken / like  (ngram 인덱스
사용 ), 그  외  positionCaseInsensitive(...) > 0
contains_list multiSearchAnyCaseInsensitive(field, [ 리스트
항목 ]) . 항목은  컴파일  때  펼치고  리스트가  바뀌면  다시  컴
파일
regex match(...)
in_list , not_in_list dictHas('detect.dict_list_items', (list_id,
value))
has_tag has(src_asset_tags, 'tag')
exists 숫자형은  isNotNull(...) , 문자열은  != ''
시나리오  기반  탐지  엔진  설계안  (Claude Code 구현용 )
5. 시나리오  룰  ( 순서도 )
시나리오  룰은  단일룰을  노드로  놓고  화살표로  이은  순서도다 . 같은  대상 ( 기관  + entity) 에  대해  시작  노
드에서  경보  노드까지  가는  경로가  성립하면  경보가  난다 .
단일룰  히트가  시작점이고 , 마름모에서  다른  단일룰의  발생  여부나  자산  조건으로  갈라져  등급이  다른  경
보  노드에  도달한다 .
노드  유형
시나리오  순서도  예시  · SC_SMB_WORM
유형 모양 성립  조건 주요  속성
start 둥근  시작점 항상  성립 . 순서도당  1 개
rule 사각형 참조한  단일룰의  히트가  앞  노드  성립  시각  이
후 , 들어오는  화살표의  within  안에  있음
rule_id
check 마름모  ( 예 / 아
니오 )
현재  시각  앞뒤  lookaround  안에  참조  룰
중  하나라도  히트가  있으면  예 . 순서  무관  조건
과  등급  분기에  사용
rule_ids , lookaround
asset 마름모  ( 예 / 아
니오 )
대상  자산이  지정  태그  중  하나를  가지면  예 tags
and 합류 들어오는  모든  가지가  within  안에  성립 . 성
립  시각은  가장  늦은  가지
within
or 합류 들어오는  가지  중  하나  성립 . 성립  시각은  가장
이른  가지
시나리오  기반  탐지  엔진  설계안  (Claude Code 구현용 )
화살표  속성
저장  형식  ( 위  그림의  순서도 )
{
  "id": "SC_SMB_WORM",
  "name": "SMB 웜  전파 ",
  "entity_type": "host",
  "status": "draft",
  "suppress_for": "6h",
  "nodes": [
    {"id": "n0", "type": "start", "pos": [40, 110]},
    {"id": "n1", "type": "rule", "rule_id": "SR_SMB_OUT_FANOUT", "pos": [190, 
110]},
    {"id": "n2", "type": "check", "rule_ids": ["SR_WANNACRY_SIG", 
"SR_TI_HIT"], "lookaround": "24h", "pos": [390, 110]},
    {"id": "n3", "type": "asset", "tags": ["legacy_os", "medical_device", 
"kiosk"], "pos": [390, 236]},
    {"id": "a1", "type": "alert", "severity": "critical",
     "title": "SMB 웜  전파  ( 고위험 ): {{entity}}",
     "playbook": " 네트워크  격리 ( 포맷  금지 ), 호스트  점검  로그  채증 , 백신  정밀  검사 , SMB 포
트  비활성화  검토 ", "pos": [650, 110]},
    {"id": "a2", "type": "alert", "severity": "high",
     "title": "SMB 웜  외부  전파  의심 : {{entity}}",
     "playbook": " 출발지  자산  확인 , 정상  통신  여부  확인 , 호스트  점검  요청 ", "pos": 
[650, 316]}
  ],
  "edges": [
    {"from": "n0", "to": "n1"},
    {"from": "n1", "to": "n2"},
    {"from": "n2", "to": "a1", "branch": "yes"},
    {"from": "n2", "to": "n3", "branch": "no"},
유형 모양 성립  조건 주요  속성
alert 끝  노드 도달하면  경보 . 여러  개  둘  수  있음 severity , title ,
playbook
속성 의미
from , to 잇는  노드
branch 마름모에서  나가는  화살표의  yes  또는  no
within rule  노드로  들어갈  때  앞  노드  이후  허용  시간  ( 예 : 30m ).
시작  노드에서  나가는  화살표에는  없음
시나리오  기반  탐지  엔진  설계안  (Claude Code 구현용 )
    {"from": "n3", "to": "a1", "branch": "yes"},
    {"from": "n3", "to": "a2", "branch": "no"}
  ]
}
평가  규칙
순서도의  모든  rule , check  노드는  순서도의  entity_type 과  같은  유형의  단일룰만  참조한다 .
시작  노드  바로  뒤의  rule  노드는  히트가  있으면  성립한다 . 그  뒤의  rule  노드는  순서와  within
을  지켜야  한다 .
한  번의  평가에서  여러  경보  노드에  도달하면  가장  높은  등급  하나만  경보로  만든다 .
억제  시간  안에  같은  대상이  더  높은  등급의  경보  노드에  도달하면  새  경보를  만들지  않고  기존  경보
의  등급을  올려  다시  전달한다 . check  노드가  나중에  예로  바뀌는  경우가  여기에  해당한다 .
경보에는  지나온  경로 ( 노드별  성립  시각과  근거  히트 ) 를  함께  저장한다 .
저장  시  검증
순환이  없어야  한다 . 시작  노드는  1 개 , 경보  노드는  1 개  이상이다 .
모든  노드는  시작에서  도달할  수  있고 , 경보가  아닌  모든  노드는  나가는  화살표가  있다 .
마름모는  yes 와  no  화살표를  하나씩  가진다 .
참조한  단일룰이  존재하고  silent  또는  active  상태다 . 순서도를  active 로  올리려면  참조  룰
도  모두  active 여야  한다 .
시작에서  경보까지  within 과  lookaround 의  합은  7 일을  넘지  않는다 .
6. 기본  제공  룰
과거  사고  12 건에서  단일룰  14 개와  시나리오  7 개를  뽑아  초기  룰로  넣는다 . 임계치는  시작값이며  백테스
트로  조정한다 .
단일룰
ID 유형 대상  필
드
조건  ( 시작값 )
SR_SMB_OUT_FANOUT count src_ip FIREWALL·IPS·TMS 에서  10 분  내  외부  445
목적지  20 개  이상  ( 차단  포함 )
SR_SMB_IN_FANOUT count src_ip FIREWALL·IPS·TMS 에서  10 분  내  내부  445
목적지  10 개  이상
SR_SMB_SIG signature src_ip SMB 관리  공유  접근  시그니처
SR_WANNACRY_SIG signature src_ip WannaCry 시그니처  또는  킬스위치  도메인  접
속
시나리오  기반  탐지  엔진  설계안  (Claude Code 구현용 )
시나리오
ID 유형 대상  필
드
조건  ( 시작값 )
SR_TI_HIT signature src_ip 유해  IP· 도메인과  통신
SR_REMOTE_PORT_FANOUT count src_ip FIREWALL·IPS·TMS 에서  10 분  내  외부
3389/3390/33890/22/5900 목적지  10 개  이
상
SR_AUTH_BRUTEFORCE count dst_ip 5 분  내  인증  포트 (22, 25, 110, 143, 587, 3389)
인바운드  30 건  이상  (FIREWALL·IPS·TMS),
또는  대입  공격명  시그니처
SR_AUTH_SUCCESS signature dst_ip 인증  성공  시그니처 , 또는  IDS·IPS·TMS 페이
로드에  SMTP 235 응답
SR_REMOTE_TOOL signature src_ip 원격제어  도구  시그니처 , 또는  도구  포트
(AnyDesk 6568 등 ) 아웃바운드  접속
SR_MALWARE_SIG signature src_ip 악성코드  분류  시그니처
SR_COINMINER signature src_ip 채굴  풀  통신  시그니처
SR_COINMINER_REPEAT count src_ip 1 시간  내  채굴  시그니처  10 건  이상
SR_WAF_BURST count dst_ip 1 분  내  WAF 공격  탐지  300 건  이상
(event_count 합계 )
SR_NEW_OUTBOUND signature src_ip 웹서버  태그  자산이  처음  보는  외부  IP 로  접속
(2 단계  기능 )
ID 순서도 경보  등급
SC_SMB_WORM SR_SMB_OUT_FANOUT  → WannaCry· 유해  IP 확인
→ 레거시  자산  확인
긴급  또는  높
음
SC_SMB_LATERAL SR_SMB_IN_FANOUT  또는  SR_SMB_SIG  (or 합류 )
→ 파일서버  자산  확인  ( 파일서버면  낮음 )
높음  또는  낮
음
SC_REMOTE_SCAN_OUT SR_REMOTE_PORT_FANOUT  → 레거시  자산  확인 긴급  또는  높
음
SC_BRUTEFORCE_SUCCESS SR_AUTH_BRUTEFORCE  → 30 분  내
SR_AUTH_SUCCESS
높음
시나리오  기반  탐지  엔진  설계안  (Claude Code 구현용 )
단일룰은  rules/builtin/single/*.yaml , 순서도는  rules/builtin/scenarios/*.json 에
둔다 .
7. 탐지  서버  동작
탐지  서버는  1 분마다  " 단일룰  실행  → 새  히트  확인  → 순서도  평가  → 경보 " 를  반복한다 . 집계는
ClickHouse 가  하고 , 서버는  SQL 을  만들어  보내고  순서도를  따라가는  일만  한다 .
1. 실행  대상  선택 . 스케줄러가  silent , active  단일룰  중  주기가  된  룰을  고른다 . MariaDB 행  잠
금 (`SELECT ... FOR UPDATE SKIP LOCKED`) 으로  서버가  여러  대여도  한  룰은  한  번만  실행한
다 .
2. 단일룰  실행 . 룰별  SQL 을  INSERT INTO rule_hits ... SELECT  형태로  ClickHouse 에  보낸
다 . 결과가  서버를  거치지  않는다 . 실행  시간 , 히트  수 , 오류를  rule_runs 에  기록한다 .
3. 단독  경보 . alert_on_hit 가  켜진  룰의  새  히트는  바로  경보  후보가  된다 .
4. 후보  대상  선정 . 이번  주기에  새  히트가  생긴  (org_id, entity) 와  그  룰을  참조하는  순서도를  짝
짓는다 .
5. 히트  조회 . 후보  대상에  대해  순서도가  참조하는  모든  룰의  히트를  순서도  최대  기간만큼
rule_hits 에서  한  번에  읽는다 .
6. 순서도  평가 . evaluate(graph, hits, asset_tags) 가  그래프를  따라가며  도달한  경보  노드
와  경로를  돌려준다 . 입출력만  있는  순수  함수로  만들어  실시간 , 백테스트 , 화면  미리보기가  같이  쓴
다 .
7. 경보  생성 , 상향 , 억제 . 억제  키는  ( 순서도 , org_id, entity) 다 . 억제  시간  안에  같은  등급이면
건수와  최종  시각만  갱신하고 , 더  높은  등급이면  기존  경보를  상향해  다시  전달한다 .
8. 전달 . active  순서도의  경보만  사고처리  시스템으로  보낸다 . silent 는  저장만  한다 .
시간  처리
평가  구간은  mgr_time ( 수집  시각 ) 기준이고 , 끝은  현재  − 15 초 다 . 장비  시각이  늦거나  수집이  지
연돼도  수집된  다음  주기에  잡히므로  겹쳐  다시  평가할  필요가  없다 .
룰별  마지막  평가  시각 ( last_evaluated_to ) 을  MariaDB 에  둔다 . 서버가  멈췄다  살아나면  그  시
각부터  따라잡는다  ( 최대  24 시간 , 원본  보관  30 일  이내 ).
ID 순서도 경보  등급
SC_REMOTE_TOOL_MALICIOUS SR_REMOTE_TOOL 과  ( SR_TI_HIT  또는
SR_MALWARE_SIG ) 가  24 시간  내  모두  발생  (and 합
류 )
높음
SC_COINMINER SR_COINMINER  → SR_COINMINER_REPEAT  확인 높음  또는  중
간
SC_WEB_ATTACK_SUCCESS SR_WAF_BURST  → 1 시간  내  SR_NEW_OUTBOUND 긴급
시나리오  기반  탐지  엔진  설계안  (Claude Code 구현용 )
히트의  first_seen , last_seen 과  경보  표시는  장비  시각 ( event_time ) 을  쓴다 . 순서도의  순
서  판정은  히트의  hit_bucket ( 수집  시각  기준 ) 으로  한다 .
설정  변경  반영
룰이나  순서도를  고치면  버전이  올라간다 . 히트에는  룰  버전이  남고 , 순서도  평가는  참조  룰의  현재
버전  히트만  쓴다 .
서버는  매  주기  시작  때  변경된  룰과  순서도만  다시  읽는다 . 재시작이  필요  없다 .
장애와  부하  보호
ClickHouse 쿼리가  실패하거나  시간  제한을  넘으면  그  실행을  실패로  기록하고  다음  주기에  같은
구간을  다시  시도한다 . 3 회  연속  실패하면  관리  화면에  경고를  띄운다 .
단일룰  동시  실행  수를  제한한다  ( 기본  4 개 ). 한  주기  안에  끝나지  못한  룰은  다음  주기를  건너뛰고  지
연  지표를  올린다 .
사고처리  시스템  전달  실패  시  지수  간격으로  최대  10 회  재시도하고 , 실패  건은  관리  화면에  표시한
다 .
8. 데이터  모델  (MariaDB)
MariaDB(10.11 LTS 이상 ) 에는  설정 , 버전  이력 , 경보 , 실행  이력을  저장한다 . 이벤트와  히트는
ClickHouse 에  있고 (3 장 ), 경보는  근거  히트와  이벤트  ID 만  참조한다 . 여러  값인  항목 ( 기관  대역 , 자산  태
그 , 참조  룰 ) 은  배열  컬럼  대신  하위  테이블로  둔다 .
공통  규칙
모든  테이블은  ENGINE=InnoDB , DEFAULT CHARSET=utf8mb4
COLLATE=utf8mb4_unicode_ci .
시각은  DATETIME(3) 에  한국  시간으로  저장하고 , 접속  세션은  time_zone='+09:00' 으로  고정
한다 . ClickHouse 의  Asia/Seoul 과  맞춘다 .
JSON 은  JSON  타입 ( 내부적으로  LONGTEXT  + JSON_VALID  검사 ) 으로  저장한다 .
ID 는  MariaDB UUID  타입 (10.7 이상 ) 을  쓴다 .
주기  실행  잠금은  SELECT ... FOR UPDATE SKIP LOCKED (10.6 이상 ) 로  한다 .
CREATE TABLE orgs (
  org_id     VARCHAR(64)  PRIMARY KEY,          -- log_integrated_success_all.inst_id 값
  name       VARCHAR(200) NOT NULL,
  enabled    BOOLEAN      NOT NULL DEFAULT TRUE
);
CREATE TABLE org_cidrs (                         -- 기관  내부  대역  (dict_orgs 원
본 )
  org_id  VARCHAR(64) NOT NULL,
  cidr    VARCHAR(43) NOT NULL,                  -- 예 : 10.30.0.0/16
시나리오  기반  탐지  엔진  설계안  (Claude Code 구현용 )
  PRIMARY KEY (org_id, cidr),
  FOREIGN KEY (org_id) REFERENCES orgs (org_id)
);
-- 단일룰
CREATE TABLE single_rules (
  rule_id           VARCHAR(64) PRIMARY KEY,
  current_version   INT         NOT NULL,
  type              VARCHAR(16) NOT NULL CHECK (type IN 
('signature','count')),
  entity_type       VARCHAR(32) NOT NULL,
  status            VARCHAR(16) NOT NULL CHECK (status IN 
('draft','silent','active','disabled')),
  schedule_sec      INT         NOT NULL DEFAULT 60,
  last_evaluated_to DATETIME(3),                 -- 마지막  평가  구간의  끝 
(mgr_time 기준 )
  next_run_at       DATETIME(3),                 -- 스케줄러가  SKIP LOCKED 로  집
는  기준
  created_by        VARCHAR(64) NOT NULL,
  updated_at        DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON 
UPDATE CURRENT_TIMESTAMP(3),
  KEY idx_due (status, next_run_at)
);
CREATE TABLE single_rule_versions (
  rule_id      VARCHAR(64) NOT NULL,
  version      INT         NOT NULL,
  definition   JSON        NOT NULL,             -- 검증을  통과한  정의
  compiled_sql MEDIUMTEXT  NOT NULL,             -- 변환된  ClickHouse SQL
  change_note  VARCHAR(500),
  created_by   VARCHAR(64) NOT NULL,
  created_at   DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  PRIMARY KEY (rule_id, version),
  FOREIGN KEY (rule_id) REFERENCES single_rules (rule_id)
);
CREATE TABLE org_rule_params (                   -- dict_org_rule_params 원본
  org_id    VARCHAR(64) NOT NULL,
  rule_id   VARCHAR(64) NOT NULL,
  enabled   BOOLEAN     NOT NULL DEFAULT TRUE,
  threshold DOUBLE,
  PRIMARY KEY (org_id, rule_id)
);
CREATE TABLE rule_runs (
  run_id      UUID        PRIMARY KEY,
시나리오  기반  탐지  엔진  설계안  (Claude Code 구현용 )
  rule_id     VARCHAR(64) NOT NULL,
  version     INT         NOT NULL,
  win_from    DATETIME(3) NOT NULL,
  win_to      DATETIME(3) NOT NULL,
  status      VARCHAR(16) NOT NULL,              -- ok, failed, timeout
  hit_count   INT,
  duration_ms INT,
  error       TEXT,
  started_at  DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  KEY idx_rule_time (rule_id, started_at)
);
-- 시나리오  ( 순서도 )
CREATE TABLE scenarios (
  scenario_id     VARCHAR(64) PRIMARY KEY,
  current_version INT         NOT NULL,
  entity_type     VARCHAR(32) NOT NULL,
  status          VARCHAR(16) NOT NULL CHECK (status IN 
('draft','silent','active','disabled')),
  created_by      VARCHAR(64) NOT NULL,
  updated_at      DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE 
CURRENT_TIMESTAMP(3)
);
CREATE TABLE scenario_versions (
  scenario_id  VARCHAR(64) NOT NULL,
  version      INT         NOT NULL,
  graph        JSON        NOT NULL,             -- 노드 , 화살표 , 화면  좌표
  max_span_sec INT         NOT NULL,             -- 시작부터  경보까지  최대  기간
  change_note  VARCHAR(500),
  created_by   VARCHAR(64) NOT NULL,
  created_at   DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  PRIMARY KEY (scenario_id, version),
  FOREIGN KEY (scenario_id) REFERENCES scenarios (scenario_id)
);
CREATE TABLE scenario_rule_refs (                -- " 이  룰을  참조하는  순서도 " 조회
용
  scenario_id VARCHAR(64) NOT NULL,
  version     INT         NOT NULL,
  rule_id     VARCHAR(64) NOT NULL,
  PRIMARY KEY (scenario_id, version, rule_id),
  KEY idx_rule (rule_id)
);
-- 리스트와  자산  (ClickHouse 딕셔너리  원본 )
시나리오  기반  탐지  엔진  설계안  (Claude Code 구현용 )
CREATE TABLE lists (
  list_id      VARCHAR(64) PRIMARY KEY,
  kind         VARCHAR(16) NOT NULL CHECK (kind IN 
('ip','cidr','domain','string','signature_map')),
  scope_org_id VARCHAR(64),                      -- NULL 이면  전체  기관  공통
  description  VARCHAR(500)
);
CREATE TABLE list_items (
  list_id      VARCHAR(64)  NOT NULL,
  value        VARCHAR(255) NOT NULL,
  mapped_value VARCHAR(64),                      -- signature_map 일  때  분류값
  expires_at   DATETIME(3),
  note         VARCHAR(500),
  PRIMARY KEY (list_id, value),
  FOREIGN KEY (list_id) REFERENCES lists (list_id) ON DELETE CASCADE
);
CREATE TABLE assets (
  org_id     VARCHAR(64) NOT NULL,
  ip         VARCHAR(45) NOT NULL,               -- IPv4 문자열 
(v_events.src_ip 와  같은  형식 )
  purpose    VARCHAR(200),
  os         VARCHAR(100),
  holds_sensitive BOOLEAN,
  source     VARCHAR(32),                        -- manual, import, 
incident_reply
  updated_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE 
CURRENT_TIMESTAMP(3),
  PRIMARY KEY (org_id, ip)
);
CREATE TABLE asset_tags (
  org_id VARCHAR(64) NOT NULL,
  ip     VARCHAR(45) NOT NULL,
  tag    VARCHAR(64) NOT NULL,                   -- legacy_os, 
medical_device, kiosk 등
  PRIMARY KEY (org_id, ip, tag),
  FOREIGN KEY (org_id, ip) REFERENCES assets (org_id, ip) ON DELETE CASCADE
);
-- 경보
CREATE TABLE alerts (
  alert_id        UUID        PRIMARY KEY,
  source_type     VARCHAR(16) NOT NULL CHECK (source_type IN 
('single_rule','scenario')),
시나리오  기반  탐지  엔진  설계안  (Claude Code 구현용 )
  source_id       VARCHAR(64) NOT NULL,
  source_version  INT         NOT NULL,
  org_id          VARCHAR(64) NOT NULL,
  entity_type     VARCHAR(32) NOT NULL,
  entity          VARCHAR(128) NOT NULL,
  severity        VARCHAR(16) NOT NULL,
  title           VARCHAR(300) NOT NULL,
  path            JSON        NOT NULL,          -- 지나온  노드별  성립  시각 , 근거 
히트 , 이벤트  ID
  first_seen      DATETIME(3) NOT NULL,
  last_seen       DATETIME(3) NOT NULL,
  hit_count       INT         NOT NULL DEFAULT 1,
  silent          BOOLEAN     NOT NULL DEFAULT FALSE,
  delivery_status VARCHAR(16) NOT NULL DEFAULT 'pending',   -- pending, sent, 
failed
  case_ref        VARCHAR(64),
  verdict         VARCHAR(32),                   -- true_positive, 
false_positive, benign
  verdict_note    TEXT,
  verdict_at      DATETIME(3),
  KEY idx_org_time (org_id, first_seen),
  KEY idx_source_time (source_type, source_id, first_seen),
  KEY idx_suppress (source_id, org_id, entity, last_seen)
);
CREATE TABLE known_incidents (                   -- 재현율  확인용  과거  사고
  incident_id VARCHAR(64) PRIMARY KEY,
  org_id      VARCHAR(64) NOT NULL,
  entity      VARCHAR(128) NOT NULL,
  occurred_at DATETIME(3) NOT NULL,
  summary     TEXT
);
CREATE TABLE backtest_jobs (
  job_id      UUID        PRIMARY KEY,
  target_type VARCHAR(16) NOT NULL,              -- single_rule, scenario
  target_id   VARCHAR(64) NOT NULL,
  definition  JSON        NOT NULL,              -- 저장  전  초안도  시험  가능
  org_ids     JSON,
  time_from   DATETIME(3) NOT NULL,
  time_to     DATETIME(3) NOT NULL,
  status      VARCHAR(16) NOT NULL,              -- queued, running, done, 
failed
  result      JSON,
  created_by  VARCHAR(64) NOT NULL,
  created_at  DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3)
시나리오  기반  탐지  엔진  설계안  (Claude Code 구현용 )
);
CREATE TABLE audit_log (
  id     BIGINT AUTO_INCREMENT PRIMARY KEY,
  actor  VARCHAR(64)  NOT NULL,
  action VARCHAR(64)  NOT NULL,
  target VARCHAR(200) NOT NULL,
  detail JSON,
  at     DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  KEY idx_at (at)
);
ClickHouse 딕셔너리  (MariaDB 원본 )
-- 접속  정보는  ClickHouse 서버  설정의  named collection(mariadb_detect) 에  두고  SQL 에 
쓰지  않는다
CREATE DICTIONARY detect.dict_orgs (
  inst_id        String,
  internal_cidrs String                      -- 쉼표로  이은  대역
)
PRIMARY KEY inst_id
SOURCE(MYSQL(NAME mariadb_detect
  query 'SELECT org_id AS inst_id, GROUP_CONCAT(cidr) AS internal_cidrs FROM 
org_cidrs GROUP BY org_id'))
LAYOUT(COMPLEX_KEY_HASHED())
LIFETIME(MIN 30 MAX 60);
CREATE DICTIONARY detect.dict_assets (
  org_id String, ip String,
  tags   String                              -- 쉼표로  이은  태그
)
PRIMARY KEY org_id, ip
SOURCE(MYSQL(NAME mariadb_detect
  query 'SELECT org_id, ip, GROUP_CONCAT(tag) AS tags FROM asset_tags GROUP 
BY org_id, ip'))
LAYOUT(COMPLEX_KEY_HASHED())
LIFETIME(MIN 30 MAX 60);
dict_list_items , dict_threat_ip , dict_signature_map , dict_org_rule_params
도  같은  방식으로  각  테이블에서  만든다 .
딕셔너리용  MariaDB 계정은  해당  테이블  읽기  권한만  갖는다 .
GROUP_CONCAT  결과가  잘리지  않도록  이  계정의  group_concat_max_len 을  충분히 ( 예 :
65535) 키운다 .
시나리오  기반  탐지  엔진  설계안  (Claude Code 구현용 )
assets.source 의  incident_reply 는  사고  대응  중  기관이  회신한  자산  정보를  등록한  경우다 . 회
신  정보가  쌓일수록  순서도의  자산  조건  분기가  정확해진다 .
9. 서버  API
모든  API 는  /api/v1  아래  REST(JSON) 로  제공하고  OpenAPI 문서를  자동  생성한다 . 인증은  세션  토
큰 , 권한은  역할  기반이다 .
메서드와  경로 기능 최소  역할
GET /meta/fields v_events  컬럼 , 타입 , 쓸  수  있는
연산자  ( 양식  구성용 )
viewer
GET, POST /single-rules 단일룰  목록 , 생성 viewer, author
GET, PUT /single-rules/{id} 조회 , 수정  ( 새  버전  생성 ) viewer, author
POST /single-rules/compile 저장  없이  검증하고  변환된  SQL 반
환
author
POST /single-rules/preview 초안을  최근  구간 ( 기본  24 시간 ) 에
실행해  히트  수 , 상위  대상 , 시간대
별  분포  반환
author
POST /single-rules/{id}/status 상태  전환 author, admin
(active 전환 )
GET /single-rules/{id}/runs 실행  이력과  오류 viewer
GET /single-rules/{id}/hits 최근  히트  조회 analyst
GET, POST /scenarios 순서도  목록 , 생성 viewer, author
GET, PUT /scenarios/{id} 순서도  조회 , 수정  ( 새  버전  생성 ) viewer, author
POST /scenarios/validate 저장  없이  그래프  검증 . 오류를  노드
· 화살표  ID 와  함께  반환
author
POST /scenarios/simulate 초안  순서도를  지정한  대상과  기간
의  실제  히트에  대입해  경로  반환
author
POST /scenarios/{id}/status 상태  전환 author, admin
(active 전환 )
GET /scenarios/{id}/versions 버전  이력과  차이 viewer
GET, PUT /orgs/{org}/rule-
params/{rule_id}
기관별  임계치와  사용  여부 author
시나리오  기반  탐지  엔진  설계안  (Claude Code 구현용 )
역할
사고처리  시스템으로  보내는  경보  본문
{
  "alert_id": "uuid",
  "source_type": "scenario",
  "source_id": "SC_SMB_WORM",
  "source_version": 3,
  "org_id": "ORG001",
  "severity": "critical",
  "title": "SMB 웜  전파  ( 고위험 ): 10.1.2.3",
메서드와  경로 기능 최소  역할
GET, POST /lists , PUT, DELETE
/lists/{id} , POST
/lists/{id}/items:bulk
리스트  관리 , 일괄  등록  (CSV) author
GET, PUT /orgs/{org}/assets , POST
/orgs/{org}/assets:import
자산과  태그  관리 author
GET /alerts , GET /alerts/{id} 경보  검색 , 상세  ( 경로와  근거  포함 ) analyst
GET /alerts/{id}/events 근거  이벤트를  ClickHouse 에서
조회
analyst
POST /alerts/{id}/verdict 정탐 · 오탐  판정  등록 analyst
POST /backtests , GET
/backtests/{id}
백테스트  실행 , 결과  조회 author
GET /metrics/rules 룰 · 순서도별  경보  수 , 정탐률 , 실행
시간
viewer
GET /health , GET /metrics 상태  점검 , Prometheus 지표 내부망
POST /hooks/case-verdict 사고처리  시스템이  종결  판정을  돌
려주는  수신점
서비스  토큰
역할 할  수  있는  일
viewer 조회
analyst 경보  조회와  판정
author 단일룰 · 순서도 · 리스트 · 자산  작성 , 미리보기 , 백테스트
admin 운영  반영 (active), 사용자 · 기관  관리
시나리오  기반  탐지  엔진  설계안  (Claude Code 구현용 )
  "entity": {"type": "host", "value": "10.1.2.3"},
  "asset": {"tags": ["legacy_os", "medical_device"], "purpose": " 검사  장비 ", 
"os": "Windows 7"},
  "path": [
    {"node": "n1", "rule_id": "SR_SMB_OUT_FANOUT", "at": "2026-11-
12T01:10:00Z", "value": 37, "threshold": 20},
    {"node": "n2", "result": "no"},
    {"node": "n3", "result": "yes", "matched_tags": ["legacy_os"]},
    {"node": "a1"}
  ],
  "first_seen": "2026-11-12T01:00:03Z",
  "last_seen": "2026-11-12T01:10:00Z",
  "playbook": " 네트워크  격리 ( 포맷  금지 ), 호스트  점검  로그  채증 , ...",
  "evidence_url": "https://<server>/alerts/<alert_id>"
}
10. 관리  화면
화면은  5 개이고 , 핵심은  단일룰  편집기와  순서도  편집기다 . 둘  다  저장  전에  실제  데이터로  결과를  확인할
수  있어야  한다 .
순서도  편집기  동작  규칙
왼쪽  목록에는  순서도의  entity_type 과  같은  유형의  단일룰만  보인다 . 끌어다  놓으면  rule  노
드가  된다 .
화면 구성 주요  동작
단일룰  편
집기
왼쪽  양식 ( 유형 , 대상  필드 , 조건  줄 , 집계 ,
창 , 임계치 ), 오른쪽  변환된  SQL 과  미리보
기  결과
조건  줄  추가 · 삭제 · 묶기 (all/any), 미리보기
실행 , 저장 , 상태  전환
순서도  편
집기
왼쪽  단일룰  목록 ( 검색 , 유형  표시 ), 가운데
캔버스 , 오른쪽  선택한  노드 · 화살표의  속성
단일룰을  캔버스로  끌어다  놓기 , 노드  연결 ,
분기 · 합류 · 경보  노드  추가 , 검증 , 시뮬레이션 ,
저장
경보  목록 ·
상세
필터 ( 기관 , 등급 , 기간 , 판정 ), 상세에는  순서
도와  지나온  경로  강조 , 노드별  근거  이벤트
판정  등록 , 오탐  대상을  예외  리스트에  추가
설정 리스트 , 자산 · 태그 , 기관별  임계치 , 시그니처
분류  매핑
일괄  등록 (CSV), 수정
현황 룰 · 순서도별  경보  수 , 정탐률 , 실행  시간 , 실
패한  실행
조정이  필요한  룰  확인
시나리오  기반  탐지  엔진  설계안  (Claude Code 구현용 )
마름모 ( check , asset ) 에서  화살표를  뽑으면  예 / 아니오를  고르게  한다 . 이미  쓴  가지는  고를  수  없
다 .
rule  노드로  들어가는  화살표를  누르면  허용  시간 ( within ) 을  입력한다 . 화살표  위에  "30 분
내 " 처럼  표시한다 .
검증  오류는  해당  노드나  화살표에  빨간  테두리와  설명으로  표시한다 . 오류가  있으면  draft 로만  저
장된다 .
시뮬레이션은  대상 (IP) 과  기간을  넣으면  실제  히트로  평가해 , 성립한  노드는  색을  채우고  막힌  지점
에는  이유 ( 히트  없음 , 시간  초과 ) 를  보여  준다 .
노드  좌표는  그래프  JSON 의  pos 에  저장한다 . JSON 내보내기와  가져오기를  지원한다 .
순서도를  자유  형식  그림으로  저장하지  않는다 . 화면은  5 장의  그래프  JSON 만  읽고  쓴다 .
11. 백테스트 , 룰  수명주기 , 피드백
단일룰과  순서도는  모두  draft → silent → active  순서로만  운영에  들어가고 , 각  전환에는  통과  기
준이  있다 .
백테스트
단일룰 : 변환된  SQL 을  과거  기간에  대해  창  단위로  묶어  한  번에  실행하고 , 결과를
rule_hits_backtest 에  쓴다 . 기간  상한은  원본  보관  기간인  30 일이다 .
순서도 : 참조  단일룰을  먼저  백테스트한  뒤 , 그  히트에  실시간과  같은  evaluate  함수를  적용한다 .
평가  로직을  따로  만들지  않는다 .
결과 : 총  히트 · 경보  수 , 일별  분포 , 상위  대상  20 개 , 임계치  민감도 ( 시작값의  0.5 배 , 1 배 , 2 배일  때  건
수 ).
재현율  확인 : known_incidents 에  등록한  과거  사고가  히트나  경보로  잡혔는지  표시한다 .
백테스트  쿼리는  운영  평가와  다른  ClickHouse 사용자  프로필 ( 낮은  우선순위 , 메모리  상한 ) 로  실행
한다 .
피드백
분석가  판정이나  사고처리  시스템  종결  결과를  verdict 로  기록한다 .
상태 동작 다음  단계로  가는  기준
draft 평가  안  함 . 검증과  백테스트만  가능 백테스트  1 회  이상  완료
silent 실시간  평가 , 경보는  저장만  하고  전달  안
함
7 일  이상  운영 , 일평균  경보  수가  합의  상한  이
하
active 경보를  사고처리  시스템으로  전달 관리자  승인
disabled 평가  중지 , 이력  보존
시나리오  기반  탐지  엔진  설계안  (Claude Code 구현용 )
룰별  정탐률과  오탐  상위  키를  지표로  보여  준다 .
정탐률이  30 일간  20% 아래면  룰  목록에  조정  필요  표시를  띄운다 . 자동  비활성화는  하지  않는다 .
오탐  경보에서  바로  " 이  키를  예외  리스트에  추가 " 를  실행할  수  있다 .
사고  이력에서  룰  초안  만들기  ( 선택  모듈 )
입력 : 서술식  사고  이력  텍스트 .
처리 : 위협  유형 , 출발지 · 목적지  방향 , 포트 , 탐지  장비 , 탐지명 , 확정  근거를  정형  필드로  추출하고  가
장  가까운  룰  틀에  채워  draft  룰로  제안한다 .
폐쇄망  전제이므로  1 차  구현은  키워드 · 정규식  추출과  사람  검수로  한다 . 내부망  LLM 이  생기면  추출
기만  교체한다  (src/server/ extractors/  인터페이스 ).
시나리오  기반  탐지  엔진  설계안  (Claude Code 구현용 )
12. 비기능  요구사항
13. 구현  계획
6 개  마일스톤으로  나누고 , 각  마일스톤은  수용  기준을  테스트로  통과해야  다음으로  넘어간다 .
디렉터리  구조
scenario-engine/
  CLAUDE.md                  # 14 장의  작업  규칙
  docker-compose.yml         # server, web, mariadb, clickhouse( 개발 · 테스트용 )
  pyproject.toml
  clickhouse/
    source/                  # codlog.log_integrated_success_all 스키마  사본  ( 테스트  전용 , 샘플 
구분 기준
탐지  지연 이벤트  적재부터  경보  저장까지  95% 구간  3 분  이내  ( 평가
주기  60 초  기준 , 수집  지연  별도 )
단일룰  실행  시간 룰  1 개당  95% 구간  5 초  이내 , 상한  30 초 . 활성  단일룰  100
개를  1 분  주기로  처리
ClickHouse 부하 탐지  쿼리는  전용  사용자  프로필로  동시  실행  수와  메모리를
제한 . 모든  쿼리에  mgr_time 범위와  data_tp 조건을  건
다  ( 원본  정렬  키  (mgr_time, data_tp))
확장 탐지  서버는  상태가  없어  여러  대  실행  가능 . 룰  단위  잠금으
로  중복  실행  방지
가용성 탐지  서버  2 대  이상 , MariaDB 이중화 ( 복제  또는  Galera)
권장 . ClickHouse 가용성은  기존  구성에  따름
보관 원본  이벤트  30 일 ( 기존  설정 ), 히트  90 일 , 경보  1 년 , 감사  로
그  3 년  ( 기관  규정에  맞춰  조정 )
인증 · 권한 역할  기반  접근  제어 , 모든  변경을  감사  로그에  기록
SQL 안전성 필드명  허용  목록 , 값  타입  검증과  이스케이프 , 탐지  계정은
v_events  읽기와  rule_hits  쓰기만  허용
통신  보안 서비스  간  TLS, 접속  정보는  환경  변수  또는  비밀  저장소
배포 Docker Compose 기본 , 폐쇄망용  이미지 · 의존성  묶음  파
일  제공
관측 Prometheus 지표 : 룰별  실행  시간 · 히트  수 · 실패  수 , 평가
지연 , 순서도  평가  건수 , 전달  실패  수
시나리오  기반  탐지  엔진  설계안  (Claude Code 구현용 )
생성  SQL 포함 )
    views/                   # detect.v_events 뷰
    dictionaries/            # dict_orgs, dict_assets, dict_list_items 등
    tables/                  # rule_hits, rule_hits_backtest, peer_first_seen
  src/server/
    single_rule/
      schema.py              # 단일룰  정의  모델과  검증
      compiler.py            # 정의  → ClickHouse SQL
      runner.py              # 실행 , rule_runs 기록
    scenario/
      schema.py              # 그래프  모델과  검증
      evaluator.py           # evaluate(graph, hits, asset_tags) 순수  함수
    scheduler.py             # 주기  실행 , 잠금 , 따라잡기
    alerting.py              # 경보  생성 , 상향 , 억제
    adapters/case/           # 사고처리  시스템  webhook
    backtest/
    api/                     # FastAPI 라우터
    db/                      # MariaDB 모델 , 마이그레이션 (Alembic)
    ch.py                    # ClickHouse 클라이언트  래퍼  ( 시간  제한 , 프로필 )
  rules/builtin/
    single/                  # 단일룰  14 개  (YAML)
    scenarios/               # 순서도  7 개  (JSON)
  web/
    src/pages/single-rules/  # 양식  편집기 , SQL· 미리보기  패널
    src/pages/scenarios/     # 순서도  편집기  (Vue Flow)
    src/pages/alerts/
    src/pages/settings/
  tests/
    unit/
    scenarios/               # 순서도별  합성  이벤트와  기대  경보
    perf/
기술  스택
영역 선택 이유
서버 Python 3.12, FastAPI, Pydantic v2 정의  검증과  OpenAPI 자동  생성
이벤트 ·
히트
ClickHouse ( 기존 ), clickhouse-
connect
집계를  DB 가  수행 , 딕셔너리로  보강
설정 · 경
보
MariaDB 10.11 LTS, SQLAlchemy 2
(mariadb 커넥터 ), Alembic
버전  이력 , 잠금 , ClickHouse 딕셔너리  원본
스케줄링 서버  내장  루프  + MariaDB 행  잠금 (SKIP
LOCKED)
별도  큐나  Redis 없이  여러  대  실행
시나리오  기반  탐지  엔진  설계안  (Claude Code 구현용 )
마일스톤과  수용  기준
테스트  자료
순서도마다  events.jsonl ( 합성  이벤트 ) 과  expected.yaml ( 기대  히트와  경보의  ID, 대상 , 등
급 ) 을  둔다 .
영역 선택 이유
관리  화
면
Vue 3, TypeScript, Vite, Vue Flow 끌어다  놓는  순서도  편집 , 노드  좌표  저장
테스트 pytest, testcontainers (ClickHouse,
MariaDB), Playwright
실제  ClickHouse 로  SQL 검증 , 순서도  편집
기  화면  테스트
단계 산출물 수용  기준
M1 ClickHouse
기반
스키마  파일로  띄운  테스트용
codlog.log_integrated_success_all ,
detect.v_events  뷰 , 딕셔너리  5 종 ,
rule_hits , 유형별  필드  채움  비율  조회
쿼리
스키마  파일의  샘플  생성  SQL 로  데이터
를  넣고 , 보강  컬럼 ( 방향 , 자산  태그 , 유해
IP, 시그니처  분류 ) 이  기대값과  일치 . 기
관  대역이  겹치는  두  기관에서  방향  판정
이  섞이지  않음
M2 단일룰 정의  검증 , SQL 컴파일러 , 실행기 , 기본  단
일룰  14 개
14 개  룰이  합성  이벤트에서  기대  히트를
정확히  생성 . 잘못된  정의  20 종이  원인
메시지와  함께  거부됨 . SQL 주입  시도
입력이  모두  거부됨 . 모든  생성  쿼리에
mgr_time · data_tp  조건이  있음
M3 순서도  평가 그래프  검증 , evaluate , 기본  순서도  7 개 tests/scenarios/ 의  7 개  순서도에
서  기대  경보가  1 건씩  발생 . 정상  트래픽
표본에서  경보  0 건 . 잘못된  그래프  15 종
거부
M4 탐지  서버 스케줄러 , 경보  생성 · 상향 · 억제 , 사고처리
webhook, 판정  수신
서버  2 대  동시  실행  시  중복  실행과  중복
경보  없음 . 서버  중단  후  따라잡기  테스트
통과
M5 API 와  백테
스트
REST API, 권한 , 감사  로그 , 미리보기 , 시
뮬레이션 , 백테스트
OpenAPI 계약  테스트  통과 . 같은  데이
터에서  백테스트와  실시간  평가의  경보
가  일치
M6 관리  화면과
배포
단일룰  편집기 , 순서도  편집기 , 경보  상세 ,
폐쇄망  배포  묶음
화면에서  단일룰  2 개를  만들고  순서도로
이어  silent  반영까지  코드  수정  없이
완료  (Playwright). 성능  기준  충족
시나리오  기반  탐지  엔진  설계안  (Claude Code 구현용 )
각  순서도에  반례를  최소  3 개  넣는다 : 임계치  바로  아래 , 허용  시간을  벗어난  경우 , 예외  리스트에  해
당하는  경우 .
실제  기관명 , 담당자명 , 실제  IP 는  테스트  자료에  넣지  않는다 . 문서용  대역 ( 192.0.2.0/24 ,
198.51.100.0/24 ) 과  사설  대역만  쓴다 .
14. Claude Code 작업  규칙
아래  내용을  저장소의  CLAUDE.md 로  넣고 , 이  설계안은  docs/design.md 로  함께  둔다 .
# 프로젝트 : ClickHouse 기반  시나리오  탐지  서버
설계  기준은  docs/design.md 이다 . 설계와  다르게  구현해야  하면  먼저  이유를  설명하고  확인을  받
는다 .
## 작업  순서
- docs/design.md 13 장의  마일스톤  M1 → M6 순서로  진행한다 .
- 마일스톤마다  수용  기준  테스트를  먼저  작성하고 , 통과한  뒤  다음으로  넘어간다 .
- 한  마일스톤이  끝나면  변경  요약과  남은  미결  사항을  보고하고  멈춘다 .
## 설계  원칙
- 탐지  로직을  코드에  넣지  않는다 . 포트  번호 , 임계치 , 탐지명은  단일룰  정의와  리스트에만  둔다 .
- 구조는  두  층이다 . 단일룰 (ClickHouse SQL 로  변환 , 히트  생성 ) 과  순서도 ( 히트를  조합해  경보  생
성 ). 순서도  평가에서  v_events 를  직접  조회하지  않는다 .
- 집계는  ClickHouse 가  한다 . 이벤트를  서버로  가져와  파이썬에서  세지  않는다 . 단일룰  실행은 
INSERT ... SELECT 한  문장이다 .
- 서버는  메모리  상태를  갖지  않는다 . 중간  결과는  rule_hits, 진행  상태는  MariaDB 에  둔다 .
- scenario/evaluator.py 의  evaluate 는  입출력만  있는  순수  함수다 . DB 접근을  넣지  않는
다 . 실시간 , 백테스트 , 화면  시뮬레이션이  같은  함수를  쓴다 .
- 새  시나리오가  코드  수정을  요구하면  그  시나리오가  아니라  일반  기능 ( 연산자 , 집계  함수 , 노드  유
형 ) 으로  추가한다 .
- 모든  히트와  경보는  org_id + entity 단위다 . 기관  간  데이터를  섞지  않는다 .
## SQL 생성  규칙
- 사용자가  입력한  문자열을  SQL 에  직접  잇지  않는다 . 필드명은  허용  목록 , 값은  타입  검증  후  이스
케이프  또는  쿼리  파라미터 .
- 컴파일러  출력은  스냅샷  테스트로  고정하고 , 테스트용  ClickHouse 에서  실제  실행해  검증한다 .
- 모든  쿼리에  max_execution_time 과  결과  행  제한을  건다 .
- 원본  이벤트는  codlog.log_integrated_success_all 다  (clickhouse/source 참고 ). 룰은 
detect.v_events 뷰만  참조하고 , 원본  매핑은  clickhouse/views 에서만  바꾼다 .
- 모든  탐지  쿼리는  mgr_time 범위와  data_tp 조건을  먼저  건다  ( 원본  정렬  키 ). 건수는 
count() 가  아니라  sum(event_count) 로  센다 .
- 데이터  유형마다  비어  있는  필드가  다르다  (design.md 3 장  표 ). 포트  조건은  FIREWALL, IPS, 
TMS, DDos 에서만  유효하다 .
- 스키마  파일의  샘플  INSERT 와  mv_security_log_live 는  테스트  환경에서만  쓴다 . 운영 
ClickHouse 에서  실행하지  않는다 .
시나리오  기반  탐지  엔진  설계안  (Claude Code 구현용 )
## 관리  화면  규칙
- 순서도  편집기는  Vue Flow 로  만들고 , 서버와는  design.md 5 장의  그래프  JSON 만  주고받는다 .
- 검증은  서버가  최종  판단한다 . 화면의  검증은  편의  기능이다 .
- 단일룰  양식의  필드와  연산자  목록은  GET /meta/fields 에서  받는다 . 화면에  하드코딩하지  않는
다 .
## 코드  규칙
- Python 3.12, 타입  힌트  필수 , ruff 와  mypy(strict) 통과 . 프런트엔드는  TypeScript 
strict, eslint 통과 .
- 시간에  의존하는  코드는  시계를  주입받는다 .
- RDBMS 는  MariaDB 10.11 이상이다 . PostgreSQL 전용  기능 ( 배열  컬럼 , jsonb 연산자 , inet 
타입  등 ) 을  쓰지  않는다 . 여러  값은  하위  테이블로  둔다 .
- MariaDB 변경은  Alembic 마이그레이션으로만 , ClickHouse 변경은  clickhouse/ 아래  번호 
붙은  SQL 파일로만  한다 .
- 외부  네트워크  호출을  추가하지  않는다  ( 폐쇄망  운영 ). 의존성  추가  시  오프라인  설치  목록을  갱신
한다 .
## 보안과  데이터
- 실제  기관명 , 담당자명 , 실제  IP 를  코드 , 테스트 , 문서에  넣지  않는다 .
- 접속  정보는  환경  변수로만  받는다 . 저장소에  커밋하지  않는다 .
- 운영  ClickHouse 에  대한  DDL( 테이블  생성 · 변경 ) 은  직접  실행하지  말고  SQL 파일로  만들어  확인
을  받는다 .
## 확인이  필요한  항목  ( 추측으로  구현하지  않는다 )
- 운영  데이터의  유형별  필드  채움  비율  ( 특히  IDS, UTM, WAF 포트 ), ClickHouse 버전과  클러
스터  구성
- inst_id 와  산하기관  대응 , 기관별  내부  대역
- 사고처리  시스템의  경보  등록  API
- 실제  EPS
## 명령
- 테스트 : pytest
- 순서도  테스트만 : pytest tests/scenarios
- 화면  테스트 : npx playwright test
- 실행 : docker compose up
Claude Code 에  처음  줄  지시문  예시
docs/design.md 와  CLAUDE.md 를  읽고  M1 을  구현해  줘 .
clickhouse/source 의  스키마로  테스트용  ClickHouse 를  띄우고 , detect.v_events 뷰 , 딕셔
너리 , rule_hits 테이블을  만들어 .
유형별  필드  채움  비율을  확인하는  쿼리도  작성해 .
수용  기준  테스트를  먼저  쓰고 , 끝나면  변경  요약과  미결  사항을  보고해 .
시나리오  기반  탐지  엔진  설계안  (Claude Code 구현용 )