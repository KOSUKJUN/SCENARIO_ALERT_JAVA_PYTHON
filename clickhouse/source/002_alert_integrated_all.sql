-- 테스트 전용 (CH_MANAGE_SOURCE=true): 경보 테이블 사본. 운영·공용 ClickHouse 에서는 이미 있으므로 실행하지 않는다.
-- 대상 ClickHouse(25.3)의 codlog.alert_integrated_all SHOW CREATE TABLE 결과를 그대로 옮겼다 (2026-11-21).
-- 같은 날 대상 서버에서 group_cd·group_nm 이 추가되고 grp_cd 가 rull_grp_cd 로 이름이 바뀌었다 (이미 만든 사본은 003 이 바꾼다).
-- 이 시스템의 경보 본문은 여기에만 있다 (_data_type 'SCENARIO' = 시나리오 경보, 'EVENT_MODULE' = 이벤트 탐지모듈 단독 경보).
-- 경로·억제 상태·판정·전달 상태·ATT&CK·D3FEND 는 MariaDB alert_state 에 _alert_cd 와 같은 ID 로 둔다.
-- ReplacingMergeTree(_collect_time): 같은 정렬 키(window_ms, _data_type, attack, risk)는 가장 늦게 넣은 행만 남는다.
CREATE DATABASE IF NOT EXISTS codlog;

CREATE TABLE IF NOT EXISTS codlog.alert_integrated_all
(
    `_alert_cd` String COMMENT '경보 ID',
    `_collect_time` DateTime64(3, 'Asia/Seoul') DEFAULT now64(3) COMMENT '생성·갱신 시각 (중복 행 정리 기준)',
    `_data_type` LowCardinality(String) COMMENT '로그 유형',
    `event_time` DateTime64(3, 'Asia/Seoul') COMMENT '발생 일시 (최근)',
    `event_sdt` DateTime64(3, 'Asia/Seoul') COMMENT '최초 발생',
    `event_edt` DateTime64(3, 'Asia/Seoul') COMMENT '최근 발생',
    `window_ms` UInt64 COMMENT '1시간 구간 시작(ms)',
    `attack` String COMMENT '공격명 (경보 제목)',
    `risk` LowCardinality(String) COMMENT '위험도 (= 심각도)',
    `max_lvl` Nullable(UInt8) COMMENT '최대 수준',
    `rull_grp_cd` LowCardinality(String) DEFAULT '' COMMENT '룰 그룹 코드',
    `group_cd` LowCardinality(String) DEFAULT '' COMMENT 'CODPRO그룹코드',
    `group_nm` LowCardinality(String) DEFAULT '' COMMENT 'CODPRO그룹명',
    `count` UInt64 COMMENT '근거 이벤트 수',
    `src_ip` Nullable(IPv6) COMMENT '출발지 IP',
    `src_port` Nullable(UInt16) COMMENT '출발지 포트',
    `src_iso` LowCardinality(Nullable(String)) COMMENT '출발지 국가 코드',
    `src_lat` Nullable(String) COMMENT '위도',
    `src_lng` Nullable(String) COMMENT '경도',
    `city` Nullable(String) COMMENT '도시',
    `dst_ip` Nullable(IPv6) COMMENT '목적지 IP',
    `dst_port` Nullable(UInt16) COMMENT '목적지 포트',
    `action` LowCardinality(String) DEFAULT '' COMMENT '대응 (허용/차단 등)',
    `product` LowCardinality(String) DEFAULT '' COMMENT '탐지 장비',
    `origin_ip` Nullable(IPv6) COMMENT '에이전트 IP',
    `origin_id` Nullable(String) COMMENT '에이전트 ID',
    `distance` Nullable(UInt32) COMMENT '거리',
    `tmuser` Nullable(String) COMMENT '룰 생성자',
    `set_id` Nullable(UInt32) COMMENT '세트 ID',
    `fields` JSON COMMENT '그 밖의 값 (th_map_data tmp1~13 · jtmp1/2 등)'
)
ENGINE = ReplacingMergeTree(_collect_time)
PARTITION BY toYYYYMM(event_sdt)
ORDER BY (window_ms, _data_type, attack, risk)
TTL toDateTime(event_sdt) + toIntervalDay(30)
SETTINGS index_granularity = 8192
COMMENT '경보 (탐지 이벤트를 1시간·로그 유형·공격명·위험도로 묶은 것)';
