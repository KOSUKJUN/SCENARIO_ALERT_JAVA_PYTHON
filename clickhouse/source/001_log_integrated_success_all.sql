-- 테스트 전용 (CH_MANAGE_SOURCE=true): 원본 로그 테이블 사본. 운영·공용 ClickHouse 에서는 이미 있으므로 실행하지 않는다.
-- 대상 ClickHouse(25.3)의 codlog.log_integrated_success_all SHOW CREATE TABLE 결과를 그대로 옮겼다 (2026-11-21).
-- 단일 MergeTree 테이블이다 (Distributed 아님). 수집 파이프라인이 넣고, 이 시스템은 읽기만 한다.
--
-- 컬럼 의미 (탐지 뷰 detect.v_events 가 이 이름을 탐지 컬럼으로 바꾼다)
--   _event_cd 이벤트 ID, _collect_time 수집 시각(평가 시간축), _data_type 데이터 유형, _asset_id 로그 수집원
--   (기관은 MariaDB log_sources 매핑으로 정한다), _raw_log 원문, _parser_* / _origin_topic / _parser_node 수집 경로
--   fields(JSON): 그 밖의 장비 필드 (count, risk, url_method, action, product, payload ... 값은 문자열)
CREATE DATABASE IF NOT EXISTS codlog;

CREATE TABLE IF NOT EXISTS codlog.log_integrated_success_all
(
    `_event_cd` String,
    `_parser_cd` LowCardinality(String),
    `_data_type` LowCardinality(String),
    `_asset_id` LowCardinality(String),
    `_collect_time` DateTime64(3, 'Asia/Seoul'),
    `_raw_log` String,
    `_origin_topic` LowCardinality(String),
    `_parser_node` LowCardinality(String),
    `event_time` Nullable(DateTime64(3, 'Asia/Seoul')),
    `event_type` LowCardinality(Nullable(String)),
    `origin_ip` Nullable(IPv6),
    `origin_id` Nullable(String),
    `origin_name` Nullable(String),
    `src_ip` Nullable(IPv6),
    `src_port` Nullable(UInt16),
    `src_iso` LowCardinality(Nullable(String)),
    `src_lat` Nullable(String),
    `src_lng` Nullable(String),
    `dst_ip` Nullable(IPv6),
    `dst_port` Nullable(UInt16),
    `protocol` LowCardinality(Nullable(String)),
    `attack` Nullable(String),
    `category` LowCardinality(Nullable(String)),
    `method` Nullable(String),
    `fields` JSON,
    `_init_build_flag` UInt8 DEFAULT 1
)
ENGINE = MergeTree
PARTITION BY toYYYYMM(_collect_time)
ORDER BY (_collect_time, _parser_cd, _asset_id)
TTL toDateTime(_collect_time) + toIntervalDay(30)
SETTINGS index_granularity = 8192;
