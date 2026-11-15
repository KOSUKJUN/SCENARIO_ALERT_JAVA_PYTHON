-- 테스트 전용: codlog.log_integrated_success_all 스키마 사본.
-- 운영 스키마 파일이 제공되지 않아 설계안 3장에 나온 필드만으로 구성했다 (65개 공통 필드 중 탐지에 쓰는 것).
-- 운영 ClickHouse 에서 실행하지 않는다.
CREATE DATABASE IF NOT EXISTS codlog;

CREATE TABLE IF NOT EXISTS codlog.log_integrated_success_all
(
    event_id     String,
    mgr_time     DateTime64(3, 'Asia/Seoul'),
    event_time   Nullable(DateTime64(3, 'Asia/Seoul')),
    inst_id      LowCardinality(String),
    data_tp      LowCardinality(String),
    log          LowCardinality(String) DEFAULT '',
    sublog       LowCardinality(String) DEFAULT '',
    product      LowCardinality(String) DEFAULT '',
    s_info       Nullable(IPv6),
    d_info       Nullable(IPv6),
    s_port       Nullable(UInt16),
    d_port       Nullable(UInt16),
    protocol     LowCardinality(String) DEFAULT '',
    action       LowCardinality(String) DEFAULT '',
    maction      LowCardinality(String) DEFAULT '',
    mstatus      LowCardinality(String) DEFAULT '',
    direction    LowCardinality(String) DEFAULT '',
    mdirection   LowCardinality(String) DEFAULT '',
    s_country    LowCardinality(String) DEFAULT '',
    d_country    LowCardinality(String) DEFAULT '',
    method       String DEFAULT '',
    attack       String DEFAULT '',
    risk         LowCardinality(String) DEFAULT '',
    count        Nullable(UInt32),
    uri          String DEFAULT '',
    url_method   LowCardinality(String) DEFAULT '',
    payload      String DEFAULT '',
    search_text  String DEFAULT lower(concat_ws(' ', method, attack, uri, payload)),
    INDEX idx_s_info s_info TYPE bloom_filter GRANULARITY 4,
    INDEX idx_d_info d_info TYPE bloom_filter GRANULARITY 4,
    INDEX idx_attack attack TYPE bloom_filter GRANULARITY 4,
    INDEX idx_risk risk TYPE set(100) GRANULARITY 4,
    INDEX idx_action action TYPE set(100) GRANULARITY 4,
    INDEX idx_search search_text TYPE ngrambf_v1(4, 65536, 3, 0) GRANULARITY 4
)
ENGINE = MergeTree
PARTITION BY toYYYYMMDD(mgr_time)
ORDER BY (mgr_time, data_tp)
TTL toDateTime(mgr_time) + INTERVAL 30 DAY;
