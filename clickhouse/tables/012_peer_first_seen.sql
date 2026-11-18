-- "처음 보는 목적지" 조건용: (org_id, src_ip, dst_ip) 별 최초 관측 시각 (mgr_time 기준)
CREATE TABLE IF NOT EXISTS detect.peer_first_seen
(
    org_id     LowCardinality(String),
    src_ip     String,
    dst_ip     String,
    first_seen SimpleAggregateFunction(min, DateTime64(3, 'Asia/Seoul'))
)
ENGINE = AggregatingMergeTree
ORDER BY (org_id, src_ip, dst_ip);

-- 이 표를 채우는 MV 는 views/031_mv_peer_first_seen.sql (로그 수집원 딕셔너리를 쓰므로 딕셔너리 뒤에 만든다).
