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

CREATE MATERIALIZED VIEW IF NOT EXISTS detect.mv_peer_first_seen TO detect.peer_first_seen AS
SELECT
    toString(inst_id) AS org_id,
    replaceRegexpOne(IPv6NumToString(assumeNotNull(s_info)), '^::ffff:', '') AS src_ip,
    replaceRegexpOne(IPv6NumToString(assumeNotNull(d_info)), '^::ffff:', '') AS dst_ip,
    min(mgr_time) AS first_seen
FROM codlog.log_integrated_success_all
WHERE isNotNull(s_info) AND isNotNull(d_info)
GROUP BY org_id, src_ip, dst_ip;
