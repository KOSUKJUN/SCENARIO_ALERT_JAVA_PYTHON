-- detect.peer_first_seen 을 채우는 MV. 기관을 로그 수집원 딕셔너리(020)로 정하므로 딕셔너리 뒤에 만든다
-- (ClickHouse 25.3 은 MV 를 만들 때 딕셔너리가 있는지 확인한다). source/000 이 init 때마다 지우고 여기서 다시 만든다.
-- 원본 테이블(codlog.log_integrated_success_all, MergeTree)에 건다: 들어오는 행마다 동작한다.
-- 기관은 적재 시점의 로그 수집원 매핑(dict_log_sources)으로 정한다 (나중에 매핑을 바꿔도 이미 집계한 행은 그대로).
CREATE MATERIALIZED VIEW IF NOT EXISTS detect.mv_peer_first_seen TO detect.peer_first_seen AS
SELECT
    dictGetOrDefault('detect.dict_log_sources', 'org_id', tuple(toString(asset)), 'UNASSIGNED') AS org_id,
    replaceRegexpOne(IPv6NumToString(s_info), '^::ffff:', '') AS src_ip,
    replaceRegexpOne(IPv6NumToString(d_info), '^::ffff:', '') AS dst_ip,
    min(t) AS first_seen
FROM
(
    SELECT _asset_id AS asset, _collect_time AS t, assumeNotNull(src_ip) AS s_info, assumeNotNull(dst_ip) AS d_info
    FROM codlog.log_integrated_success_all
    WHERE isNotNull(src_ip) AND isNotNull(dst_ip)
)
GROUP BY org_id, src_ip, dst_ip;
