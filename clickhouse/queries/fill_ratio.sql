-- 유형별 필드 채움 비율 (설계안 3장 표를 운영 데이터로 확인하는 쿼리)
-- 기간은 최근 1일. 운영에서는 읽기 전용 계정으로 실행한다.
-- 운영 원본(default.log_integrated_success_all): 공통 필드는 Nullable 컬럼, 그 밖의 필드는 fields(JSON) 의 키 유무로 본다.
SELECT
    _data_type                                                                AS data_tp,
    count()                                                                   AS rows,
    uniqExact(_asset_id)                                                      AS log_sources,
    round(countIf(isNotNull(src_ip)) / rows, 3)                               AS src_ip,
    round(countIf(isNotNull(dst_ip)) / rows, 3)                               AS dst_ip,
    round(countIf(isNotNull(src_port)) / rows, 3)                             AS src_port,
    round(countIf(isNotNull(dst_port)) / rows, 3)                             AS dst_port,
    round(countIf(isNotNull(protocol)) / rows, 3)                             AS protocol,
    round(countIf(isNotNull(method)) / rows, 3)                               AS method,
    round(countIf(isNotNull(attack)) / rows, 3)                               AS attack,
    round(countIf(isNotNull(event_time)) / rows, 3)                           AS event_time,
    round(countIf(isNotNull(event_type)) / rows, 3)                           AS event_type,
    round(countIf(isNotNull(category)) / rows, 3)                             AS category,
    round(countIf(isNotNull(fields.count)) / rows, 3)                         AS f_count,
    round(countIf(isNotNull(fields.action) OR isNotNull(fields.maction)) / rows, 3) AS f_action,
    round(countIf(isNotNull(fields.mstatus) OR isNotNull(fields.status)) / rows, 3) AS f_status,
    round(countIf(isNotNull(fields.direction) OR isNotNull(fields.mdirection)) / rows, 3) AS f_direction,
    round(countIf(isNotNull(fields.risk)) / rows, 3)                          AS f_risk,
    round(countIf(isNotNull(fields.payload)) / rows, 3)                       AS f_payload,
    round(countIf(isNotNull(fields.uri)) / rows, 3)                           AS f_uri
FROM default.log_integrated_success_all
WHERE _collect_time >= now() - INTERVAL 1 DAY
GROUP BY _data_type
ORDER BY _data_type;

-- fields 에 실제로 들어오는 키 (탐지 뷰가 읽는 키와 비교)
-- SELECT arrayJoin(JSONAllPaths(fields)) AS path, count() FROM default.log_integrated_success_all
-- WHERE _collect_time >= now() - INTERVAL 1 DAY GROUP BY path ORDER BY 2 DESC;
