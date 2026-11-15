-- 유형별 필드 채움 비율 (설계안 3장 표를 운영 데이터로 확인하는 쿼리)
-- 기간은 최근 1일. 운영에서는 읽기 전용 계정으로 실행한다.
SELECT
    data_tp,
    count()                                                   AS rows,
    round(countIf(isNotNull(s_info)) / rows, 3)               AS s_info,
    round(countIf(isNotNull(d_info)) / rows, 3)               AS d_info,
    round(countIf(isNotNull(s_port)) / rows, 3)               AS s_port,
    round(countIf(isNotNull(d_port)) / rows, 3)               AS d_port,
    round(countIf(direction != '' OR mdirection != '') / rows, 3) AS direction,
    round(countIf(method != '') / rows, 3)                    AS method,
    round(countIf(attack != '') / rows, 3)                    AS attack,
    round(countIf(action != '' OR maction != '') / rows, 3)   AS action,
    round(countIf(mstatus != '') / rows, 3)                   AS mstatus,
    round(countIf(isNotNull(count)) / rows, 3)                AS count,
    round(countIf(payload != '') / rows, 3)                   AS payload,
    round(countIf(uri != '') / rows, 3)                       AS uri,
    round(countIf(isNotNull(event_time)) / rows, 3)           AS event_time
FROM codlog.log_integrated_success_all
WHERE mgr_time >= now() - INTERVAL 1 DAY
GROUP BY data_tp
ORDER BY data_tp;
