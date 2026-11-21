-- 탐지 전용 뷰. 단일룰은 이 뷰의 컬럼명만 참조한다. 원본 구조가 바뀌면 이 파일만 고친다.
-- 안쪽 SELECT: 운영 원본(codlog.log_integrated_success_all, ClickHouse 25.3)을 탐지 컬럼 이름으로 펼친다.
--   _event_cd → event_id, _collect_time → mgr_time(평가 시간축), _data_type → data_tp,
--   _asset_id(로그 수집원) → 기관: MariaDB log_sources 매핑(dict_log_sources). 매핑 없으면 'UNASSIGNED'.
--   fields 는 JSON 타입: ifNull(toString(fields.키), '') 로 읽는다 (값이 문자열·숫자·없음 어느 것이어도 문자열).
--   count 도 fields 안에 있다 (없으면 1건).
-- 바깥 SELECT: 정규화와 보강. 출력 컬럼은 이전과 같다 (+ log_source).
CREATE OR REPLACE VIEW detect.v_events AS
SELECT
    event_id,
    mgr_time,                                                   -- 평가 시간축 (수집 시각)
    coalesce(event_time, mgr_time)               AS event_time,  -- 장비 시각 (표시·근거용)
    toString(inst_id)                            AS org_id,
    data_tp,
    log_source,                                                  -- 로그 수집원 (_asset_id)
    log, sublog, product,
    s_info, d_info,                                              -- 원본 IPv6
    if(isNull(s_info), '', replaceRegexpOne(IPv6NumToString(assumeNotNull(s_info)), '^::ffff:', '')) AS src_ip,
    if(isNull(d_info), '', replaceRegexpOne(IPv6NumToString(assumeNotNull(d_info)), '^::ffff:', '')) AS dst_ip,
    s_port                                       AS src_port,    -- Nullable
    d_port                                       AS dst_port,    -- Nullable
    lower(protocol)                              AS protocol,
    lower(multiIf(action != '', action, maction != '', maction, mstatus != '', mstatus, status)) AS action,
    s_country                                    AS src_country,
    d_country                                    AS dst_country,
    method                                       AS signature_name,
    attack,
    risk,
    toUInt64(if(cnt = 0, 1, cnt))                AS event_count,
    uri, url_method, payload,
    lower(concat_ws(' ', method, attack, uri, payload)) AS search_text,
    event_type, category, origin_id, origin_name,
    if(isNull(o_info), '', replaceRegexpOne(IPv6NumToString(assumeNotNull(o_info)), '^::ffff:', '')) AS origin_ip,

    -- 보강: 방향 (장비 값 우선, 없으면 기관 내부 대역으로 판정). 기관별 대역이 겹칠 수 있어 기관 ID로 목록을 꺼낸다.
    arrayFilter(x -> x != '', splitByChar(',',
        dictGetOrDefault('detect.dict_orgs', 'internal_cidrs', tuple(toString(inst_id)), ''))) AS org_cidrs,
    if(src_ip = '', 0, arrayExists(c -> isIPAddressInRange(src_ip, c), org_cidrs)) AS src_internal,
    if(dst_ip = '', 0, arrayExists(c -> isIPAddressInRange(dst_ip, c), org_cidrs)) AS dst_internal,
    multiIf(direction != '', lower(direction),
            mdirection != '', lower(mdirection),
            src_internal AND dst_internal, 'internal',
            src_internal, 'outbound',
            dst_internal, 'inbound',
            'external') AS net_direction,

    -- 보강: 자산 태그, 유해 IP, 시그니처 분류
    arrayFilter(x -> x != '', splitByChar(',',
        dictGetOrDefault('detect.dict_assets', 'tags', tuple(toString(inst_id), src_ip), ''))) AS src_asset_tags,
    arrayFilter(x -> x != '', splitByChar(',',
        dictGetOrDefault('detect.dict_assets', 'tags', tuple(toString(inst_id), dst_ip), ''))) AS dst_asset_tags,
    if(src_ip = '', 0, dictHas('detect.dict_threat_ip', tuple(src_ip))) AS src_ti_hit,
    if(dst_ip = '', 0, dictHas('detect.dict_threat_ip', tuple(dst_ip))) AS dst_ti_hit,
    dictGetOrDefault('detect.dict_signature_map', 'category', tuple(toString(data_tp), lower(method)),
        dictGetOrDefault('detect.dict_signature_map', 'category', tuple('*', lower(method)), '')) AS signature_category
FROM
(
    SELECT
        _event_cd                                        AS event_id,
        _collect_time                                    AS mgr_time,
        event_time,
        _data_type                                       AS data_tp,
        toString(_asset_id)                              AS log_source,
        dictGetOrDefault('detect.dict_log_sources', 'org_id', tuple(toString(_asset_id)), 'UNASSIGNED') AS inst_id,
        ifNull(event_type, '')                           AS event_type,
        ifNull(category, '')                             AS category,
        ifNull(method, '')                               AS method,
        ifNull(attack, '')                               AS attack,
        ifNull(protocol, '')                             AS protocol,
        ifNull(origin_id, '')                            AS origin_id,
        ifNull(origin_name, '')                          AS origin_name,
        src_ip                                           AS s_info,
        dst_ip                                           AS d_info,
        origin_ip                                        AS o_info,
        src_port                                         AS s_port,
        dst_port                                         AS d_port,
        ifNull(src_iso, '')                              AS s_country,
        toUInt64OrZero(ifNull(toString(fields.count), '')) AS cnt,
        ifNull(toString(fields.dst_iso), '')             AS d_country,
        ifNull(toString(fields.log), '')                 AS log,
        ifNull(toString(fields.sublog), '')              AS sublog,
        ifNull(toString(fields.product), '')             AS product,
        ifNull(toString(fields.action), '')              AS action,
        ifNull(toString(fields.maction), '')             AS maction,
        ifNull(toString(fields.mstatus), '')             AS mstatus,
        ifNull(toString(fields.status), '')              AS status,
        ifNull(toString(fields.direction), '')           AS direction,
        ifNull(toString(fields.mdirection), '')          AS mdirection,
        ifNull(toString(fields.risk), '')                AS risk,
        ifNull(toString(fields.uri), '')                 AS uri,
        ifNull(toString(fields.url_method), '')          AS url_method,
        ifNull(toString(fields.payload), '')             AS payload
    FROM codlog.log_integrated_success_all
);
