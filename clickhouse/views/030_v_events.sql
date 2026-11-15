-- 탐지 전용 뷰. 단일룰은 이 뷰의 컬럼명만 참조한다. 원본 구조가 바뀌면 이 파일만 고친다.
CREATE OR REPLACE VIEW detect.v_events AS
SELECT
    event_id,
    mgr_time,                                                   -- 평가 시간축 (수집 시각)
    coalesce(event_time, mgr_time)               AS event_time,  -- 장비 시각 (표시·근거용)
    toString(inst_id)                            AS org_id,
    data_tp,                                                     -- 정렬 키 그대로 (인덱스 사용)
    log, sublog, product,
    s_info, d_info,                                              -- 원본 IPv6 (인덱스용)
    if(isNull(s_info), '', replaceRegexpOne(IPv6NumToString(assumeNotNull(s_info)), '^::ffff:', '')) AS src_ip,
    if(isNull(d_info), '', replaceRegexpOne(IPv6NumToString(assumeNotNull(d_info)), '^::ffff:', '')) AS dst_ip,
    s_port                                       AS src_port,    -- Nullable
    d_port                                       AS dst_port,    -- Nullable
    lower(protocol)                              AS protocol,
    lower(multiIf(action != '', action, maction != '', maction, mstatus)) AS action,
    s_country                                    AS src_country,
    d_country                                    AS dst_country,
    method                                       AS signature_name,
    attack,
    risk,
    toUInt64(ifNull(count, 1))                   AS event_count,
    uri, url_method, payload, search_text,

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
FROM codlog.log_integrated_success_all;
