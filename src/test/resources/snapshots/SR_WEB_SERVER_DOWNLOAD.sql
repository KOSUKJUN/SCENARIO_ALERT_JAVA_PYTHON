INSERT INTO detect.rule_hits
  (hit_bucket, rule_id, rule_version, org_id, entity_type, entity,
   first_seen, last_seen, value, threshold, sample_event_ids, run_id, win_to)
SELECT
  toStartOfInterval({win_to:DateTime64(3)}, INTERVAL 600 SECOND) AS hit_bucket,
  {p0:String} AS rule_id, {rule_version:UInt32} AS rule_version, org_id, 'host' AS entity_type,
  src_ip AS entity,
  min(event_time) AS first_seen, max(event_time) AS last_seen,
  toFloat64(sum(event_count)) AS value,
  if(dictGetOrDefault('detect.dict_org_rule_params', 'threshold', tuple(org_id, {p0:String}), -1.) < 0, {p5:Float64}, dictGetOrDefault('detect.dict_org_rule_params', 'threshold', tuple(org_id, {p0:String}), -1.)) AS threshold,
  groupArray(20)(event_id) AS sample_event_ids,
  {run_id:UUID} AS run_id, {win_to:DateTime64(3)} AS win_to
FROM detect.v_events
WHERE mgr_time >= {win_from:DateTime64(3)} AND mgr_time < {win_to:DateTime64(3)}
  AND data_tp IN ('IDS', 'IPS', 'TMS', 'UTM')
  AND src_ip != ''
  AND dictGetOrDefault('detect.dict_org_rule_params', 'enabled', tuple(org_id, {p0:String}), toUInt8(1)) = 1
  AND ((net_direction = {p1:String}) AND has(src_asset_tags, {p2:String}) AND (multiSearchAnyCaseInsensitiveUTF8(search_text, {p3:Array(String)})))
  AND (NOT has(['', org_id], dictGetOrDefault('detect.dict_list_items', 'scope', tuple({p4:String}, lower(toString(src_ip))), '-')))
GROUP BY org_id, entity
HAVING value >= threshold
LIMIT 100000
-- params
-- p0 = 'SR_WEB_SERVER_DOWNLOAD'
-- p1 = 'outbound'
-- p2 = 'webserver'
-- p3 = ['wget/', 'curl/']
-- p4 = 'false_positive_hosts'
-- p5 = 1.0
