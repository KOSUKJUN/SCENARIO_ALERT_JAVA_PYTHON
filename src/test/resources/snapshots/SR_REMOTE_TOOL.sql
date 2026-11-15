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
  AND data_tp IN ('FIREWALL', 'IDS', 'IPS', 'TMS', 'UTM')
  AND src_ip != ''
  AND dictGetOrDefault('detect.dict_org_rule_params', 'enabled', tuple(org_id, {p0:String}), toUInt8(1)) = 1
  AND ((signature_category = {p1:String}) OR ((net_direction = {p2:String}) AND has({p3:Array(Int64)}, ifNull(dst_port, -1))))
  AND (NOT has(['', org_id], dictGetOrDefault('detect.dict_list_items', 'scope', tuple({p4:String}, lower(toString(src_ip))), '-')))
GROUP BY org_id, entity
HAVING value >= threshold
LIMIT 100000
-- params
-- p0 = 'SR_REMOTE_TOOL'
-- p1 = 'remote_tool'
-- p2 = 'outbound'
-- p3 = [6568, 7070, 5938]
-- p4 = 'false_positive_hosts'
-- p5 = 1.0
