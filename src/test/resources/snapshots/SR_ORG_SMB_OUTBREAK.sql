INSERT INTO detect.rule_hits
  (hit_bucket, rule_id, rule_version, org_id, entity_type, entity,
   first_seen, last_seen, value, threshold, sample_event_ids, run_id, win_to)
SELECT
  toStartOfInterval({win_to:DateTime64(3)}, INTERVAL 3600 SECOND) AS hit_bucket,
  {p0:String} AS rule_id, {rule_version:UInt32} AS rule_version, org_id, 'org' AS entity_type,
  org_id AS entity,
  min(event_time) AS first_seen, max(event_time) AS last_seen,
  toFloat64(uniqExact(src_ip)) AS value,
  if(dictGetOrDefault('detect.dict_org_rule_params', 'threshold', tuple(org_id, {p0:String}), -1.) < 0, {p4:Float64}, dictGetOrDefault('detect.dict_org_rule_params', 'threshold', tuple(org_id, {p0:String}), -1.)) AS threshold,
  groupArray(20)(event_id) AS sample_event_ids,
  {run_id:UUID} AS run_id, {win_to:DateTime64(3)} AS win_to
FROM detect.v_events
WHERE mgr_time >= {win_from:DateTime64(3)} AND mgr_time < {win_to:DateTime64(3)}
  AND data_tp IN ('FIREWALL', 'IPS', 'TMS')
  AND org_id != ''
  AND dictGetOrDefault('detect.dict_org_rule_params', 'enabled', tuple(org_id, {p0:String}), toUInt8(1)) = 1
  AND ((net_direction = {p1:String}) AND (dst_port = {p2:Int64}) AND (src_internal = {p3:UInt8}))
GROUP BY org_id, entity
HAVING value >= threshold
LIMIT 100000
-- params
-- p0 = 'SR_ORG_SMB_OUTBREAK'
-- p1 = 'outbound'
-- p2 = 445
-- p3 = 1
-- p4 = 3.0
