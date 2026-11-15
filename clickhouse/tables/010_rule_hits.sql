CREATE DATABASE IF NOT EXISTS detect;

-- 단일룰 히트. (org_id, rule_id, entity, hit_bucket) 당 한 행만 남는다. 조회는 FINAL.
-- 설계 대비 변경: win_to(이 히트를 만든 평가 구간의 끝)를 추가하고 ReplacingMergeTree 의 버전으로 쓴다.
--   inserted_at(초 단위)을 버전으로 쓰면 따라잡기 중 같은 초에 여러 번 넣을 때 남는 행이 정해지지 않는다.
CREATE TABLE IF NOT EXISTS detect.rule_hits
(
    hit_bucket       DateTime('Asia/Seoul'),
    rule_id          LowCardinality(String),
    rule_version     UInt32,
    org_id           LowCardinality(String),
    entity_type      LowCardinality(String),
    entity           String,
    first_seen       DateTime64(3, 'Asia/Seoul'),
    last_seen        DateTime64(3, 'Asia/Seoul'),
    value            Float64,
    threshold        Float64,
    sample_event_ids Array(String),
    run_id           UUID,
    win_to           DateTime64(3, 'Asia/Seoul'),
    inserted_at      DateTime DEFAULT now()
)
ENGINE = ReplacingMergeTree(win_to)
PARTITION BY toYYYYMMDD(hit_bucket)
ORDER BY (org_id, rule_id, entity, hit_bucket)
TTL hit_bucket + INTERVAL 90 DAY;
