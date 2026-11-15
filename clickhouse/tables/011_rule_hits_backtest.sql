-- 백테스트 결과. rule_hits 와 같은 구조 + job_id, first_win_to(실시간이었다면 처음 보였을 평가 시각).
CREATE TABLE IF NOT EXISTS detect.rule_hits_backtest
(
    job_id           UUID,
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
    win_to           DateTime64(3, 'Asia/Seoul'),
    first_win_to     DateTime64(3, 'Asia/Seoul'),
    inserted_at      DateTime DEFAULT now()
)
ENGINE = MergeTree
PARTITION BY toYYYYMMDD(hit_bucket)
ORDER BY (job_id, org_id, rule_id, entity, hit_bucket)
TTL inserted_at + INTERVAL 7 DAY;
