-- 로그 수집원 → 기관 매핑.
-- 운영 원본(default.log_integrated_success_all)에는 기관 컬럼이 없고 로그 수집원 ID(_asset_id)만 있다.
-- 탐지는 모든 히트·경보를 기관(org_id) 단위로 다루므로, 수집원마다 기관을 정해 둔다 (설정 > 로그 수집원).
-- ClickHouse 딕셔너리 detect.dict_log_sources 가 이 표를 읽고, v_events 가 org_id 로 바꾼다.
-- 매핑이 없는 수집원의 이벤트는 기관 'UNASSIGNED'(미지정)로 탐지한다 (탐지를 놓치지 않기 위해).
CREATE TABLE log_sources (
  asset_id    VARCHAR(128) PRIMARY KEY,
  org_id      VARCHAR(64)  NOT NULL,
  description VARCHAR(500),
  updated_by  VARCHAR(64)  NOT NULL,
  updated_at  DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
  KEY idx_org (org_id),
  FOREIGN KEY (org_id) REFERENCES orgs (org_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 매핑 없는 수집원이 모이는 기관. 이 기관의 경보는 수집원 매핑부터 하라는 신호다.
INSERT IGNORE INTO orgs (org_id, name, enabled) VALUES ('UNASSIGNED', '미지정 (로그 수집원 매핑 없음)', TRUE);
