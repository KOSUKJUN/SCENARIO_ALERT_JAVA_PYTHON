-- 초기 스키마 (설계안 8장). Python 원본의 Alembic 0001 과 같은 구조 + 시나리오별 Python 코드 저장 칼럼.
--
-- 설계 대비 추가
-- - single_rules.name, consecutive_failures, scenarios.name : 목록 표시와 3회 연속 실패 경고용
-- - alerts.delivery_attempts, next_delivery_at, delivery_error, upgraded_at : 전달 재시도(지수 간격 10회)용
-- - users, sessions : 세션 토큰 인증과 역할
-- - scenario_versions.python_code, code_sha256, generator_version :
--     순서도 버전마다 Java 가 생성한 Python 평가 코드. 이 칼럼이 원본이고, 파일(SCENARIO_CODE_DIR)은 캐시다.

CREATE TABLE orgs (
  org_id   VARCHAR(64)  PRIMARY KEY,
  name     VARCHAR(200) NOT NULL,
  enabled  BOOLEAN      NOT NULL DEFAULT TRUE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE org_cidrs (
  org_id VARCHAR(64) NOT NULL,
  cidr   VARCHAR(43) NOT NULL,
  PRIMARY KEY (org_id, cidr),
  FOREIGN KEY (org_id) REFERENCES orgs (org_id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE single_rules (
  rule_id              VARCHAR(64) PRIMARY KEY,
  name                 VARCHAR(200) NOT NULL DEFAULT '',
  current_version      INT         NOT NULL,
  type                 VARCHAR(16) NOT NULL CHECK (type IN ('signature','count')),
  entity_type          VARCHAR(32) NOT NULL,
  status               VARCHAR(16) NOT NULL CHECK (status IN ('draft','silent','active','disabled')),
  schedule_sec         INT         NOT NULL DEFAULT 60,
  last_evaluated_to    DATETIME(3),
  next_run_at          DATETIME(3),
  consecutive_failures INT         NOT NULL DEFAULT 0,
  created_by           VARCHAR(64) NOT NULL,
  updated_at           DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
  KEY idx_due (status, next_run_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE single_rule_versions (
  rule_id      VARCHAR(64) NOT NULL,
  version      INT         NOT NULL,
  definition   JSON        NOT NULL,
  compiled_sql MEDIUMTEXT  NOT NULL,
  change_note  VARCHAR(500),
  created_by   VARCHAR(64) NOT NULL,
  created_at   DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  PRIMARY KEY (rule_id, version),
  FOREIGN KEY (rule_id) REFERENCES single_rules (rule_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE org_rule_params (
  org_id    VARCHAR(64) NOT NULL,
  rule_id   VARCHAR(64) NOT NULL,
  enabled   BOOLEAN     NOT NULL DEFAULT TRUE,
  threshold DOUBLE,
  PRIMARY KEY (org_id, rule_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE rule_runs (
  run_id        UUID        PRIMARY KEY,
  rule_id       VARCHAR(64) NOT NULL,
  version       INT         NOT NULL,
  win_from      DATETIME(3) NOT NULL,
  win_to        DATETIME(3) NOT NULL,
  status        VARCHAR(16) NOT NULL,
  hit_count     INT,
  new_hit_count INT,
  duration_ms   INT,
  error         TEXT,
  instance_id   VARCHAR(64),
  started_at    DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  KEY idx_rule_time (rule_id, started_at),
  KEY idx_time (started_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE scenarios (
  scenario_id     VARCHAR(64) PRIMARY KEY,
  name            VARCHAR(200) NOT NULL DEFAULT '',
  current_version INT         NOT NULL,
  entity_type     VARCHAR(32) NOT NULL,
  status          VARCHAR(16) NOT NULL CHECK (status IN ('draft','silent','active','disabled')),
  created_by      VARCHAR(64) NOT NULL,
  updated_at      DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE scenario_versions (
  scenario_id       VARCHAR(64) NOT NULL,
  version           INT         NOT NULL,
  graph             JSON        NOT NULL,
  max_span_sec      INT         NOT NULL,
  python_code       MEDIUMTEXT  NOT NULL,
  code_sha256       CHAR(64)    NOT NULL,
  generator_version VARCHAR(16) NOT NULL,
  change_note       VARCHAR(500),
  created_by        VARCHAR(64) NOT NULL,
  created_at        DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  PRIMARY KEY (scenario_id, version),
  FOREIGN KEY (scenario_id) REFERENCES scenarios (scenario_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE scenario_rule_refs (
  scenario_id VARCHAR(64) NOT NULL,
  version     INT         NOT NULL,
  rule_id     VARCHAR(64) NOT NULL,
  PRIMARY KEY (scenario_id, version, rule_id),
  KEY idx_rule (rule_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE lists (
  list_id      VARCHAR(64) PRIMARY KEY,
  kind         VARCHAR(16) NOT NULL CHECK (kind IN ('ip','cidr','domain','string','signature_map')),
  scope_org_id VARCHAR(64),
  description  VARCHAR(500)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE list_items (
  list_id      VARCHAR(64)  NOT NULL,
  value        VARCHAR(255) NOT NULL,
  mapped_value VARCHAR(64),
  expires_at   DATETIME(3),
  note         VARCHAR(500),
  PRIMARY KEY (list_id, value),
  FOREIGN KEY (list_id) REFERENCES lists (list_id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE assets (
  org_id          VARCHAR(64) NOT NULL,
  ip              VARCHAR(45) NOT NULL,
  purpose         VARCHAR(200),
  os              VARCHAR(100),
  holds_sensitive BOOLEAN,
  source          VARCHAR(32),
  updated_at      DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
  PRIMARY KEY (org_id, ip)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE asset_tags (
  org_id VARCHAR(64) NOT NULL,
  ip     VARCHAR(45) NOT NULL,
  tag    VARCHAR(64) NOT NULL,
  PRIMARY KEY (org_id, ip, tag),
  FOREIGN KEY (org_id, ip) REFERENCES assets (org_id, ip) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE alerts (
  alert_id          UUID         PRIMARY KEY,
  source_type       VARCHAR(16)  NOT NULL CHECK (source_type IN ('single_rule','scenario')),
  source_id         VARCHAR(64)  NOT NULL,
  source_version    INT          NOT NULL,
  org_id            VARCHAR(64)  NOT NULL,
  entity_type       VARCHAR(32)  NOT NULL,
  entity            VARCHAR(128) NOT NULL,
  severity          VARCHAR(16)  NOT NULL,
  title             VARCHAR(300) NOT NULL,
  alert_node        VARCHAR(64),
  playbook          TEXT,
  path              JSON         NOT NULL,
  first_seen        DATETIME(3)  NOT NULL,
  last_seen         DATETIME(3)  NOT NULL,
  hit_count         INT          NOT NULL DEFAULT 1,
  silent            BOOLEAN      NOT NULL DEFAULT FALSE,
  delivery_status   VARCHAR(16)  NOT NULL DEFAULT 'pending',
  delivery_attempts INT          NOT NULL DEFAULT 0,
  next_delivery_at  DATETIME(3),
  delivery_error    TEXT,
  case_ref          VARCHAR(64),
  verdict           VARCHAR(32),
  verdict_note      TEXT,
  verdict_at        DATETIME(3),
  created_at        DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  upgraded_at       DATETIME(3),
  KEY idx_org_time (org_id, first_seen),
  KEY idx_source_time (source_type, source_id, first_seen),
  KEY idx_suppress (source_id, org_id, entity, last_seen),
  KEY idx_delivery (delivery_status, next_delivery_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE known_incidents (
  incident_id VARCHAR(64)  PRIMARY KEY,
  org_id      VARCHAR(64)  NOT NULL,
  entity      VARCHAR(128) NOT NULL,
  occurred_at DATETIME(3)  NOT NULL,
  summary     TEXT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE backtest_jobs (
  job_id      UUID        PRIMARY KEY,
  target_type VARCHAR(16) NOT NULL,
  target_id   VARCHAR(64) NOT NULL,
  definition  JSON        NOT NULL,
  org_ids     JSON,
  time_from   DATETIME(3) NOT NULL,
  time_to     DATETIME(3) NOT NULL,
  status      VARCHAR(16) NOT NULL,
  result      JSON,
  error       TEXT,
  created_by  VARCHAR(64) NOT NULL,
  created_at  DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  finished_at DATETIME(3),
  KEY idx_status (status, created_at),
  KEY idx_target (target_type, target_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE audit_log (
  id     BIGINT AUTO_INCREMENT PRIMARY KEY,
  actor  VARCHAR(64)  NOT NULL,
  action VARCHAR(64)  NOT NULL,
  target VARCHAR(200) NOT NULL,
  detail JSON,
  at     DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  KEY idx_at (at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE users (
  username      VARCHAR(64)  PRIMARY KEY,
  password_hash VARCHAR(255) NOT NULL,
  role          VARCHAR(16)  NOT NULL CHECK (role IN ('viewer','analyst','author','admin')),
  enabled       BOOLEAN      NOT NULL DEFAULT TRUE,
  created_at    DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE sessions (
  token      VARCHAR(64) PRIMARY KEY,
  username   VARCHAR(64) NOT NULL,
  expires_at DATETIME(3) NOT NULL,
  KEY idx_user (username)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
