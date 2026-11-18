-- MITRE ATT&CK 내부 사본 (폐쇄망). 공식 STIX 2.1 번들(enterprise-attack-<버전>.json 등)을 가져와 버전별로 보관한다.
-- 도메인(enterprise-attack / ics-attack / mobile-attack)마다 활성 버전은 하나다. 룰·순서도는 기법 ID(T1190, T1059.004)만 저장하고,
-- 경보는 만들어질 때 활성 버전의 이름·전술을 함께 저장한다(나중에 버전이 바뀌어도 경보 내용은 그대로).

CREATE TABLE attack_versions (
  domain        VARCHAR(32)  NOT NULL,
  version       VARCHAR(16)  NOT NULL,
  name          VARCHAR(100) NOT NULL,
  released_at   DATETIME(3),
  spec_version  VARCHAR(16),
  source_file   VARCHAR(255) NOT NULL,
  source_sha256 CHAR(64)     NOT NULL,
  counts        JSON         NOT NULL,
  is_active     BOOLEAN      NOT NULL DEFAULT FALSE,
  imported_by   VARCHAR(64)  NOT NULL,
  imported_at   DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  activated_at  DATETIME(3),
  PRIMARY KEY (domain, version)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 객체 유형: tactic(TA), technique(T, 하위 기법 포함), mitigation(M), group(G), software(S), detection(DET, 탐지 전략)
CREATE TABLE attack_objects (
  domain        VARCHAR(32)  NOT NULL,
  version       VARCHAR(16)  NOT NULL,
  obj_type      VARCHAR(16)  NOT NULL,
  attack_id     VARCHAR(16)  NOT NULL,
  stix_id       VARCHAR(80)  NOT NULL,
  name          VARCHAR(300) NOT NULL,
  parent_id     VARCHAR(16),
  shortname     VARCHAR(64),
  ord           INT,
  description   MEDIUMTEXT,
  url           VARCHAR(300),
  tactics       JSON,
  extra         JSON,
  deprecated    BOOLEAN      NOT NULL DEFAULT FALSE,
  revoked       BOOLEAN      NOT NULL DEFAULT FALSE,
  revoked_by    VARCHAR(16),
  stix_modified DATETIME(3),
  PRIMARY KEY (domain, version, obj_type, attack_id),
  KEY idx_name (domain, version, obj_type, name),
  FOREIGN KEY (domain, version) REFERENCES attack_versions (domain, version) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 기법을 향한 관계만 둔다: mitigates(M→T), detects(DET→T), uses(G/S→T)
CREATE TABLE attack_relations (
  domain      VARCHAR(32) NOT NULL,
  version     VARCHAR(16) NOT NULL,
  rel_type    VARCHAR(16) NOT NULL,
  src_type    VARCHAR(16) NOT NULL,
  src_id      VARCHAR(16) NOT NULL,
  dst_id      VARCHAR(16) NOT NULL,
  description TEXT,
  PRIMARY KEY (domain, version, rel_type, src_type, src_id, dst_id),
  KEY idx_dst (domain, version, dst_id),
  FOREIGN KEY (domain, version) REFERENCES attack_versions (domain, version) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 경보: 만들어질 때(또는 등급 상향 때)의 ATT&CK 기법 스냅샷 [{id, name, tactics:[{id, name}]}] 과 그 버전
ALTER TABLE alerts
  ADD COLUMN attack         JSON,
  ADD COLUMN attack_version VARCHAR(64);
