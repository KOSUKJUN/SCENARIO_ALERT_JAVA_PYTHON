-- MITRE D3FEND 내부 사본 (폐쇄망). 공식 릴리스의 온톨로지(d3fend.json, JSON-LD)와 ATT&CK 매핑(d3fend-full-mappings.csv)을
-- 버전별로 보관한다. 활성 버전은 하나다. 룰·순서도 경보 노드는 지정 대응방책을 D3FEND 기법 ID(D3-PT 등)로만 저장하고,
-- 경보는 만들어질 때 활성 버전의 이름·전술을 함께 저장한다(나중에 버전이 바뀌어도 경보 내용은 그대로).

CREATE TABLE d3fend_versions (
  version       VARCHAR(32)  NOT NULL PRIMARY KEY,
  released_at   DATETIME(3),
  source_files  JSON         NOT NULL,
  source_sha256 CHAR(64)     NOT NULL,
  counts        JSON         NOT NULL,
  is_active     BOOLEAN      NOT NULL DEFAULT FALSE,
  imported_by   VARCHAR(64)  NOT NULL,
  imported_at   DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  activated_at  DATETIME(3)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 전술: Model, Harden, Detect, Isolate, Deceive, Evict, Restore (표시 순서 ord)
CREATE TABLE d3fend_tactics (
  version     VARCHAR(32)  NOT NULL,
  tactic      VARCHAR(32)  NOT NULL,
  ord         INT          NOT NULL,
  definition  TEXT,
  PRIMARY KEY (version, tactic),
  FOREIGN KEY (version) REFERENCES d3fend_versions (version) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 방어 기법 (D3-xxx). parent_id 가 없으면 전술 바로 아래 기법이다. depth 0 = 최상위.
CREATE TABLE d3fend_techniques (
  version     VARCHAR(32)  NOT NULL,
  d3f_id      VARCHAR(32)  NOT NULL,
  iri         VARCHAR(128) NOT NULL,
  name        VARCHAR(200) NOT NULL,
  tactic      VARCHAR(32),
  parent_id   VARCHAR(32),
  depth       INT          NOT NULL DEFAULT 0,
  definition  TEXT,
  kb_article  MEDIUMTEXT,
  synonyms    JSON,
  PRIMARY KEY (version, d3f_id),
  KEY idx_name (version, name),
  KEY idx_parent (version, parent_id),
  FOREIGN KEY (version) REFERENCES d3fend_versions (version) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ATT&CK 기법 → D3FEND 대응 기법 (D3FEND 추론 매핑). via = 디지털 아티팩트를 통한 근거 몇 개
-- [{def_rel, def_artifact, off_rel, off_artifact}]. attack_domain = enterprise / ics.
CREATE TABLE d3fend_attack_map (
  version        VARCHAR(32) NOT NULL,
  attack_id      VARCHAR(16) NOT NULL,
  d3f_id         VARCHAR(32) NOT NULL,
  attack_domain  VARCHAR(16) NOT NULL,
  attack_name    VARCHAR(300),
  via            JSON,
  PRIMARY KEY (version, attack_id, d3f_id),
  KEY idx_d3f (version, d3f_id),
  FOREIGN KEY (version) REFERENCES d3fend_versions (version) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ATT&CK 완화(M) ↔ D3FEND 기법 (d3f:related)
CREATE TABLE d3fend_mitigation_map (
  version          VARCHAR(32)  NOT NULL,
  mitigation_id    VARCHAR(16)  NOT NULL,
  mitigation_name  VARCHAR(300),
  d3f_id           VARCHAR(32)  NOT NULL,
  PRIMARY KEY (version, mitigation_id, d3f_id),
  KEY idx_d3f (version, d3f_id),
  FOREIGN KEY (version) REFERENCES d3fend_versions (version) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 경보: 지정 대응방책 스냅샷 [{id, name, tactic}] 과 그 D3FEND 버전
ALTER TABLE alerts
  ADD COLUMN d3fend         JSON,
  ADD COLUMN d3fend_version VARCHAR(32);
