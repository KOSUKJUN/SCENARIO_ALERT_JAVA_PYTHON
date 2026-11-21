-- 경보 본문은 ClickHouse codlog.alert_integrated_all 에만 둔다 (2026-11-21 요청).
-- MariaDB 에는 같은 alert_id(= _alert_cd)로 경보의 상태만 남긴다:
--   억제(출처·기관·대상·등급·최종 시각), 경로(path), 판정, 사고처리 시스템 전달 상태, ATT&CK·D3FEND 스냅샷.
-- 제목·대응 절차·최초 시각·횟수는 ClickHouse 행에 있다 (제목 = attack, 최초 = event_sdt, 횟수 = count, 대응 절차 = fields.playbook).
-- ch_window_ms 는 ClickHouse 행을 찾는 열쇠다 (정렬 키 첫 칸 window_ms = 최초 시각의 1시간 구간 시작).
--
-- 이전 alerts 행은 alerts_legacy 로 남겨 두고, init 이 ClickHouse 로 옮긴 다음 그 행을 지운다 (AlertStore.migrateLegacy).
RENAME TABLE alerts TO alerts_legacy;

CREATE TABLE alert_state (
  alert_id          UUID         PRIMARY KEY,
  source_type       VARCHAR(16)  NOT NULL CHECK (source_type IN ('single_rule','scenario')),
  source_id         VARCHAR(64)  NOT NULL,
  source_version    INT          NOT NULL,
  org_id            VARCHAR(64)  NOT NULL,
  entity_type       VARCHAR(32)  NOT NULL,
  entity            VARCHAR(128) NOT NULL,
  severity          VARCHAR(16)  NOT NULL,
  alert_node        VARCHAR(64),
  path              JSON         NOT NULL,
  last_seen         DATETIME(3)  NOT NULL,
  ch_window_ms      BIGINT       NOT NULL,
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
  attack            JSON,
  attack_version    VARCHAR(64),
  d3fend            JSON,
  d3fend_version    VARCHAR(32),
  KEY idx_org_created (org_id, created_at),
  KEY idx_source_created (source_type, source_id, created_at),
  KEY idx_suppress (source_id, org_id, entity, last_seen),
  KEY idx_delivery (delivery_status, next_delivery_at),
  KEY idx_case_ref (case_ref)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 이전 경보의 상태 부분을 옮긴다 (DB 시간대는 +09:00, DATETIME 은 KST 이므로 UNIX_TIMESTAMP 가 그대로 맞다)
INSERT INTO alert_state (alert_id, source_type, source_id, source_version, org_id, entity_type, entity, severity, alert_node, path,
                         last_seen, ch_window_ms, silent, delivery_status, delivery_attempts, next_delivery_at, delivery_error, case_ref,
                         verdict, verdict_note, verdict_at, created_at, upgraded_at, attack, attack_version, d3fend, d3fend_version)
SELECT alert_id, source_type, source_id, source_version, org_id, entity_type, entity, severity, alert_node, path,
       last_seen, UNIX_TIMESTAMP(DATE_FORMAT(first_seen, '%Y-%m-%d %H:00:00')) * 1000, silent, delivery_status, delivery_attempts,
       next_delivery_at, delivery_error, case_ref, verdict, verdict_note, verdict_at, created_at, upgraded_at, attack, attack_version,
       d3fend, d3fend_version
FROM alerts_legacy;

-- 시나리오 그룹 코드: 경보의 grp_cd 로 들어간다. 기존 그룹은 SG001 형식으로 채운다.
ALTER TABLE scenario_groups ADD COLUMN grp_cd VARCHAR(32) NULL AFTER group_id;
UPDATE scenario_groups SET grp_cd = CONCAT('SG', LPAD(group_id, 3, '0'));
ALTER TABLE scenario_groups MODIFY grp_cd VARCHAR(32) NOT NULL, ADD UNIQUE KEY uq_grp_cd (grp_cd);
