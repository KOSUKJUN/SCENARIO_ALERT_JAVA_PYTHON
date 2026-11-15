-- 화면 설정 (모든 사용자 공통). 탐지 로직과 무관한 표시 옵션만 둔다.
-- show_incident: 판정·사고 번호·사고처리 시스템 전달·과거 사고 등 사고처리 관련 항목 표시 여부 (기본 숨김)
CREATE TABLE ui_settings (
  setting_key   VARCHAR(64)  PRIMARY KEY,
  setting_value VARCHAR(255) NOT NULL,
  updated_by    VARCHAR(64),
  updated_at    DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

INSERT INTO ui_settings (setting_key, setting_value, updated_by) VALUES ('show_incident', 'false', 'system');
