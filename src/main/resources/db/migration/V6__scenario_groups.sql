-- 시나리오 그룹 (시나리오 분석 화면 왼쪽). 화면에서 묶어 보기 위한 분류일 뿐 탐지 판정과는 관계없다.
-- 그룹은 순서도 그래프 JSON·생성 코드에 들어가지 않는다 (버전이 올라가지 않는다).
-- 그룹을 지우면 그 그룹의 시나리오는 미분류(group_id NULL)가 된다.
CREATE TABLE scenario_groups (
  group_id   INT AUTO_INCREMENT PRIMARY KEY,
  name       VARCHAR(100) NOT NULL,
  sort_order INT          NOT NULL DEFAULT 0,
  created_by VARCHAR(64)  NOT NULL,
  updated_at DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
  UNIQUE KEY uq_name (name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

ALTER TABLE scenarios
  ADD COLUMN group_id INT NULL AFTER entity_type,
  ADD KEY idx_group (group_id),
  ADD CONSTRAINT fk_scenarios_group FOREIGN KEY (group_id) REFERENCES scenario_groups (group_id) ON DELETE SET NULL;
