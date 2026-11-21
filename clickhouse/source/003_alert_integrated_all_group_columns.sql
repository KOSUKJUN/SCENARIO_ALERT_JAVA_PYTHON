-- 테스트 전용 (CH_MANAGE_SOURCE=true): 002 로 이미 만들어 둔 경보 테이블 사본을 대상 서버의 2026-11-21 변경에 맞춘다.
--   grp_cd → rull_grp_cd (룰 그룹 코드 = 이 시스템의 시나리오 그룹 코드)
--   group_cd / group_nm 추가 (CODPRO 그룹 코드·이름 = 이 시스템의 기관 코드·기관명)
-- 대상 서버는 그쪽에서 같은 ALTER 를 한다. 반복 실행해도 된다 (IF EXISTS / IF NOT EXISTS).
ALTER TABLE codlog.alert_integrated_all RENAME COLUMN IF EXISTS grp_cd TO rull_grp_cd;
ALTER TABLE codlog.alert_integrated_all ADD COLUMN IF NOT EXISTS group_cd LowCardinality(String) DEFAULT '' COMMENT 'CODPRO그룹코드' AFTER rull_grp_cd;
ALTER TABLE codlog.alert_integrated_all ADD COLUMN IF NOT EXISTS group_nm LowCardinality(String) DEFAULT '' COMMENT 'CODPRO그룹명' AFTER group_cd;
