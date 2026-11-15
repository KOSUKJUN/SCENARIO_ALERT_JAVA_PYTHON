-- 테스트 전용: 원본 이벤트 테이블 이름 변경 (codlog.security_log -> codlog.log_integrated_success_all).
-- 이전 이름으로 만들어진 환경에서 데이터를 유지한 채 이름만 바꾼다. 없으면 아무 일도 하지 않는다.
-- 최초 관측 MV 는 원본 테이블 이름을 쿼리에 담고 있으므로 지우고 012_peer_first_seen.sql 에서 새 이름으로 다시 만든다
-- (MV 는 데이터를 갖지 않는다. 집계 결과는 detect.peer_first_seen 에 그대로 남는다).
-- 운영 ClickHouse 에서 실행하지 않는다.
CREATE DATABASE IF NOT EXISTS codlog;
CREATE DATABASE IF NOT EXISTS detect;

RENAME TABLE IF EXISTS codlog.security_log TO codlog.log_integrated_success_all;

DROP VIEW IF EXISTS detect.mv_peer_first_seen;
