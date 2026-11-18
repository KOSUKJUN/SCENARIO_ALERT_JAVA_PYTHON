-- 테스트 전용: 이전 테스트 사본 정리. 운영 ClickHouse 에서 실행하지 않는다.
-- 원본 테이블은 운영과 같은 default.log_integrated_success_all(Distributed) / log_integrated_success_store(MergeTree) 다 (001).
-- 예전 사본(codlog.*)은 샘플 데이터뿐이라 지운다. init 이 새 테이블에 샘플 이벤트를 다시 넣는다.
-- 최초 관측 MV 는 원본 테이블 이름을 쿼리에 담고 있으므로 지우고 012_peer_first_seen.sql 에서 다시 만든다
-- (MV 는 데이터를 갖지 않는다. 집계 결과는 detect.peer_first_seen 에 남는다).
CREATE DATABASE IF NOT EXISTS detect;

DROP VIEW IF EXISTS detect.mv_peer_first_seen;
DROP TABLE IF EXISTS codlog.security_log;
DROP TABLE IF EXISTS codlog.log_integrated_success_all_v1;
DROP TABLE IF EXISTS codlog.log_integrated_success_all;
