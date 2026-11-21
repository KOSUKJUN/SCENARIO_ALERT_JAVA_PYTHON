-- 테스트 전용 (init 이 CH_MANAGE_SOURCE=true 일 때만 실행한다). 운영·공용 ClickHouse 에서는 실행하지 않는다.
-- 예전 개발용 사본(default.log_integrated_success_all Distributed / _store)을 정리한다.
-- 원본은 이제 codlog.log_integrated_success_all (001), 경보는 codlog.alert_integrated_all (002) 이다.
-- 주의: codlog.* 는 실제 테이블과 같은 이름이라 여기서 절대 지우지 않는다.
-- 최초 관측 MV 는 원본 테이블 이름을 쿼리에 담고 있으므로 지우고 views/031 에서 다시 만든다
-- (MV 는 데이터를 갖지 않는다. 집계 결과는 detect.peer_first_seen 에 남는다).
CREATE DATABASE IF NOT EXISTS detect;

DROP VIEW IF EXISTS detect.mv_peer_first_seen;
DROP TABLE IF EXISTS default.log_integrated_success_all;
DROP TABLE IF EXISTS default.log_integrated_success_store;
