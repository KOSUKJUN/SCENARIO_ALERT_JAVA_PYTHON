#!/bin/bash
# 딕셔너리용 읽기 전용 계정 (ClickHouse MySQL 딕셔너리 소스)
mariadb -uroot -p"${MARIADB_ROOT_PASSWORD}" <<SQL
CREATE USER IF NOT EXISTS 'detect_dict'@'%' IDENTIFIED BY '${DICT_PASSWORD}';
GRANT SELECT ON detect.* TO 'detect_dict'@'%';
FLUSH PRIVILEGES;
SQL
