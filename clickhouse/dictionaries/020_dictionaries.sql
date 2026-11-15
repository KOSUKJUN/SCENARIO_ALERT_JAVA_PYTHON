-- MariaDB 원본 딕셔너리. 접속 정보는 named collection(mariadb_detect)에만 있다.
-- 여러 값 항목은 GROUP_CONCAT 쉼표 문자열로 넘기고 뷰에서 나눈다.

CREATE OR REPLACE DICTIONARY detect.dict_orgs
(
    inst_id        String,
    internal_cidrs String
)
PRIMARY KEY inst_id
SOURCE(MYSQL(NAME mariadb_detect
    query 'SELECT org_id AS inst_id, GROUP_CONCAT(cidr) AS internal_cidrs FROM org_cidrs GROUP BY org_id'))
LAYOUT(COMPLEX_KEY_HASHED())
LIFETIME(MIN 30 MAX 60);

CREATE OR REPLACE DICTIONARY detect.dict_assets
(
    org_id String,
    ip     String,
    tags   String
)
PRIMARY KEY org_id, ip
SOURCE(MYSQL(NAME mariadb_detect
    query 'SELECT org_id, ip, GROUP_CONCAT(tag) AS tags FROM asset_tags GROUP BY org_id, ip'))
LAYOUT(COMPLEX_KEY_HASHED())
LIFETIME(MIN 30 MAX 60);

-- 리스트 항목 (값은 소문자). scope 는 리스트의 적용 기관('' 이면 전체 기관 공통). 만료 항목 제외.
CREATE OR REPLACE DICTIONARY detect.dict_list_items
(
    list_id      String,
    value        String,
    scope        String,
    mapped_value String
)
PRIMARY KEY list_id, value
SOURCE(MYSQL(NAME mariadb_detect
    query 'SELECT i.list_id AS list_id, LOWER(i.value) AS value, COALESCE(l.scope_org_id, '''') AS scope, COALESCE(i.mapped_value, '''') AS mapped_value FROM list_items i JOIN lists l ON l.list_id = i.list_id WHERE i.expires_at IS NULL OR i.expires_at > NOW()'))
LAYOUT(COMPLEX_KEY_HASHED())
LIFETIME(MIN 30 MAX 60);

-- 유해 IP: kind = ip 이고 list_id 가 threat_ 로 시작하는 리스트의 항목
CREATE OR REPLACE DICTIONARY detect.dict_threat_ip
(
    ip      String,
    list_id String
)
PRIMARY KEY ip
SOURCE(MYSQL(NAME mariadb_detect
    query 'SELECT i.value AS ip, MIN(i.list_id) AS list_id FROM list_items i JOIN lists l ON l.list_id = i.list_id WHERE l.kind = ''ip'' AND LEFT(l.list_id, 7) = ''threat_'' AND (i.expires_at IS NULL OR i.expires_at > NOW()) GROUP BY i.value'))
LAYOUT(COMPLEX_KEY_HASHED())
LIFETIME(MIN 30 MAX 60);

-- 시그니처 분류: kind = signature_map 리스트 항목. value 는 '데이터유형|시그니처명' ('*' 는 모든 유형), mapped_value 가 분류.
CREATE OR REPLACE DICTIONARY detect.dict_signature_map
(
    data_tp  String,
    method   String,
    category String
)
PRIMARY KEY data_tp, method
SOURCE(MYSQL(NAME mariadb_detect
    query 'SELECT SUBSTRING_INDEX(i.value, ''|'', 1) AS data_tp, LOWER(SUBSTRING(i.value, LOCATE(''|'', i.value) + 1)) AS method, MIN(i.mapped_value) AS category FROM list_items i JOIN lists l ON l.list_id = i.list_id WHERE l.kind = ''signature_map'' AND LOCATE(''|'', i.value) > 0 GROUP BY 1, 2'))
LAYOUT(COMPLEX_KEY_HASHED())
LIFETIME(MIN 30 MAX 60);

-- 기관별 룰 파라미터. threshold 가 NULL 이면 -1 (룰 기본값 사용)
CREATE OR REPLACE DICTIONARY detect.dict_org_rule_params
(
    org_id    String,
    rule_id   String,
    enabled   UInt8,
    threshold Float64
)
PRIMARY KEY org_id, rule_id
SOURCE(MYSQL(NAME mariadb_detect
    query 'SELECT org_id, rule_id, enabled, COALESCE(threshold, -1) AS threshold FROM org_rule_params'))
LAYOUT(COMPLEX_KEY_HASHED())
LIFETIME(MIN 30 MAX 60);
