# 테스트용 D3FEND 릴리스

`<버전>/d3fend.json`, `<버전>/d3fend-full-mappings.csv` 는 공식 MITRE D3FEND 릴리스(https://d3fend.mitre.org/resources/ontology/)에서
일부만 잘라 낸 것이다. 온톨로지는 전술·방어 기법·ATT&CK 완화 노드만 남기고 정의·설명을 짧게 잘랐고, 매핑은 기본 룰·순서도가
참조하는 ATT&CK 기법의 행만 (방어 기법, ATT&CK 기법) 쌍마다 한 행씩 남겼다. `scripts/make_d3fend_fixture.py` 로 다시 만든다.

D3FEND™ © The MITRE Corporation. D3FEND 온톨로지는 MIT 라이선스로 배포된다.
