// 서버 응답·요청의 주요 형태 (src/server/api/*.py 기준).

export type Json = string | number | boolean | null | Json[] | { [k: string]: Json };
export type Row = Record<string, unknown>;

export type Role = 'viewer' | 'analyst' | 'author' | 'admin';
export type Status = 'draft' | 'silent' | 'active' | 'disabled';
export type Severity = 'low' | 'medium' | 'high' | 'critical';

export interface Me {
  username: string;
  role: Role;
  dev_tools: boolean;
  ui?: UiSettings;
}

/** 화면 설정 (모든 사용자 공통, 관리자만 변경) */
export interface UiSettings {
  /** 판정·사고 번호·사고처리 시스템 전달·과거 사고 등 사고처리 관련 항목 표시 */
  show_incident: boolean;
}

export interface LoginResponse {
  token: string;
  username: string;
  role: Role;
}

// ---------- /meta/fields ----------
export type FieldType = 'string' | 'int' | 'ip' | 'bool' | 'tags' | 'peer';

export interface FieldMeta {
  name: string;
  type: FieldType;
  label: string;
  ops: string[];
  available: string[];
  nullable: boolean;
  enum: string[];
  note: string;
}

export interface ListMeta {
  list_id: string;
  kind: string;
  scope_org_id: string | null;
  description: string | null;
  item_count?: number;
}

export interface MetaFields {
  data_types: string[];
  fields: FieldMeta[];
  op_labels: Record<string, string>;
  entity_types: { type: string; fields: string[] }[];
  aggregate_funcs: { func: string; fields: string[] }[];
  severities: Severity[];
  statuses: Status[];
  node_types: string[];
  lists: ListMeta[];
  asset_tags: string[];
}

// ---------- 이벤트 탐지모듈 ----------
export type FilterLeaf = { field: string; op: string; value?: Json };
export type FilterNode = { all: FilterNode[] } | { any: FilterNode[] } | { not: FilterNode } | FilterLeaf;

export interface RuleDefinition {
  id: string;
  name: string;
  description?: string;
  type: 'signature' | 'count';
  entity: { type: string; field: string };
  data_tp: string[];
  filter: FilterNode;
  aggregate?: { func: string; field?: string };
  window: string;
  threshold?: number;
  min_count?: number;
  exclude_lists?: string[];
  schedule?: string;
  alert_on_hit?: boolean;
  severity?: Severity;
  suppress_for?: string;
  tags?: Json;
  status?: Status;
  /** MITRE ATT&CK 기법 ID (T1190, T1059.004) */
  attack?: string[];
  /** 지정 대응방책: MITRE D3FEND 방어 기법 ID (D3-PT, D3-NI) */
  d3fend?: string[];
}

export interface RuleSummary {
  rule_id: string;
  name: string;
  version: number;
  status: Status;
  type: string;
  entity_type: string;
  entity_field: string | null;
  data_tp: string[] | null;
  window: string | null;
  severity: Severity;
  alert_on_hit: boolean;
  schedule_sec: number;
  last_evaluated_to: string | null;
  consecutive_failures: number;
  warning: boolean;
  updated_at: string | null;
  hits_24h?: number;
  avg_run_ms?: number;
  failures_24h?: number;
  used_by?: string[];
}

export interface RuleDetail {
  rule: RuleSummary;
  definition: RuleDefinition;
  compiled_sql: string;
  operation: { silent_since: string | null; alerts_30d: number };
}

export interface RuleSaveResponse {
  rule: RuleSummary;
  definition: RuleDefinition;
  warnings: { path: string; message: string }[];
}

export interface CompileResponse {
  ok: boolean;
  errors: { path: string; message: string }[];
  warnings: { path: string; message: string }[];
  sql: string;
}

/** POST /single-rules/import/snort 항목 하나 (저장 전 변환·검증 결과) */
export interface SnortImportItem {
  line: number;
  source: string;
  sid: string | null;
  notes: string[];
  skipped: string | null;
  definition?: RuleDefinition;
  ok?: boolean;
  errors?: { path: string; message: string }[];
  warnings?: { path: string; message: string }[];
  sql?: string | null;
  exists?: boolean;
}

export interface SnortImportResponse {
  total: number;
  convertible: number;
  items: SnortImportItem[];
}

export interface PreviewResponse {
  time_from: string;
  time_to: string;
  total_hits: number;
  distinct_entities: number;
  hourly: { hour: string; hits: number }[];
  top_entities: { org_id: string; entity: string; hits: number }[];
  samples: Row[];
  warnings: { path: string; message: string }[];
  sql: string;
}

export interface RuleVersion {
  version: number;
  definition: RuleDefinition;
  change_note: string | null;
  created_by: string;
  created_at: string;
}

// ---------- 순서도 ----------
export type NodeType = 'start' | 'rule' | 'check' | 'asset' | 'and' | 'or' | 'alert';

export interface GraphNode {
  id: string;
  type: NodeType;
  pos?: [number, number];
  label?: string;
  rule_id?: string;
  rule_ids?: string[];
  lookaround?: string;
  tags?: string[];
  within?: string;
  severity?: Severity;
  title?: string;
  playbook?: string;
  /** 경보 노드: MITRE ATT&CK 기법 ID (경로의 룰 기법은 경보에 자동으로 더해진다) */
  attack?: string[];
  /** 경보 노드: 지정 대응방책 (MITRE D3FEND 방어 기법 ID) */
  d3fend?: string[];
}

export interface GraphEdge {
  from: string;
  to: string;
  branch?: 'yes' | 'no';
  within?: string;
}

export interface Graph {
  id: string;
  name: string;
  description?: string;
  entity_type: string;
  status?: Status;
  suppress_for?: string;
  nodes: GraphNode[];
  edges: GraphEdge[];
}

/** 시나리오 그룹 (시나리오 분석 왼쪽). 탐지 판정과 무관한 화면 분류 */
export interface ScenarioGroup {
  group_id: number;
  /** 경보 테이블(alert_integrated_all) 의 rull_grp_cd 로 들어가는 그룹 코드 */
  grp_cd: string;
  name: string;
  sort_order: number;
  scenario_count: number;
}

/** 시나리오 분석 왼쪽에서 고른 그룹: 'all' = 전체, 'none' = 미분류, 숫자 = 그룹 ID */
export type GroupKey = 'all' | 'none' | number;
export interface ScenarioGroupList {
  groups: ScenarioGroup[];
  total: number;
  ungrouped: number;
}

export interface ScenarioSummary {
  scenario_id: string;
  name: string;
  version: number;
  status: Status;
  entity_type: string;
  max_span_sec: number;
  suppress_for: string;
  rule_ids: string[];
  node_count: number;
  severities: Severity[];
  updated_at: string | null;
  alerts_24h?: number;
  /** 화면 분류용 시나리오 그룹 (없으면 미분류) */
  group_id?: number | null;
}

export interface GraphIssue {
  target: 'node' | 'edge' | 'graph';
  id: string;
  message: string;
}

export interface ValidateResponse {
  ok: boolean;
  errors: GraphIssue[];
  warnings: GraphIssue[];
  max_span_sec: number;
  rule_refs: string[];
}

export interface NodeSim {
  status: 'reached' | 'blocked' | 'not_reached';
  reason?: string;
  message?: string;
  result?: 'yes' | 'no';
  at?: string | null;
  hits?: number;
  matched_tags?: string[];
  yes?: number;
  no?: number;
}

export interface PathStep {
  node: string;
  type?: string;
  rule_id?: string;
  matched_rule_id?: string;
  at?: string;
  value?: number;
  threshold?: number;
  result?: 'yes' | 'no';
  matched_tags?: string[];
  severity?: Severity;
  first_seen?: string;
  last_seen?: string;
  sample_event_ids?: string[];
}

export interface SimulateResponse {
  ok: boolean;
  errors?: GraphIssue[];
  node_status?: Record<string, NodeSim>;
  asset_tags?: string[];
  hits?: { rule_id: string; at: string; value: number; threshold: number }[];
  alert?: { node: string; severity: Severity; title: string; path: PathStep[] } | null;
  reached_alerts?: string[];
}

export interface ScenarioDetail {
  scenario: ScenarioSummary;
  graph: Graph;
  operation: { silent_since: string | null; alerts_30d: number };
  warnings: GraphIssue[];
}

export interface ScenarioSaveResponse {
  scenario: ScenarioSummary;
  graph: Graph;
  warnings: GraphIssue[];
}

export interface GraphDiff {
  nodes_added: string[];
  nodes_removed: string[];
  nodes_changed: string[];
  edges_added: string[];
  edges_removed: string[];
  edges_changed: string[];
  settings_changed: string[];
}

export interface ScenarioVersion {
  version: number;
  graph: Graph;
  max_span_sec: number;
  change_note: string | null;
  created_by: string;
  created_at: string;
  diff: GraphDiff | null;
  /** 이 버전에서 생성된 Python 평가 코드의 sha256 (Java 버전 서버) */
  code_sha256?: string;
  generator_version?: string;
}

/** 순서도 버전별로 생성된 Python 평가 코드 (GET /scenarios/{id}/code?version=N) */
export interface ScenarioCode {
  scenario_id: string;
  version: number;
  python_code: string;
  code_sha256: string;
  generator_version: string;
  created_at: string;
}

// ---------- 백테스트 ----------
export interface BacktestJob {
  job_id: string;
  target_type: 'single_rule' | 'scenario';
  target_id: string;
  status: 'queued' | 'running' | 'done' | 'failed';
  time_from: string;
  time_to: string;
  created_by?: string;
  created_at?: string;
  finished_at?: string | null;
  error?: string | null;
  result?: BacktestResult | null;
}

export interface RecallItem {
  incident_id: string;
  org_id: string;
  entity: string;
  occurred_at: string;
  summary: string | null;
  detected: boolean;
}

export interface BacktestResult {
  target_type: string;
  target_id: string;
  version?: number;
  time_from: string;
  time_to: string;
  total_hits: number;
  total_alerts: number;
  daily: { date: string; hits?: number; alerts?: number }[];
  top_entities: { org_id: string; entity: string; hits?: number; alerts?: number }[];
  threshold_sensitivity?: Record<string, number>;
  alerts?: Row[];
  recall?: RecallItem[];
  alerts_by_severity?: Record<string, number>;
  hits_by_rule?: Record<string, number>;
}

// ---------- 경보 ----------
export interface AlertItem {
  alert_id: string;
  source_type: 'single_rule' | 'scenario';
  source_id: string;
  source_version: number;
  org_id: string;
  entity_type: string;
  entity: string;
  severity: Severity;
  title: string;
  alert_node: string | null;
  first_seen: string;
  last_seen: string;
  hit_count: number;
  silent: boolean | number;
  delivery_status: string;
  delivery_attempts: number;
  case_ref: string | null;
  verdict: string | null;
  created_at: string;
  upgraded_at: string | null;
  /** 경보 생성(상향) 때의 MITRE ATT&CK 기법 스냅샷 */
  attack?: AttackRef[];
  /** 경보 생성(상향) 때의 지정 대응방책 (D3FEND) 스냅샷 */
  d3fend?: D3fendRef[];
  /** ClickHouse 경보 본문(codlog.alert_integrated_all) 에서 온 값 */
  /** 룰 그룹 코드 = 시나리오 그룹 코드 (경보를 만들 때의 값) */
  rull_grp_cd?: string | null;
  /** CODPRO 그룹 = 대상 기관 코드·기관명 */
  group_cd?: string | null;
  group_nm?: string | null;
  risk?: string | null;
  data_type?: string | null;
  src_ip?: string | null;
  src_port?: number | null;
  src_iso?: string | null;
  dst_ip?: string | null;
  dst_port?: number | null;
  action?: string | null;
  product?: string | null;
  origin_id?: string | null;
}

export interface AlertDetail extends AlertItem {
  attack_version?: string | null;
  d3fend_version?: string | null;
  playbook: string | null;
  path: PathStep[];
  delivery_error: string | null;
  verdict_note: string | null;
  verdict_at: string | null;
  asset: Row | null;
  graph: Graph | null;
  exception_lists: { list_id: string; kind: string; description: string | null }[];
}

export interface AlertEvents {
  events: Row[];
  by_node: Record<string, string[]>;
}

// ---------- 설정 ----------
export interface Org {
  org_id: string;
  name: string;
  enabled: boolean | number;
  cidrs: string[];
}

export interface RuleParam {
  org_id: string;
  rule_id: string;
  enabled: boolean | number;
  threshold: number | null;
}

export interface ListItem {
  value: string;
  mapped_value: string | null;
  expires_at: string | null;
  note: string | null;
}

export interface ListDetail extends ListMeta {
  items: ListItem[];
}

export interface Asset {
  org_id: string;
  ip: string;
  purpose: string | null;
  os: string | null;
  holds_sensitive: boolean | number | null;
  source: string | null;
  tags: string[];
  [k: string]: unknown;
}

export interface Incident {
  incident_id: string;
  org_id: string;
  entity: string;
  occurred_at: string;
  summary: string | null;
}

export interface UserRow {
  username: string;
  role: Role;
  enabled: boolean | number;
  created_at: string;
}

// ---------- 현황 ----------
export interface SourceStat {
  alerts: number;
  true_positive: number;
  false_positive: number;
  benign: number;
  judged: number;
  tp_rate: number | null;
  needs_tuning: boolean;
  delivery_failed: number;
  top_fp_entities: { entity: string; count: number }[];
}

export interface RuleMetric extends SourceStat {
  rule_id: string;
  name: string;
  status: Status;
  runs_24h: number;
  avg_run_ms: number;
  max_run_ms: number;
  failed_runs_24h: number;
  hits_24h: number;
  eval_lag_sec: number | null;
  consecutive_failures: number;
  warning: boolean;
}

export interface ScenarioMetric extends SourceStat {
  scenario_id: string;
  name: string;
  status: Status;
}

export interface RuleMetrics {
  days: number;
  rules: RuleMetric[];
  scenarios: ScenarioMetric[];
  failed_runs: { rule_id: string; win_to: string; status: string; error: string | null; started_at: string }[];
  undelivered_alerts: {
    alert_id: string;
    source_id: string;
    org_id: string;
    entity: string;
    severity: Severity;
    delivery_attempts: number;
    delivery_error: string | null;
    created_at: string;
  }[];
}

// ---------- MITRE ATT&CK (내부 사본) ----------
export interface AttackTactic {
  id: string;
  name: string;
  shortname?: string;
}

/** 경보에 저장된 기법 (스냅샷). name 이 null 이면 그때 활성 버전에 없던 ID. */
export interface AttackRef {
  id: string;
  name: string | null;
  tactics: AttackTactic[];
  revoked_by?: string;
}

/** POST /attack/techniques/lookup 결과 한 건 (활성 버전) */
export interface AttackLookup extends AttackRef {
  deprecated: boolean;
  revoked: boolean;
  revoked_by: string;
  domain: string;
  version: string;
}

export interface AttackVersion {
  domain: string;
  version: string;
  name: string;
  released_at: string | null;
  spec_version: string | null;
  source_file: string;
  source_sha256: string;
  counts: Record<string, number>;
  is_active: boolean;
  imported_by: string;
  imported_at: string;
  activated_at: string | null;
}

export interface AttackSearchItem {
  id: string;
  name: string;
  parent_id: string | null;
  parent_name: string | null;
  tactics: string[];
}

export interface AttackCoverage {
  rules: { id: string; name: string; status: Status }[];
  scenarios: { id: string; name: string; status: Status; via: string }[];
  alerts_30d: number;
}

export interface AttackRelated {
  id: string;
  name: string;
  description: string | null;
}

export interface AttackTechniqueDetail {
  id: string;
  name: string;
  domain: string;
  version: string;
  parent_id: string | null;
  parent_name?: string | null;
  description: string | null;
  url: string | null;
  tactics: AttackTactic[];
  extra: { platforms?: string[] };
  deprecated: boolean;
  revoked: boolean;
  revoked_by: string | null;
  stix_modified: string | null;
  subtechniques: { id: string; name: string }[];
  mitigations: AttackRelated[];
  detections: AttackRelated[];
  groups: AttackRelated[];
  software: AttackRelated[];
  coverage: AttackCoverage;
}

export interface AttackMatrixCell {
  id: string;
  name: string;
  rules: number;
  scenarios: number;
  alerts_30d: number;
  covered: boolean;
  subtechniques?: AttackMatrixCell[];
}

export interface AttackMatrix {
  domain: string;
  version: string;
  tactics: (AttackTactic & { techniques: AttackMatrixCell[] })[];
  summary: { techniques: number; covered: number; cells: number };
}

export interface AttackDiffResult {
  domain: string;
  from: string | null;
  to: string;
  summary?: Record<string, number>;
  added?: { id: string; name: string }[];
  removed?: { id: string; name: string }[];
  revoked?: { id: string; name: string; revoked_by: string | null; revoked_by_name: string | null }[];
  deprecated?: { id: string; name: string }[];
  renamed?: { id: string; from: string; to: string }[];
  tactics_changed?: { id: string; name: string; from: string[]; to: string[] }[];
  impact: {
    technique: string;
    status: 'missing' | 'revoked' | 'deprecated';
    replacement: string | null;
    refs: { kind: 'rule' | 'scenario'; id: string; name: string; status: Status; detail: string | null }[];
  }[];
}

// ---------- MITRE D3FEND (내부 사본, 대응방책) ----------
export type D3fendTactic = 'Model' | 'Harden' | 'Detect' | 'Isolate' | 'Deceive' | 'Evict' | 'Restore';

/** 경보에 저장된 지정 대응방책 (스냅샷). name 이 null 이면 그때 활성 버전에 없던 ID. */
export interface D3fendRef {
  id: string;
  name: string | null;
  tactic: string | null;
}

export interface D3fendLookup extends D3fendRef {
  parent_id: string | null;
  version: string;
}

export interface D3fendVersion {
  version: string;
  released_at: string | null;
  source_files: { source: string; files: { file: string; sha256: string }[] };
  source_sha256: string;
  counts: Record<string, number>;
  is_active: boolean;
  imported_by: string;
  imported_at: string;
  activated_at: string | null;
}

export interface D3fendSearchItem {
  id: string;
  name: string;
  tactic: string;
  parent_id: string | null;
  parent_name: string | null;
  depth: number;
  attack_count: number;
}

export interface D3fendRefSite {
  kind: 'rule' | 'scenario';
  id: string;
  name: string;
  status: Status;
  detail: string | null;
}

export interface D3fendVia {
  def_tech: string | null;
  def_rel: string | null;
  def_artifact: string | null;
  off_rel: string | null;
  off_artifact: string | null;
}

export interface D3fendTechniqueDetail {
  id: string;
  iri: string;
  name: string;
  tactic: string;
  tactic_ko: string | null;
  parent_id: string | null;
  depth: number;
  definition: string | null;
  kb_article: string | null;
  synonyms: string[];
  version: string;
  ancestors: { id: string; name: string }[];
  children: { id: string; name: string }[];
  attack: { id: string; name: string | null; domain: string; via: D3fendVia[] }[];
  mitigations: { id: string; name: string | null }[];
  designated_by: D3fendRefSite[];
}

export interface D3fendMatrixCell {
  id: string;
  name: string;
  tactic: string;
  parent_id: string | null;
  depth: number;
  attack_count: number;
  designated: number;
}

export interface D3fendMatrix {
  version: string;
  tactics: { name: string; label_ko: string; ord: number; definition: string | null; techniques: D3fendMatrixCell[] }[];
  summary: { techniques: number; designated: number };
}

export interface CountermeasureItem {
  id: string;
  name: string;
  parent_id: string | null;
  depth: number;
  definition: string | null;
  attack: string[];
  via: D3fendVia[];
  mitigations: { id: string; name: string }[];
  designated: boolean;
  recommended: boolean;
}

export interface Countermeasures {
  version: string;
  attack: string[];
  designated: string[];
  tactics: { tactic: string; label_ko: string; response: boolean; techniques: CountermeasureItem[] }[];
  attack_mitigations: { id: string; name: string; attack: string[]; d3fend: string[] }[];
  unmapped_attack: string[];
  parent_fallback: { attack: string; used: string }[];
  missing_designated: { id: string }[];
  summary: { techniques: number; designated: number; recommended: number; mapped: number };
}

export interface D3fendLinkItem {
  kind: 'rule' | 'scenario';
  id: string;
  name: string;
  status: Status;
  node: string | null;
  severity: Severity | null;
  title?: string;
  attack: string[];
  d3fend: D3fendRef[];
  mapped: number;
  response: boolean;
}

export interface D3fendLinks {
  version: string | null;
  items: D3fendLinkItem[];
  summary: { total: number; with_attack: number; with_d3fend: number; with_response: number };
}

export interface D3fendDiffResult {
  from: string | null;
  to: string;
  summary?: Record<string, number>;
  added?: { id: string; name: string; tactic: string }[];
  removed?: { id: string; name: string; tactic: string }[];
  renamed?: { id: string; from: string; to: string }[];
  moved?: { id: string; name: string; from: string; to: string }[];
  updated?: string[];
  impact: { technique: string; status: 'missing'; refs: D3fendRefSite[] }[];
}
