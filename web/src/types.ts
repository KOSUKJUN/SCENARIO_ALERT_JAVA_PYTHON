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

// ---------- 단일룰 ----------
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
}

export interface AlertDetail extends AlertItem {
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
