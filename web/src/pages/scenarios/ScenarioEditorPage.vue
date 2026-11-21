<script setup lang="ts">
// 순서도 편집기: 왼쪽 이벤트 탐지모듈·노드 목록, 가운데 Vue Flow 캔버스, 오른쪽 속성. 서버와는 그래프 JSON(설계안 5장)만 주고받는다.
import { computed, nextTick, onBeforeUnmount, ref, watch } from 'vue';
import { useRoute, useRouter } from 'vue-router';
import { ConnectionLineType, VueFlow, useVueFlow, type Connection, type GraphEdge, type GraphNode } from '@vue-flow/core';
import { Background } from '@vue-flow/background';
import { Controls } from '@vue-flow/controls';
import { MiniMap } from '@vue-flow/minimap';
import { ApiError, api, enc } from '../../api';
import { has } from '../../auth';
import { useAsync, useMeta } from '../../composables';
import BacktestPanel from '../../components/BacktestPanel.vue';
import CardBox from '../../components/CardBox.vue';
import ChangeNoteModal from '../../components/ChangeNoteModal.vue';
import ErrorBox from '../../components/ErrorBox.vue';
import LoadingBox from '../../components/LoadingBox.vue';
import NoticeBox from '../../components/NoticeBox.vue';
import StatusControl from '../../components/StatusControl.vue';
import TabBar from '../../components/TabBar.vue';
import type {
  Graph,
  GraphIssue,
  NodeSim,
  RuleSummary,
  ScenarioDetail,
  ScenarioSaveResponse,
  ScenarioGroupList,
  ScenarioSummary,
  SimulateResponse,
  Status,
  ValidateResponse,
} from '../../types';
import { downloadJson, fmtSec, fmtTime } from '../../util';
import ScenarioIcon from '../../components/ScenarioIcon.vue';
import RuleEditorPage from '../single-rules/RuleEditorPage.vue';
import FlowEdgeView from './FlowEdgeView.vue';
import FlowNodeView from './FlowNodeView.vue';
import PaletteBox from './PaletteBox.vue';
import PropertiesPanel from './PropertiesPanel.vue';
import ResultPanel from './ResultPanel.vue';
import ScenarioVersionsTab from './ScenarioVersionsTab.vue';
import SimulateModal from './SimulateModal.vue';
import {
  DIAMONDS,
  FLOW_NODE_TYPE,
  PALETTE_DND_TYPE,
  defaultProps,
  edgeId,
  gtype,
  nextNodeId,
  layoutGraph,
  styleEdge,
  toFlow,
  toGraph,
  type FlowEdge,
  type FlowNode,
  type GraphMeta,
  type LeveledIssue,
  type NodeProps_,
  type PaletteItem,
} from './graph';

const props = defineProps<{ scenarioId?: string }>();
const router = useRouter();
const route = useRoute();

// 화면 분류용 그룹 (그래프 JSON 밖이라 바꿔도 버전이 올라가지 않는다). 새 시나리오는 목록에서 고른 그룹(?group=)으로 시작
const groupsQ = useAsync(() => api.get<ScenarioGroupList>('/scenario-groups'));
const groupSel = ref<string>(typeof route.query.group === 'string' && /^[0-9]+$/.test(route.query.group) ? route.query.group : '');
async function assignGroup(sid: string) {
  await api.put('/scenario-groups/assign', { group_id: groupSel.value ? Number(groupSel.value) : null, scenario_ids: [sid] });
}
async function onGroupChange() {
  if (isNew.value || !props.scenarioId) return; // 새 시나리오는 저장할 때 넣는다
  try {
    await assignGroup(props.scenarioId);
    message.value = { kind: 'ok', text: '그룹을 바꿨습니다 (순서도 버전은 그대로)' };
  } catch (e) {
    actionError.value = e;
  }
}
const isNew = computed(() => !props.scenarioId);
const readOnly = computed(() => !has('author'));
const metaF = useMeta();
const rulesQ = useAsync(() => api.get<RuleSummary[]>('/single-rules'));

// 화면마다 새 Vue Flow 저장소 (다른 순서도를 열면 컴포넌트가 새로 만들어진다)
const flowId = `scenario-editor-${Math.random().toString(36).slice(2, 8)}`;
const vf = useVueFlow(flowId);
const { nodes, edges } = vf;
const fnodes = computed(() => nodes.value as unknown as FlowNode[]);
const fedges = computed(() => edges.value as unknown as FlowEdge[]);

const meta = ref<GraphMeta | null>(null);
const summary = ref<ScenarioSummary | null>(null);
const loadError = ref<unknown>(null);
const issues = ref<LeveledIssue[]>([]);
const validated = ref<ValidateResponse | null>(null);
const sim = ref<SimulateResponse | null>(null);
const simOpen = ref(false);
const saveOpen = ref(false);
const saving = ref(false);
const busy = ref<string | null>(null);
const actionError = ref<unknown>(null);
const message = ref<{ kind: 'ok' | 'warn' | 'info'; text: string } | null>(null);
const dirty = ref(false);
const tab = ref('result');
const fileInput = ref<HTMLInputElement | null>(null);
const bottom = ref<HTMLElement | null>(null);
const canvas = ref<HTMLElement | null>(null);
let quiet = false; // 프로그램이 그래프를 바꾸는 동안 "저장 안 됨" 을 켜지 않는다

function markDirty() {
  if (!quiet) dirty.value = true;
}

// ---------- 불러오기 ----------
function loadGraph(g: Graph, markAsDirty = false) {
  quiet = true;
  const f = toFlow(g);
  meta.value = f.meta;
  // 같은 ID 의 노드를 다시 넣을 때 Vue Flow 가 이전 노드에 붙은 화살표를 지우므로, 화살표는 노드가 바뀐 다음에 넣는다
  vf.setEdges([]);
  vf.setNodes(f.nodes as unknown as GraphNode[]);
  sim.value = null;
  void nextTick(() => {
    vf.setEdges(f.edges as unknown as GraphEdge[]);
    void nextTick(() => {
      quiet = false;
      dirty.value = markAsDirty;
      restyleEdges();
    });
  });
}

function withoutStatus(g: Graph): Graph {
  const c = { ...g };
  delete c.status;
  return c;
}

if (isNew.value) {
  loadGraph({ id: '', name: '', entity_type: '', suppress_for: '6h', nodes: [{ id: 'n0', type: 'start', pos: [40, 160] }], edges: [] });
} else {
  api
    .get<ScenarioDetail>(`/scenarios/${enc(props.scenarioId ?? '')}`)
    .then((d) => {
      loadGraph(withoutStatus(d.graph));
      summary.value = d.scenario;
      groupSel.value = d.scenario.group_id != null ? String(d.scenario.group_id) : '';
      issues.value = d.warnings.map((w) => ({ ...w, level: 'warn' as const }));
    })
    .catch((e: unknown) => (loadError.value = e));
}

// 새 순서도면 대상 유형 기본값을 /meta/fields 첫 항목으로
watch(
  () => metaF.data.value,
  (m) => {
    const first = m?.entity_types[0]?.type;
    if (isNew.value && first && meta.value && !meta.value.entity_type) meta.value.entity_type = first;
  },
  { immediate: true },
);

vf.onNodesChange((changes) => {
  if (changes.some((c) => c.type !== 'select' && c.type !== 'dimensions')) markDirty();
});
vf.onEdgesChange((changes) => {
  if (changes.some((c) => c.type !== 'select')) markDirty();
});

// ---------- 파생 상태 ----------
const rulesForEntity = computed(() => (rulesQ.data.value ?? []).filter((r) => !meta.value || r.entity_type === meta.value.entity_type));
const ruleNames = computed<Record<string, string>>(() => Object.fromEntries((rulesQ.data.value ?? []).map((r) => [r.rule_id, r.name])));
const issueMaps = computed(() => {
  const nodeErr: Record<string, string[]> = {};
  const nodeWarn: Record<string, string[]> = {};
  const edgeErr: Record<string, string[]> = {};
  for (const i of issues.value) {
    if (i.target === 'node') {
      const m = i.level === 'error' ? nodeErr : nodeWarn;
      (m[i.id] ??= []).push(i.message);
    }
    if (i.target === 'edge' && i.level === 'error') (edgeErr[i.id] ??= []).push(i.message);
  }
  return { nodeErr, nodeWarn, edgeErr };
});
const simMap = computed<Record<string, NodeSim>>(() => sim.value?.node_status ?? {});

/** 화살표 색·라벨: 검증 오류(빨강), 시뮬레이션 통과 경로(초록), 분기·허용 시간 라벨. */
function restyleEdges() {
  const types = Object.fromEntries(fnodes.value.map((n) => [n.id, gtype(n)]));
  for (const e of edges.value) {
    const fe = e as unknown as FlowEdge;
    let flow: 'reached' | 'none' | undefined;
    if (sim.value) {
      const s = simMap.value[fe.source];
      const t = simMap.value[fe.target];
      flow = 'none';
      if (s?.status === 'reached' && t?.status === 'reached') {
        if (!fe.sourceHandle) flow = 'reached';
        else if (types[fe.source] === 'check') flow = ((fe.sourceHandle === 'yes' ? s.yes : s.no) ?? 0) > 0 ? 'reached' : 'none';
        else flow = s.result === fe.sourceHandle ? 'reached' : 'none';
      }
    }
    const st = styleEdge({ ...fe, data: { ...fe.data, issues: issueMaps.value.edgeErr[fe.id], flow } }, false);
    Object.assign(e, {
      type: st.type,
      label: st.label,
      labelStyle: st.labelStyle,
      labelBgStyle: st.labelBgStyle,
      labelBgPadding: st.labelBgPadding,
      labelBgBorderRadius: st.labelBgBorderRadius,
      style: st.style,
      markerEnd: st.markerEnd,
    });
  }
}
watch(
  [() => edges.value.map((e) => `${e.id}|${e.sourceHandle ?? ''}|${(e.data as FlowEdge['data'])?.within ?? ''}`).join(','), issueMaps, sim],
  () => restyleEdges(),
);

const selNodes = computed(() => vf.getSelectedNodes.value);
const selEdges = computed(() => vf.getSelectedEdges.value);
const selectedNode = computed(() =>
  selNodes.value.length === 1 && !selEdges.value.length ? (selNodes.value[0] as unknown as FlowNode) : null,
);
const selectedEdge = computed(() =>
  selEdges.value.length === 1 && !selNodes.value.length ? (selEdges.value[0] as unknown as FlowEdge) : null,
);
const hasStart = computed(() => fnodes.value.some((n) => gtype(n) === 'start'));
const graphIssues = computed(() => issues.value.filter((i) => i.target === 'graph'));
const errorCount = computed(() => issues.value.filter((i) => i.level === 'error').length);

// ---------- 편집 동작 ----------
function selectOnly(kind: 'node' | 'edge' | null, id?: string) {
  vf.removeSelectedElements();
  if (kind === 'node' && id) {
    const n = vf.findNode(id);
    if (n) vf.addSelectedNodes([n]);
  } else if (kind === 'edge' && id) {
    const e = vf.findEdge(id);
    if (e) vf.addSelectedEdges([e]);
  }
}

function addNode(item: PaletteItem, position: { x: number; y: number }) {
  if (readOnly.value) return;
  if (item.type === 'start' && hasStart.value) {
    message.value = { kind: 'warn', text: '시작 노드는 1개만 둘 수 있습니다' };
    return;
  }
  const id = nextNodeId(item.type, fnodes.value.map((n) => n.id));
  const extra: Partial<NodeProps_> = item.rule_id ? { rule_id: item.rule_id } : {};
  vf.addNodes([{ id, type: FLOW_NODE_TYPE, position, data: { g: defaultProps(item.type, extra) }, deletable: item.type !== 'start' }]);
  markDirty();
  void nextTick(() => selectOnly('node', id));
}

function onDragOver(e: DragEvent) {
  e.preventDefault();
  if (e.dataTransfer) e.dataTransfer.dropEffect = 'move';
}

function onDrop(e: DragEvent) {
  e.preventDefault();
  const raw = e.dataTransfer?.getData(PALETTE_DND_TYPE) || e.dataTransfer?.getData('text/plain');
  if (!raw) return;
  let item: PaletteItem;
  try {
    item = JSON.parse(raw) as PaletteItem;
  } catch {
    return;
  }
  if (!item.type) return;
  const p = vf.screenToFlowCoordinate({ x: e.clientX, y: e.clientY });
  addNode(item, { x: p.x - 60, y: p.y - 30 });
}

function addAtCenter(item: PaletteItem) {
  const r = canvas.value?.getBoundingClientRect();
  const jitter = (fnodes.value.length % 5) * 24;
  const p = r ? vf.screenToFlowCoordinate({ x: r.left + r.width / 2 + jitter, y: r.top + r.height / 2 + jitter }) : { x: 200, y: 200 };
  addNode(item, { x: p.x - 60, y: p.y - 30 });
}

function isValidConnection(c: Connection): boolean {
  const { source, target } = c;
  if (!source || !target || source === target) return false;
  const sn = fnodes.value.find((n) => n.id === source);
  const tn = fnodes.value.find((n) => n.id === target);
  if (!sn || !tn || gtype(tn) === 'start' || gtype(sn) === 'alert') return false;
  if (fedges.value.some((e) => e.source === source && e.target === target)) return false;
  if (DIAMONDS.has(gtype(sn))) {
    const h = c.sourceHandle;
    if (h !== 'yes' && h !== 'no') return false;
    if (fedges.value.some((e) => e.source === source && e.sourceHandle === h)) return false; // 이미 쓴 가지
  }
  return true;
}

vf.onConnect((c) => {
  if (readOnly.value || !isValidConnection(c)) return;
  const sn = fnodes.value.find((n) => n.id === c.source);
  const tn = fnodes.value.find((n) => n.id === c.target);
  const diamond = sn ? DIAMONDS.has(gtype(sn)) : false;
  const needsWithin = !!tn && gtype(tn) === 'rule' && !!sn && gtype(sn) !== 'start';
  const id = edgeId(c.source, c.target);
  vf.addEdges([
    {
      id,
      source: c.source,
      target: c.target,
      sourceHandle: diamond ? c.sourceHandle ?? undefined : undefined,
      data: needsWithin ? { within: '30m' } : {},
    },
  ]);
  markDirty();
  void nextTick(() => {
    restyleEdges();
    selectOnly('edge', id);
  });
  if (needsWithin) {
    message.value = { kind: 'info', text: `${c.source} → ${c.target}: 허용 시간 기본값 30분을 넣었습니다. 오른쪽에서 바꿀 수 있습니다.` };
  }
});

function renameNode(id: string, newId: string): string | null {
  if (newId === id) return null;
  if (fnodes.value.some((n) => n.id === newId)) return '이미 있는 노드 ID 입니다';
  const g = currentGraph();
  if (!g) return null;
  g.nodes = g.nodes.map((n) => (n.id === id ? { ...n, id: newId } : n));
  g.edges = g.edges.map((e) => ({ ...e, from: e.from === id ? newId : e.from, to: e.to === id ? newId : e.to }));
  loadGraph(g, true);
  void nextTick(() => selectOnly('node', newId));
  return null;
}

function deleteSelected() {
  const goneNodes = selNodes.value.filter((n) => gtype(n as unknown as FlowNode) !== 'start');
  if (goneNodes.length) vf.removeNodes(goneNodes);
  if (selEdges.value.length) vf.removeEdges(selEdges.value);
  markDirty();
}

/** 자동 정렬: 그래프를 다시 불러오지 않고 노드 위치만 옮긴다 (선택·화살표 유지). */
function relayout() {
  if (readOnly.value) return;
  const pos = layoutGraph(
    fnodes.value.map((n) => ({ id: n.id, type: gtype(n) })),
    fedges.value.map((e) => ({ from: e.source, to: e.target, branch: e.sourceHandle })),
  );
  for (const n of nodes.value) {
    const p = pos[n.id];
    if (p) n.position = { x: p.x, y: p.y };
  }
  markDirty();
  setTimeout(() => void vf.fitView({ padding: 0.2, duration: 250 }), 30);
}

function fit() {
  void vf.fitView({ padding: 0.2, duration: 250 });
}

/** 노드 도구 막대: 편집(이벤트 탐지모듈 옆 패널) / 복제 / 삭제 */
function onNodeAction(id: string, kind: 'edit' | 'duplicate' | 'delete') {
  const n = fnodes.value.find((x) => x.id === id);
  if (!n) return;
  if (kind === 'edit') {
    if (n.data?.g.rule_id) openRuleEditor(n.data.g.rule_id);
    return;
  }
  if (readOnly.value) return;
  if (kind === 'delete') {
    if (gtype(n) !== 'start') vf.removeNodes([id]);
    markDirty();
    return;
  }
  const type = gtype(n);
  if (type === 'start') return;
  const nid = nextNodeId(type, fnodes.value.map((x) => x.id));
  const g = JSON.parse(JSON.stringify(n.data?.g ?? defaultProps(type))) as NodeProps_;
  vf.addNodes([{ id: nid, type: FLOW_NODE_TYPE, position: { x: n.position.x + 30, y: n.position.y + 110 }, data: { g }, deletable: true }]);
  markDirty();
  void nextTick(() => selectOnly('node', nid));
}

vf.onNodeDoubleClick(({ node }) => {
  const g = (node as unknown as FlowNode).data?.g;
  if (g?.type === 'rule' && g.rule_id) openRuleEditor(g.rule_id);
});

function removeEdge(id: string) {
  if (readOnly.value) return;
  vf.removeEdges([id]);
  markDirty();
}

// ---------- 이벤트 탐지모듈 옆 패널 (만들기·편집) ----------
interface Drawer {
  key: number;
  ruleId?: string;
  /** 새로 만든 탐지를 넣을 rule 노드 (없으면 새 노드를 만든다) */
  forNode?: string;
  created?: boolean;
}
const drawer = ref<Drawer | null>(null);
const drawerDirty = ref(false);
let drawerSeq = 0;

function confirmLeaveDrawer(): boolean {
  return !drawerDirty.value || window.confirm('이벤트 탐지모듈에 저장하지 않은 변경이 있습니다. 닫을까요?');
}
function openRuleEditor(ruleId: string) {
  if (drawer.value && !confirmLeaveDrawer()) return;
  drawerDirty.value = false;
  drawer.value = { key: ++drawerSeq, ruleId };
}
function openNewRule(forNode?: string) {
  if (readOnly.value) return;
  if (drawer.value && !confirmLeaveDrawer()) return;
  drawerDirty.value = false;
  drawer.value = { key: ++drawerSeq, forNode };
}
function closeDrawer() {
  if (!confirmLeaveDrawer()) return;
  drawer.value = null;
  drawerDirty.value = false;
}
function onRuleSaved(ruleId: string) {
  rulesQ.reload();
  const d = drawer.value;
  if (!d) return;
  if (!d.ruleId && !d.created) {
    // 새로 만든 탐지: 고른 rule 노드에 넣거나, 새 노드로 추가
    const target = d.forNode ? fnodes.value.find((n) => n.id === d.forNode) : undefined;
    if (target?.data) {
      target.data.g.rule_id = ruleId;
      markDirty();
    } else {
      addAtCenter({ type: 'rule', rule_id: ruleId });
    }
    d.created = true;
    message.value = { kind: 'ok', text: `이벤트 탐지모듈 ${ruleId} 를 만들어 순서도에 넣었습니다. 시나리오도 저장해야 반영됩니다.` };
  } else {
    message.value = { kind: 'ok', text: `이벤트 탐지모듈 ${ruleId} 를 저장했습니다.` };
  }
}
function onWindowKey(e: KeyboardEvent) {
  if (e.key === 'Escape' && drawer.value) closeDrawer();
}
window.addEventListener('keydown', onWindowKey);
onBeforeUnmount(() => window.removeEventListener('keydown', onWindowKey));

const moreOpen = ref(false);

const MINI_COLOR: Record<string, string> = {
  start: '#6c7a89',
  rule: '#0095ff',
  check: '#f5b041',
  asset: '#00d1b9',
  and: '#8a91a2',
  or: '#8a91a2',
  alert: '#ff6b6b',
};
function miniColor(n: { data?: FlowNode['data'] }): string {
  return MINI_COLOR[n.data?.g.type ?? 'rule'] ?? '#8a91a2';
}

// ---------- 서버 동작 ----------
function currentGraph(): Graph | null {
  return meta.value ? toGraph(meta.value, fnodes.value, fedges.value) : null;
}

function applyIssues(errors: GraphIssue[], warnings: GraphIssue[]) {
  issues.value = [...errors.map((e) => ({ ...e, level: 'error' as const })), ...warnings.map((w) => ({ ...w, level: 'warn' as const }))];
}

function issuesFromError(e: unknown): boolean {
  if (e instanceof ApiError && e.errors.length) {
    const conv = (l: typeof e.errors): GraphIssue[] => l.map((i) => ({ target: i.target ?? 'graph', id: i.id ?? i.path ?? '', message: i.message }));
    applyIssues(conv(e.errors), conv(e.warnings));
    return true;
  }
  return false;
}

function focusBottom(t: string) {
  tab.value = t;
  setTimeout(() => bottom.value?.scrollIntoView({ behavior: 'smooth', block: 'start' }), 30);
}

async function validate() {
  const g = currentGraph();
  if (!g) return;
  busy.value = 'validate';
  actionError.value = null;
  try {
    const r = await api.post<ValidateResponse>('/scenarios/validate', { graph: g });
    applyIssues(r.errors, r.warnings);
    validated.value = r;
    message.value = r.ok
      ? { kind: 'ok', text: `검증 통과 · 최대 기간 ${fmtSec(r.max_span_sec)}${r.warnings.length ? ` · 경고 ${r.warnings.length}건` : ''}` }
      : { kind: 'warn', text: `검증 오류 ${r.errors.length}건 — 빨간 테두리를 확인하세요` };
    focusBottom('result');
  } catch (e) {
    if (!issuesFromError(e)) actionError.value = e;
  } finally {
    busy.value = null;
  }
}

async function simulate(p: { org_id: string; entity: string; time_from: string; time_to: string }) {
  const g = currentGraph();
  if (!g) return;
  busy.value = 'simulate';
  actionError.value = null;
  try {
    const r = await api.post<SimulateResponse>('/scenarios/simulate', { graph: g, ...p });
    if (!r.ok) {
      applyIssues(r.errors ?? [], []);
      sim.value = null;
      message.value = { kind: 'warn', text: '순서도에 오류가 있어 시뮬레이션할 수 없습니다' };
    } else {
      sim.value = r;
      issues.value = issues.value.filter((i) => i.level === 'warn');
      message.value = r.alert
        ? { kind: 'ok', text: `경보 노드 ${r.alert.node} 에 도달: ${r.alert.title}` }
        : { kind: 'info', text: '경보 노드에 도달하지 않았습니다. 빨간 노드의 이유를 확인하세요.' };
    }
    simOpen.value = false;
    focusBottom('result');
  } catch (e) {
    if (!issuesFromError(e)) actionError.value = e;
    simOpen.value = false;
  } finally {
    busy.value = null;
  }
}

async function save(note: string) {
  const g = currentGraph();
  if (!g) return;
  saving.value = true;
  actionError.value = null;
  try {
    const body = { graph: g, change_note: note || null };
    const r = isNew.value
      ? await api.post<ScenarioSaveResponse>('/scenarios', body)
      : await api.put<ScenarioSaveResponse>(`/scenarios/${enc(props.scenarioId ?? '')}`, body);
    summary.value = r.scenario;
    applyIssues([], r.warnings);
    dirty.value = false;
    message.value = { kind: 'ok', text: `저장했습니다 (v${r.scenario.version})${r.warnings.length ? ` · 경고 ${r.warnings.length}건` : ''}` };
    saveOpen.value = false;
    if (isNew.value && groupSel.value) await assignGroup(r.scenario.scenario_id);
    if (isNew.value) await router.replace(`/scenarios/${r.scenario.scenario_id}`);
  } catch (e) {
    saveOpen.value = false;
    issuesFromError(e);
    actionError.value = e;
  } finally {
    saving.value = false;
  }
}

async function changeStatus(s: Status) {
  try {
    const r = await api.post<{ scenario: ScenarioSummary }>(`/scenarios/${enc(props.scenarioId ?? '')}/status`, { status: s });
    summary.value = r.scenario;
    message.value = { kind: 'ok', text: `상태를 ${s} 로 바꿨습니다` };
  } catch (e) {
    issuesFromError(e);
    throw e;
  }
}

function exportJson() {
  const g = currentGraph();
  if (g) downloadJson(`${g.id || 'scenario'}.json`, g);
}

async function importJson(file: File) {
  try {
    const v: unknown = JSON.parse(await file.text());
    if (typeof v !== 'object' || v === null || !Array.isArray((v as Graph).nodes) || !Array.isArray((v as Graph).edges)) {
      throw new Error('nodes 와 edges 가 있는 순서도 JSON 이 아닙니다');
    }
    const g = withoutStatus(v as Graph);
    if (!isNew.value && props.scenarioId && g.id !== props.scenarioId) {
      g.id = props.scenarioId;
      message.value = { kind: 'warn', text: `가져온 그래프의 ID 를 현재 순서도 ID(${props.scenarioId})로 바꿨습니다` };
    } else {
      message.value = { kind: 'ok', text: `${file.name} 을(를) 불러왔습니다. 저장해야 반영됩니다.` };
    }
    loadGraph(g, true);
    setTimeout(() => void vf.fitView({ padding: 0.2 }), 60);
  } catch (e) {
    actionError.value = e;
  }
}

function onFile(e: Event) {
  const input = e.target as HTMLInputElement;
  const f = input.files?.[0];
  if (f) void importJson(f);
  input.value = '';
}

function loadVersion(g: Graph) {
  loadGraph(withoutStatus(g), true);
  message.value = { kind: 'info', text: '이전 버전을 편집기로 불러왔습니다. 저장하면 새 버전이 됩니다.' };
  setTimeout(() => void vf.fitView({ padding: 0.2 }), 60);
}

function pickIssue(i: LeveledIssue) {
  if (i.target === 'node') selectOnly('node', i.id);
  else if (i.target === 'edge') selectOnly('edge', i.id);
  else selectOnly(null);
}

const tabs = computed(() => [
  { key: 'result', label: `검증·시뮬레이션 결과${issues.value.length ? ` (${issues.value.length})` : ''}` },
  { key: 'backtest', label: '백테스트', hidden: readOnly.value },
  { key: 'versions', label: '버전 이력', hidden: isNew.value },
]);
</script>

<template>
  <ErrorBox v-if="loadError" :error="loadError" />
  <LoadingBox v-else-if="!meta" />
  <div v-else class="page scenario-editor">
    <RouterLink to="/scenarios" class="back-link" data-testid="scenario-back">← 시나리오 분석</RouterLink>
    <div class="editor-head">
      <div class="editor-title">
        <h2>
          <ScenarioIcon class="title-ico" :size="20" />
          {{ meta.name || (isNew ? '새 시나리오' : scenarioId) }}
          <span v-if="!isNew" class="item-id title-id">{{ scenarioId }}</span>
          <span v-if="dirty" class="dirty" data-testid="dirty">● 저장 안 됨</span>
        </h2>
        <label class="group-pick small">
          그룹
          <select v-model="groupSel" :disabled="readOnly" data-testid="scenario-group" @change="onGroupChange">
            <option value="">미분류</option>
            <option v-for="g in groupsQ.data.value?.groups ?? []" :key="g.group_id" :value="String(g.group_id)">{{ g.name }}</option>
          </select>
        </label>
        <div v-if="summary" class="subhead">
          <StatusControl :current="summary.status" :change="changeStatus" :disabled="isNew" />
          <span class="muted small">v{{ summary.version }} · 최대 기간 {{ fmtSec(summary.max_span_sec) }} · 수정 {{ fmtTime(summary.updated_at) }}</span>
        </div>
      </div>
      <div class="actions toolbar" data-testid="scenario-toolbar">
        <div class="btn-group">
          <button :disabled="!!busy || readOnly" data-testid="scenario-validate" @click="validate">{{ busy === 'validate' ? '검증 중…' : '✓ 검증' }}</button>
          <button :disabled="!!busy || readOnly" data-testid="scenario-simulate" @click="simOpen = true">{{ busy === 'simulate' ? '시뮬레이션 중…' : '▷ 시뮬레이션' }}</button>
          <button v-if="sim" data-testid="scenario-sim-clear" title="시뮬레이션 표시 지우기" @click="sim = null">✕</button>
        </div>
        <div class="btn-group">
          <button :disabled="readOnly" data-testid="scenario-backtest" @click="focusBottom('backtest')">백테스트</button>
          <button :disabled="isNew" data-testid="scenario-versions" @click="focusBottom('versions')">버전 이력</button>
        </div>
        <div class="menu-wrap">
          <button class="icon-btn" aria-label="더보기" data-testid="scenario-more" @click="moreOpen = !moreOpen">⋯</button>
          <div v-if="moreOpen" class="menu" @click="moreOpen = false">
            <button class="menu-item" data-testid="scenario-export" @click="exportJson">JSON 내보내기</button>
            <button v-if="!readOnly" class="menu-item" data-testid="scenario-import" @click="fileInput?.click()">JSON 가져오기</button>
          </div>
        </div>
        <input ref="fileInput" type="file" accept=".json,application/json" hidden data-testid="scenario-import-file" @change="onFile" />
        <button v-if="!readOnly" class="primary" data-testid="scenario-save" @click="saveOpen = true">저장</button>
      </div>
    </div>
    <NoticeBox v-if="message" :kind="message.kind">
      {{ message.text }} <button class="link small" @click="message = null">닫기</button>
    </NoticeBox>
    <ErrorBox :error="actionError" closable @close="actionError = null" />

    <div class="flow-layout">
      <PaletteBox
        :rules="rulesForEntity"
        :loading="rulesQ.loading.value"
        :entity-type="meta.entity_type"
        :read-only="readOnly"
        :has-start="hasStart"
        @add="addAtCenter"
        @create-rule="openNewRule()"
      />
      <div ref="canvas" class="flow-canvas" data-testid="scenario-canvas" @drop="onDrop" @dragover="onDragOver">
        <VueFlow
          :id="flowId"
          :is-valid-connection="isValidConnection"
          :nodes-draggable="!readOnly"
          :nodes-connectable="!readOnly"
          :delete-key-code="readOnly ? null : ['Delete', 'Backspace']"
          :connection-line-options="{ type: ConnectionLineType.SmoothStep, style: { stroke: '#0095ff', strokeWidth: 2 } }"
          :snap-to-grid="true"
          :snap-grid="[8, 8]"
          :min-zoom="0.2"
          :max-zoom="2"
          :zoom-on-double-click="false"
          fit-view-on-init
        >
          <template #node-scn="p">
            <FlowNodeView
              :id="p.id"
              :data="p.data"
              :selected="p.selected"
              :issues="issueMaps.nodeErr[p.id]"
              :warnings="issueMaps.nodeWarn[p.id]"
              :sim="simMap[p.id]"
              :rule-name="ruleNames[p.data.g.rule_id ?? '']"
              :editable="!readOnly"
              @action="(k) => onNodeAction(p.id, k)"
            />
          </template>
          <template #edge-scn="p">
            <FlowEdgeView v-bind="p" :editable="!readOnly" @remove="removeEdge" />
          </template>
          <Background :gap="22" :size="1.2" pattern-color="#3a3f48" />
          <Controls :show-interactive="false" position="bottom-left" />
          <MiniMap pannable zoomable :node-color="miniColor" mask-color="rgba(10, 12, 16, 0.6)" />
        </VueFlow>
        <div class="canvas-tools">
          <button class="small" :disabled="readOnly" title="흐름 방향으로 노드를 다시 배치" @click="relayout">자동 정렬</button>
          <button class="small" title="순서도 전체가 보이게" data-testid="scenario-fit" @click="fit">화면 맞춤</button>
        </div>
        <div v-if="errorCount > 0" class="canvas-badge">오류 {{ errorCount }}건</div>
        <div v-if="fnodes.length <= 1 && !readOnly" class="canvas-empty">
          <strong>순서도를 만들어 보세요</strong>
          <span>왼쪽에서 이벤트 탐지모듈을 끌어다 놓고, 시작 노드의 오른쪽 점을 끌어 잇습니다.</span>
        </div>
      </div>
      <aside class="flow-props">
        <PropertiesPanel
          :meta="meta"
          :is-new="isNew"
          :meta-fields="metaF.data.value"
          :rules="rulesForEntity"
          :node="selectedNode"
          :edge="selectedEdge"
          :nodes="fnodes"
          :edges="fedges"
          :graph-issues="graphIssues"
          :node-issues="selectedNode ? issueMaps.nodeErr[selectedNode.id] ?? [] : []"
          :node-warnings="selectedNode ? issueMaps.nodeWarn[selectedNode.id] ?? [] : []"
          :edge-issues="selectedEdge ? issueMaps.edgeErr[selectedEdge.id] ?? [] : []"
          :sim="selectedNode ? simMap[selectedNode.id] : undefined"
          :read-only="readOnly"
          :rename="renameNode"
          @changed="markDirty(), restyleEdges()"
          @delete="deleteSelected"
          @edit-rule="openRuleEditor"
          @new-rule="openNewRule(selectedNode?.id)"
        />
        <datalist id="scn-dur"><option v-for="d in ['5m', '10m', '30m', '1h', '6h', '12h', '24h', '1d', '3d', '7d']" :key="d" :value="d" /></datalist>
      </aside>
    </div>

    <div ref="bottom">
      <CardBox>
        <TabBar v-model="tab" :tabs="tabs" />
        <div class="tab-body">
          <ResultPanel v-if="tab === 'result'" :issues="issues" :validated="validated" :sim="sim" @pick="pickIssue" />
          <template v-if="tab === 'backtest' && !readOnly">
            <NoticeBox v-if="isNew" kind="info">저장한 뒤 백테스트를 실행할 수 있습니다.</NoticeBox>
            <BacktestPanel v-else target-type="scenario" :target-id="meta.id" :get-definition="currentGraph" />
          </template>
          <ScenarioVersionsTab v-if="tab === 'versions' && scenarioId" :sid="scenarioId" @load="loadVersion" />
        </div>
      </CardBox>
    </div>

    <!-- 이벤트 탐지모듈 옆 패널: 순서도를 떠나지 않고 만들고 고친다 -->
    <Transition name="drawer">
      <div v-if="drawer" class="drawer-backdrop" data-testid="rule-drawer-backdrop" @click.self="closeDrawer">
        <aside class="drawer" data-testid="rule-drawer">
          <RuleEditorPage
            :key="drawer.key"
            :rule-id="drawer.ruleId"
            :entity-type="meta.entity_type"
            embedded
            @saved="onRuleSaved"
            @close="closeDrawer"
            @dirty="(v) => (drawerDirty = v)"
          />
        </aside>
      </div>
    </Transition>

    <SimulateModal v-if="simOpen" :busy="busy === 'simulate'" @close="simOpen = false" @run="simulate" />
    <ChangeNoteModal v-if="saveOpen" :title="isNew ? '새 시나리오 저장' : '새 버전으로 저장'" :busy="saving" @close="saveOpen = false" @submit="save" />
  </div>
</template>
