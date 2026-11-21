// 그래프 JSON(설계안 5장) ↔ Vue Flow 노드·화살표 변환. 서버와는 그래프 JSON 만 주고받는다.
import { MarkerType, type Edge, type Node } from '@vue-flow/core';
import type { Graph, GraphEdge, GraphIssue, GraphNode, NodeSim, NodeType } from '../../types';
import { fmtDuration } from '../../util';

export type NodeProps_ = Omit<GraphNode, 'id' | 'pos'>;

export type FlowNodeData = {
  g: NodeProps_;
  issues?: string[];
  warnings?: string[];
  sim?: NodeSim;
  highlight?: boolean;
};
export type FlowNode = Node<FlowNodeData>;

/** Vue Flow 에는 노드 유형을 하나(scn)로 넘기고, 실제 유형은 data.g.type (그래프 JSON 의 type) 으로 그린다. */
export const FLOW_NODE_TYPE = 'scn';

export function gtype(n: { data?: FlowNodeData }): NodeType {
  return n.data?.g.type ?? 'rule';
}

export type FlowEdgeData = {
  within?: string;
  issues?: string[];
  flow?: 'reached' | 'none';
  highlight?: boolean;
};
export type FlowEdge = Edge<FlowEdgeData>;

export interface GraphMeta {
  id: string;
  name: string;
  description?: string;
  entity_type: string;
  suppress_for: string;
}

/** 왼쪽 목록에서 끌어다 놓을 때 dataTransfer 에 싣는 항목. */
export interface PaletteItem {
  type: NodeType;
  rule_id?: string;
}
export const PALETTE_DND_TYPE = 'application/x-scenario-node';

export type LeveledIssue = GraphIssue & { level: 'error' | 'warn' };

export const DIAMONDS = new Set<NodeType>(['check', 'asset']);

export function edgeId(from: string, to: string): string {
  return `${from}->${to}`;
}

/** 화면에 그리는 노드 크기 (styles.css 의 .fnode 크기와 맞춘다). 자동 정렬 간격 계산에 쓴다. */
export const NODE_SIZE: Record<NodeType, { w: number; h: number }> = {
  start: { w: 80, h: 36 },
  rule: { w: 210, h: 62 },
  check: { w: 170, h: 104 },
  asset: { w: 170, h: 104 },
  and: { w: 56, h: 56 },
  or: { w: 56, h: 56 },
  alert: { w: 210, h: 56 },
};
const GAP_X = 80;
const GAP_Y = 48;

/**
 * 왼쪽 → 오른쪽 계층 배치 (외부 라이브러리 없이, 폐쇄망).
 * 1) 시작에서의 가장 긴 경로로 열을 정하고  2) 이웃의 평균 위치(무게 중심)로 열 안 순서를 정해 교차를 줄이고
 * 3) 앞뒤 노드의 가운데에 맞추되 겹치지 않게 세로 위치를 정한다. 마름모의 "예" 가지는 위, "아니오" 가지는 아래로.
 */
export function layoutGraph(
  nodes: { id: string; type: NodeType }[],
  edges: { from: string; to: string; branch?: string | null }[],
): Record<string, { x: number; y: number }> {
  const ids = nodes.map((n) => n.id);
  const typeOf: Record<string, NodeType> = Object.fromEntries(nodes.map((n) => [n.id, n.type]));
  const size = (id: string) => NODE_SIZE[typeOf[id]] ?? NODE_SIZE.rule;
  const es = edges.filter((e) => e.from in typeOf && e.to in typeOf && e.from !== e.to);
  const out: Record<string, typeof es> = Object.fromEntries(ids.map((i) => [i, []]));
  const inn: Record<string, typeof es> = Object.fromEntries(ids.map((i) => [i, []]));
  for (const e of es) {
    out[e.from].push(e);
    inn[e.to].push(e);
  }
  const bias = (b?: string | null) => (b === 'yes' ? -0.3 : b === 'no' ? 0.3 : 0);

  // 1) 열: 가장 긴 경로 (순환이 남으면 마지막 열)
  const layer: Record<string, number> = Object.fromEntries(ids.map((i) => [i, 0]));
  const deg: Record<string, number> = Object.fromEntries(ids.map((i) => [i, inn[i].length]));
  const queue = ids.filter((i) => deg[i] === 0).sort((a, b) => (typeOf[a] === 'start' ? -1 : typeOf[b] === 'start' ? 1 : 0));
  const done = new Set<string>();
  while (queue.length) {
    const n = queue.shift() as string;
    done.add(n);
    for (const e of out[n]) {
      layer[e.to] = Math.max(layer[e.to], layer[n] + 1);
      deg[e.to] -= 1;
      if (deg[e.to] === 0) queue.push(e.to);
    }
  }
  const maxL = Math.max(0, ...Object.values(layer));
  for (const i of ids) if (!done.has(i)) layer[i] = maxL + 1;
  const nLayers = Math.max(0, ...Object.values(layer)) + 1;

  // 2) 열 안 순서: 깊이 우선 방문 순서(예 먼저)에서 시작해 무게 중심으로 몇 번 다시 정렬
  const visit: string[] = [];
  const seen = new Set<string>();
  const dfs = (n: string) => {
    if (seen.has(n)) return;
    seen.add(n);
    visit.push(n);
    [...out[n]].sort((a, b) => bias(a.branch) - bias(b.branch)).forEach((e) => dfs(e.to));
  };
  ids.filter((i) => inn[i].length === 0).forEach(dfs);
  ids.forEach(dfs);
  const layers: string[][] = Array.from({ length: nLayers }, () => []);
  for (const n of visit) layers[layer[n]].push(n);
  const index: Record<string, number> = {};
  const reindex = () => layers.forEach((l) => l.forEach((n, i) => (index[n] = i)));
  reindex();
  const sortBy = (l: string[], key: (n: string) => number | null) => {
    const k = Object.fromEntries(l.map((n, i) => [n, key(n) ?? i]));
    l.sort((a, b) => k[a] - k[b]);
  };
  const avg = (xs: number[]) => (xs.length ? xs.reduce((s, x) => s + x, 0) / xs.length : null);
  for (let it = 0; it < 4; it += 1) {
    for (let l = 1; l < nLayers; l += 1) sortBy(layers[l], (n) => avg(inn[n].map((e) => index[e.from] + bias(e.branch))));
    reindex();
    for (let l = nLayers - 2; l >= 0; l -= 1) sortBy(layers[l], (n) => avg(out[n].map((e) => index[e.to] - bias(e.branch))));
    reindex();
  }

  // 3) 좌표: 열마다 x, 세로는 이웃의 가운데에 맞추고 겹침은 밀어낸다
  const colX: number[] = [];
  let x = 40;
  for (let l = 0; l < nLayers; l += 1) {
    colX.push(x);
    x += Math.max(0, ...layers[l].map((n) => size(n).w)) + GAP_X;
  }
  const cy: Record<string, number> = {};
  for (const l of layers) {
    let y = 0;
    for (const n of l) {
      cy[n] = y + size(n).h / 2;
      y += size(n).h + GAP_Y;
    }
    const shift = y / 2;
    for (const n of l) cy[n] -= shift;
  }
  const place = (l: string[], want: (n: string) => number | null) => {
    if (!l.length) return;
    const desired = l.map((n) => want(n) ?? cy[n]);
    const y = [...desired];
    for (let i = 1; i < l.length; i += 1) {
      const min = y[i - 1] + size(l[i - 1]).h / 2 + GAP_Y + size(l[i]).h / 2;
      if (y[i] < min) y[i] = min;
    }
    for (let i = l.length - 2; i >= 0; i -= 1) {
      const max = y[i + 1] - size(l[i + 1]).h / 2 - GAP_Y - size(l[i]).h / 2;
      if (y[i] > max) y[i] = max;
    }
    // 한쪽으로 밀린 만큼 전체를 되돌려 원하는 위치와의 평균 차를 0 으로
    const off = avg(desired.map((d, i) => d - y[i])) ?? 0;
    l.forEach((n, i) => (cy[n] = y[i] + off));
  };
  const branchShift = (b?: string | null) => bias(b) * 200;
  for (let it = 0; it < 3; it += 1) {
    for (let l = 1; l < nLayers; l += 1) place(layers[l], (n) => avg(inn[n].map((e) => cy[e.from] + branchShift(e.branch))));
    for (let l = nLayers - 2; l >= 0; l -= 1) place(layers[l], (n) => avg(out[n].map((e) => cy[e.to] - branchShift(e.branch))));
  }
  for (let l = 1; l < nLayers; l += 1) place(layers[l], (n) => avg(inn[n].map((e) => cy[e.from] + branchShift(e.branch))));

  const minTop = Math.min(...ids.map((n) => cy[n] - size(n).h / 2));
  const pos: Record<string, { x: number; y: number }> = {};
  for (const n of ids) pos[n] = { x: colX[layer[n]], y: Math.round(cy[n] - size(n).h / 2 - minTop + 40) };
  return pos;
}

function autoLayout(nodes: GraphNode[], edges: GraphEdge[]): Record<string, { x: number; y: number }> {
  return layoutGraph(
    nodes.map((n) => ({ id: n.id, type: n.type })),
    edges.map((e) => ({ from: e.from, to: e.to, branch: e.branch })),
  );
}

/** 저장된 좌표로 그렸을 때 두 노드가 겹치는가 (조금의 여유를 둔다) */
function overlaps(nodes: GraphNode[]): boolean {
  const boxes = nodes
    .filter((n) => Array.isArray(n.pos) && n.pos.length === 2)
    .map((n) => {
      const s = NODE_SIZE[n.type] ?? NODE_SIZE.rule;
      const [x, y] = n.pos as number[];
      return { x, y, w: s.w + 12, h: s.h + 12 };
    });
  for (let i = 0; i < boxes.length; i += 1) {
    for (let j = i + 1; j < boxes.length; j += 1) {
      const a = boxes[i];
      const b = boxes[j];
      if (a.x < b.x + b.w && b.x < a.x + a.w && a.y < b.y + b.h && b.y < a.y + a.h) return true;
    }
  }
  return false;
}

export function toFlow(graph: Graph): { meta: GraphMeta; nodes: FlowNode[]; edges: FlowEdge[] } {
  const gnodes = Array.isArray(graph.nodes) ? graph.nodes : [];
  const gedges = Array.isArray(graph.edges) ? graph.edges : [];
  // 좌표가 없거나, 저장된 좌표에서 노드가 겹치면(예전 작은 노드 모양으로 저장한 순서도) 자동 정렬로 보여 준다
  const needLayout = gnodes.some((n) => !Array.isArray(n.pos) || n.pos.length !== 2) || overlaps(gnodes);
  const layout = needLayout ? autoLayout(gnodes, gedges) : {};
  const nodes: FlowNode[] = gnodes.map((n) => {
    const { id, pos, ...rest } = n;
    const position = !needLayout && Array.isArray(pos) && pos.length === 2 ? { x: pos[0], y: pos[1] } : layout[id] ?? { x: 0, y: 0 };
    return { id, type: FLOW_NODE_TYPE, position, data: { g: rest }, deletable: n.type !== 'start' } as FlowNode;
  });
  const edges: FlowEdge[] = gedges.map((e) => ({
    id: edgeId(e.from, e.to),
    source: e.from,
    target: e.to,
    sourceHandle: e.branch ?? undefined,
    data: e.within !== undefined ? { within: e.within } : {},
  }));
  return {
    meta: {
      id: graph.id ?? '',
      name: graph.name ?? '',
      description: graph.description,
      entity_type: graph.entity_type ?? 'host',
      suppress_for: graph.suppress_for ?? '6h',
    },
    nodes,
    edges,
  };
}

/** 노드 유형에 맞는 속성만 남긴다 (서버는 모르는 속성을 오류로 본다). */
function cleanNode(id: string, g: NodeProps_, pos: { x: number; y: number }): GraphNode {
  const n: GraphNode = { id, type: g.type };
  if (g.label) n.label = g.label;
  switch (g.type) {
    case 'rule':
      n.rule_id = g.rule_id ?? '';
      break;
    case 'check':
      n.rule_ids = g.rule_ids ?? [];
      n.lookaround = g.lookaround ?? '';
      break;
    case 'asset':
      n.tags = g.tags ?? [];
      break;
    case 'and':
      n.within = g.within ?? '';
      break;
    case 'alert':
      n.severity = g.severity ?? 'medium';
      n.title = g.title ?? '';
      if (g.playbook) n.playbook = g.playbook;
      if (g.attack?.length) n.attack = [...g.attack];
      if (g.d3fend?.length) n.d3fend = [...g.d3fend];
      break;
    default:
      break;
  }
  n.pos = [Math.round(pos.x), Math.round(pos.y)];
  return n;
}

export function toGraph(meta: GraphMeta, nodes: FlowNode[], edges: FlowEdge[]): Graph {
  const g: Graph = {
    id: meta.id,
    name: meta.name,
    entity_type: meta.entity_type,
    suppress_for: meta.suppress_for,
    nodes: nodes.map((n) => cleanNode(n.id, n.data?.g ?? { type: 'rule' }, n.position)),
    edges: edges.map((e) => {
      const out: GraphEdge = { from: e.source, to: e.target };
      if (e.sourceHandle === 'yes' || e.sourceHandle === 'no') out.branch = e.sourceHandle;
      if (e.data?.within) out.within = e.data.within;
      return out;
    }),
  };
  if (meta.description) g.description = meta.description;
  return g;
}

const PREFIX: Record<NodeType, string> = { start: 's', rule: 'n', check: 'n', asset: 'n', and: 'j', or: 'j', alert: 'a' };

export function nextNodeId(type: NodeType, existing: Iterable<string>): string {
  const used = new Set(existing);
  const p = PREFIX[type];
  for (let i = 1; i < 10000; i += 1) {
    if (!used.has(`${p}${i}`)) return `${p}${i}`;
  }
  return `${p}${Date.now()}`;
}

export function defaultProps(type: NodeType, extra: Partial<NodeProps_> = {}): NodeProps_ {
  switch (type) {
    case 'rule':
      return { type, rule_id: '', ...extra };
    case 'check':
      return { type, rule_ids: [], lookaround: '24h', ...extra };
    case 'asset':
      return { type, tags: [], ...extra };
    case 'and':
      return { type, within: '1h', ...extra };
    case 'alert':
      return { type, severity: 'medium', title: '경보: {{entity}}', playbook: '', ...extra };
    default:
      return { type, ...extra };
  }
}

/** 화살표 위 표시: "예" / "아니오" / "30분 내" */
export function edgeLabel(e: FlowEdge): string {
  const parts: string[] = [];
  if (e.sourceHandle === 'yes') parts.push('예');
  if (e.sourceHandle === 'no') parts.push('아니오');
  if (e.data?.within) parts.push(`${fmtDuration(e.data.within)} 내`);
  return parts.join(' · ');
}

/** 화살표는 FlowEdgeView(유형 scn)가 그린다: 분기 꼬리표(예/아니오)는 출발점 옆, 허용 시간·오류는 가운데. */
export const FLOW_EDGE_TYPE = 'scn';

export function styleEdge(e: FlowEdge, selected: boolean): FlowEdge {
  const issues = e.data?.issues ?? [];
  let stroke = '#8a91a2';
  let width = 1.6;
  if (e.data?.flow === 'reached' || e.data?.highlight) {
    stroke = '#00d1b9';
    width = 2.6;
  }
  if (issues.length) {
    stroke = '#ff6b6b';
    width = 2.6;
  }
  if (selected) width += 1;
  const label = edgeLabel(e);
  return {
    ...e,
    type: FLOW_EDGE_TYPE,
    label: issues.length ? `${label ? `${label} · ` : ''}⚠ ${issues[0]}` : label || undefined,
    style: { stroke, strokeWidth: width },
    markerEnd: { type: MarkerType.ArrowClosed, color: stroke, width: 18, height: 18 },
  };
}
