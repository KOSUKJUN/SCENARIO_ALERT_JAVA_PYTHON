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

/** pos 가 없는 노드는 시작점에서의 깊이(가장 긴 경로)로 간단히 배치한다. */
function autoLayout(nodes: GraphNode[], edges: GraphEdge[]): Record<string, { x: number; y: number }> {
  const ids = nodes.map((n) => n.id);
  const indeg: Record<string, number> = Object.fromEntries(ids.map((i) => [i, 0]));
  const out: Record<string, string[]> = Object.fromEntries(ids.map((i) => [i, []]));
  for (const e of edges) {
    if (e.from in out && e.to in indeg) {
      out[e.from].push(e.to);
      indeg[e.to] += 1;
    }
  }
  const depth: Record<string, number> = Object.fromEntries(ids.map((i) => [i, 0]));
  const q = ids.filter((i) => indeg[i] === 0);
  const deg = { ...indeg };
  const seen = new Set<string>();
  while (q.length) {
    const n = q.shift() as string;
    seen.add(n);
    for (const m of out[n]) {
      depth[m] = Math.max(depth[m], depth[n] + 1);
      deg[m] -= 1;
      if (deg[m] === 0) q.push(m);
    }
  }
  // 순환이 있으면 남은 노드는 마지막 열에
  const maxD = Math.max(0, ...Object.values(depth));
  for (const i of ids) if (!seen.has(i)) depth[i] = maxD + 1;
  const rows: Record<number, number> = {};
  const pos: Record<string, { x: number; y: number }> = {};
  for (const n of nodes) {
    const d = depth[n.id];
    const r = rows[d] ?? 0;
    rows[d] = r + 1;
    pos[n.id] = { x: 40 + d * 230, y: 60 + r * 150 };
  }
  return pos;
}

export function toFlow(graph: Graph): { meta: GraphMeta; nodes: FlowNode[]; edges: FlowEdge[] } {
  const gnodes = Array.isArray(graph.nodes) ? graph.nodes : [];
  const gedges = Array.isArray(graph.edges) ? graph.edges : [];
  const needLayout = gnodes.some((n) => !Array.isArray(n.pos) || n.pos.length !== 2);
  const layout = needLayout ? autoLayout(gnodes, gedges) : {};
  const nodes: FlowNode[] = gnodes.map((n) => {
    const { id, pos, ...rest } = n;
    const position = Array.isArray(pos) && pos.length === 2 ? { x: pos[0], y: pos[1] } : layout[id] ?? { x: 0, y: 0 };
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
    type: 'smoothstep',
    label: issues.length ? `${label ? `${label} · ` : ''}⚠ ${issues[0]}` : label || undefined,
    labelStyle: { fill: issues.length ? '#ffb4b4' : '#e6e6e6', fontWeight: 600, fontSize: 12 },
    labelBgStyle: { fill: issues.length ? '#402628' : '#202227', fillOpacity: 0.95 },
    labelBgPadding: [6, 3],
    labelBgBorderRadius: 4,
    style: { stroke, strokeWidth: width },
    markerEnd: { type: MarkerType.ArrowClosed, color: stroke, width: 18, height: 18 },
  };
}
