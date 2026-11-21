<script setup lang="ts">
// 읽기 전용 순서도 (경보 상세에서 지나온 경로 강조).
import { computed } from 'vue';
import { VueFlow } from '@vue-flow/core';
import { Background } from '@vue-flow/background';
import { Controls } from '@vue-flow/controls';
import type { Graph, PathStep } from '../../types';
import FlowEdgeView from './FlowEdgeView.vue';
import FlowNodeView from './FlowNodeView.vue';
import { gtype, styleEdge, toFlow, type FlowEdge } from './graph';

const props = withDefaults(defineProps<{ graph: Graph; path: PathStep[]; height?: number }>(), { height: 380 });
const flowId = `graph-view-${Math.random().toString(36).slice(2, 8)}`;

const view = computed(() => {
  const f = toFlow(props.graph);
  const hs = new Set(props.path.map((s) => s.node));
  const result: Record<string, string | undefined> = Object.fromEntries(props.path.map((s) => [s.node, s.result]));
  const types = Object.fromEntries(f.nodes.map((n) => [n.id, gtype(n)]));
  const startId = f.nodes.find((n) => gtype(n) === 'start')?.id;
  if (startId && props.path.length) hs.add(startId);
  // 경로에 남지 않는 합류(and/or) 노드: 강조된 노드 사이에 있으면 강조
  for (let k = 0; k < 3; k += 1) {
    for (const n of f.nodes) {
      const t = gtype(n);
      if ((t === 'and' || t === 'or') && !hs.has(n.id)) {
        const inHit = f.edges.some((e) => e.target === n.id && hs.has(e.source));
        const outHit = f.edges.some((e) => e.source === n.id && hs.has(e.target));
        if (inHit && outHit) hs.add(n.id);
      }
    }
  }
  const onPath = (e: FlowEdge) => {
    if (!hs.has(e.source) || !hs.has(e.target)) return false;
    if (e.sourceHandle && (types[e.source] === 'check' || types[e.source] === 'asset')) return result[e.source] === e.sourceHandle;
    return true;
  };
  return {
    nodes: f.nodes.map((n) => ({ ...n, draggable: false, selectable: false })),
    edges: f.edges.map((e) => styleEdge({ ...e, data: { ...e.data, highlight: onPath(e) } }, false)),
    hit: hs,
  };
});
</script>
<template>
  <div class="graph-view" :style="{ height: `${height}px` }" data-testid="alert-graph">
    <VueFlow
      :id="flowId"
      :nodes="view.nodes"
      :edges="view.edges"
      :nodes-draggable="false"
      :nodes-connectable="false"
      :elements-selectable="false"
      :delete-key-code="null"
      fit-view-on-init
    >
      <template #node-scn="p">
        <FlowNodeView :id="p.id" :data="p.data" :highlight="view.hit.has(p.id)" />
      </template>
      <template #edge-scn="p">
        <FlowEdgeView v-bind="p" />
      </template>
      <Background :gap="22" :size="1.2" pattern-color="#3a3f48" />
      <Controls :show-interactive="false" />
    </VueFlow>
  </div>
</template>
