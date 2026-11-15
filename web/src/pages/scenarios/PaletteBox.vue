<script setup lang="ts">
// 왼쪽 목록: 노드 종류와, 순서도 대상 유형과 같은 단일룰. 끌어다 놓거나 더블클릭(또는 +)으로 추가한다.
import { computed, ref } from 'vue';
import EmptyBox from '../../components/EmptyBox.vue';
import LoadingBox from '../../components/LoadingBox.vue';
import SeverityBadge from '../../components/SeverityBadge.vue';
import StatusBadge from '../../components/StatusBadge.vue';
import type { NodeType, RuleSummary } from '../../types';
import { PALETTE_DND_TYPE, type PaletteItem } from './graph';

const props = defineProps<{ rules: RuleSummary[]; loading: boolean; entityType: string; readOnly: boolean; hasStart: boolean }>();
const emit = defineEmits<{ add: [item: PaletteItem] }>();

const NODE_ITEMS: { type: NodeType; label: string; desc: string; shape: string }[] = [
  { type: 'check', label: '룰 확인', desc: '앞뒤 시간 안에 다른 룰 히트가 있나 (예/아니오)', shape: 'diamond' },
  { type: 'asset', label: '자산 태그 확인', desc: '대상 자산이 태그를 가졌나 (예/아니오)', shape: 'diamond' },
  { type: 'and', label: 'AND 합류', desc: '모든 가지가 within 안에 성립', shape: 'circle' },
  { type: 'or', label: 'OR 합류', desc: '가지 중 하나 성립', shape: 'circle' },
  { type: 'alert', label: '경보', desc: '도달하면 경보 (등급·제목·대응)', shape: 'rect' },
];
const q = ref('');
const shown = computed(() => {
  const s = q.value.trim().toLowerCase();
  return props.rules.filter((r) => !s || r.rule_id.toLowerCase().includes(s) || r.name.toLowerCase().includes(s));
});
function drag(e: DragEvent, item: PaletteItem) {
  if (!e.dataTransfer) return;
  const raw = JSON.stringify(item);
  e.dataTransfer.setData(PALETTE_DND_TYPE, raw);
  e.dataTransfer.setData('text/plain', raw);
  e.dataTransfer.effectAllowed = 'move';
}
function add(item: PaletteItem) {
  if (!props.readOnly) emit('add', item);
}
</script>
<template>
  <aside class="palette" data-testid="palette">
    <h4>노드</h4>
    <div class="palette-nodes">
      <div v-if="!hasStart" class="palette-item node-item" :draggable="!readOnly" data-testid="palette-start" @dragstart="drag($event, { type: 'start' })" @dblclick="add({ type: 'start' })">
        <span class="shape pill" /> 시작
      </div>
      <div
        v-for="n in NODE_ITEMS"
        :key="n.type"
        class="palette-item node-item"
        :draggable="!readOnly"
        :title="`${n.desc}\n끌어다 놓거나 더블클릭`"
        :data-testid="`palette-${n.type}`"
        @dragstart="drag($event, { type: n.type })"
        @dblclick="add({ type: n.type })"
      >
        <span :class="['shape', n.shape, n.type]" />
        <span class="grow">{{ n.label }}</span>
        <button v-if="!readOnly" class="tiny" :aria-label="`${n.label} 추가`" :data-testid="`palette-add-${n.type}`" @click="add({ type: n.type })">+</button>
      </div>
    </div>
    <h4>단일룰 <span class="muted small">({{ entityType }})</span></h4>
    <input v-model="q" placeholder="룰 검색" data-testid="palette-search" />
    <div class="palette-rules">
      <LoadingBox v-if="loading" />
      <EmptyBox v-else-if="!shown.length">대상 유형이 {{ entityType }} 인 룰이 없습니다</EmptyBox>
      <div
        v-for="r in shown"
        :key="r.rule_id"
        class="palette-item rule-item"
        :draggable="!readOnly"
        :title="`${r.name}\n끌어다 놓거나 더블클릭`"
        :data-testid="`palette-rule-${r.rule_id}`"
        @dragstart="drag($event, { type: 'rule', rule_id: r.rule_id })"
        @dblclick="add({ type: 'rule', rule_id: r.rule_id })"
      >
        <div class="rule-item-head">
          <span class="rid">{{ r.rule_id }}</span>
          <StatusBadge :status="r.status" />
        </div>
        <div class="rule-item-name">{{ r.name }}</div>
        <div class="muted small">{{ r.type === 'count' ? '카운트' : '시그니처' }} · {{ r.window }} · <SeverityBadge :severity="r.severity" /></div>
      </div>
    </div>
    <small class="hint">끌어다 캔버스에 놓으면 노드가 생깁니다 (더블클릭: 가운데에 추가).</small>
  </aside>
</template>
