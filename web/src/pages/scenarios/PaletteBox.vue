<script setup lang="ts">
// 왼쪽 패널: 흐름 블록과, 순서도 대상 유형과 같은 이벤트 탐지모듈. 끌어다 놓거나 더블클릭(또는 +)으로 추가한다.
// 이벤트 탐지모듈은 여기서 바로 새로 만들 수 있다 (옆 패널에서 편집 → 저장하면 순서도에 들어간다).
import { computed, ref } from 'vue';
import ModuleIcon from '../../components/ModuleIcon.vue';
import EmptyBox from '../../components/EmptyBox.vue';
import LoadingBox from '../../components/LoadingBox.vue';
import StatusBadge from '../../components/StatusBadge.vue';
import type { NodeType, RuleSummary } from '../../types';
import { fmtDuration } from '../../util';
import { PALETTE_DND_TYPE, type PaletteItem } from './graph';

const props = defineProps<{ rules: RuleSummary[]; loading: boolean; entityType: string; readOnly: boolean; hasStart: boolean }>();
const emit = defineEmits<{ add: [item: PaletteItem]; 'create-rule': [] }>();

const BLOCKS: { type: NodeType; label: string; desc: string; shape: string }[] = [
  { type: 'check', label: '탐지 확인', desc: '앞뒤 시간 안에 다른 이벤트 탐지모듈이 있었나 (예/아니오)', shape: 'diamond' },
  { type: 'asset', label: '자산 확인', desc: '대상 자산이 태그를 가졌나 (예/아니오)', shape: 'diamond' },
  { type: 'and', label: '모두 (AND)', desc: '들어오는 가지가 모두 시간 안에 성립', shape: 'circle' },
  { type: 'or', label: '하나라도 (OR)', desc: '들어오는 가지 중 하나라도 성립', shape: 'circle' },
  { type: 'alert', label: '경보', desc: '여기에 도달하면 경보 (등급·제목·대응 절차)', shape: 'rect' },
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
    <div class="pal-section">
      <div class="pal-title">흐름 블록</div>
      <div class="pal-blocks">
        <div v-if="!hasStart" class="pal-block" :draggable="!readOnly" data-testid="palette-start" title="시작 (1개)" @dragstart="drag($event, { type: 'start' })" @dblclick="add({ type: 'start' })">
          <span class="shape pill" /><span class="grow">시작</span>
          <button v-if="!readOnly" class="pal-add" aria-label="시작 추가" data-testid="palette-add-start" @click="add({ type: 'start' })">+</button>
        </div>
        <div
          v-for="b in BLOCKS"
          :key="b.type"
          class="pal-block"
          :draggable="!readOnly"
          :title="`${b.desc}\n끌어다 놓거나 + 를 누르세요`"
          :data-testid="`palette-${b.type}`"
          @dragstart="drag($event, { type: b.type })"
          @dblclick="add({ type: b.type })"
        >
          <span :class="['shape', b.shape, b.type]" />
          <span class="grow">{{ b.label }}</span>
          <button v-if="!readOnly" class="pal-add" :aria-label="`${b.label} 추가`" :data-testid="`palette-add-${b.type}`" @click="add({ type: b.type })">+</button>
        </div>
      </div>
    </div>

    <div class="pal-section grow-section">
      <div class="pal-title">
        <ModuleIcon /> <span class="nowrap">이벤트 탐지모듈</span>
        <button v-if="!readOnly" class="pal-new" data-testid="palette-new-rule" title="새 이벤트 탐지모듈을 만들어 이 순서도에 넣습니다" @click="emit('create-rule')">+ 새로 만들기</button>
      </div>
      <input v-model="q" :placeholder="`${entityType} 모듈 이름·ID 검색`" data-testid="palette-search" />
      <div class="pal-rules">
        <LoadingBox v-if="loading" />
        <EmptyBox v-else-if="!shown.length">대상 유형이 {{ entityType }} 인 이벤트 탐지모듈이 없습니다</EmptyBox>
        <div
          v-for="r in shown"
          :key="r.rule_id"
          class="pal-rule"
          :draggable="!readOnly"
          :title="`${r.rule_id}\n끌어다 놓거나 더블클릭`"
          :data-testid="`palette-rule-${r.rule_id}`"
          @dragstart="drag($event, { type: 'rule', rule_id: r.rule_id })"
          @dblclick="add({ type: 'rule', rule_id: r.rule_id })"
        >
          <div class="pal-rule-name"><ModuleIcon class="fnode-ico" /> {{ r.name || r.rule_id }}</div>
          <div class="pal-rule-meta">
            <span class="mono">{{ r.rule_id }}</span>
            <span class="spacer" />
            <StatusBadge :status="r.status" />
          </div>
          <div class="pal-rule-meta muted">{{ r.type === 'count' ? '횟수 집계' : '시그니처' }} · {{ fmtDuration(r.window ?? '') }}</div>
        </div>
      </div>
    </div>
    <small class="hint">끌어다 놓거나 더블클릭하면 순서도에 들어갑니다. 노드 오른쪽 점을 끌어 다음 노드와 잇습니다.</small>
  </aside>
</template>
