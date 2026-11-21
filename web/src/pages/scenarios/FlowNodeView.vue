<script setup lang="ts">
// 순서도 노드 모양: 시작=둥근 알약, 이벤트 탐지모듈=사각형, check/asset=마름모(예: 오른쪽, 아니오: 아래), and/or=작은 원, 경보=등급 색 사각형.
// 편집기에서 선택하면 위에 작은 도구 막대(편집·복제·삭제)가 나온다.
import { computed } from 'vue';
import { Handle, Position } from '@vue-flow/core';
import ScenarioIcon from '../../components/ScenarioIcon.vue';
import ModuleIcon from '../../components/ModuleIcon.vue';
import type { NodeSim } from '../../types';
import { SEVERITY_LABEL, fmtDuration } from '../../util';
import type { FlowNodeData } from './graph';

const props = defineProps<{
  id: string;
  data: FlowNodeData;
  selected?: boolean;
  issues?: string[];
  warnings?: string[];
  sim?: NodeSim;
  highlight?: boolean;
  ruleName?: string;
  editable?: boolean;
}>();
const emit = defineEmits<{ action: [kind: 'edit' | 'duplicate' | 'delete'] }>();

const SIM_REASON: Record<string, string> = { no_hit: '히트 없음', timeout: '시간 초과', branch_missing: '가지 미성립' };
const g = computed(() => props.data.g);
const t = computed(() => g.value.type);
const isDiamond = computed(() => t.value === 'check' || t.value === 'asset');
const cls = computed(() => [
  'fnode',
  t.value === 'and' || t.value === 'or' ? 'join' : isDiamond.value ? 'diamond' : t.value,
  t.value,
  t.value === 'alert' ? `sev-${g.value.severity ?? 'medium'}` : '',
  {
    selected: props.selected,
    'has-error': props.issues?.length,
    'has-warn': !props.issues?.length && props.warnings?.length,
    'sim-reached': props.sim?.status === 'reached',
    'sim-blocked': props.sim?.status === 'blocked',
    'sim-not-reached': props.sim?.status === 'not_reached',
    'path-hit': props.highlight,
  },
]);
const simText = computed(() => {
  const s = props.sim;
  if (!s) return '';
  if (s.status === 'blocked') {
    const why = SIM_REASON[s.reason ?? ''] ?? s.message ?? '막힘';
    return `✕ ${why}${s.reason === 'branch_missing' && s.message ? ` (${s.message})` : ''}`;
  }
  if (s.status === 'reached') {
    const extra = s.result ? ` · ${s.result === 'yes' ? '예' : '아니오'}` : s.hits !== undefined ? ` · 히트 ${s.hits}` : '';
    return `✓ 성립${extra}`;
  }
  return '';
});
const ruleIds = computed(() => g.value.rule_ids ?? []);
const tags = computed(() => g.value.tags ?? []);
</script>

<template>
  <div :class="cls" :data-testid="t === 'start' ? 'node-start' : `node-${id}`" :data-node-type="t">
    <div v-if="editable && selected && t !== 'start'" class="node-toolbar nodrag" data-testid="node-toolbar">
      <button v-if="t === 'rule' && g.rule_id" class="tb" title="이 이벤트 탐지모듈 편집" data-testid="node-edit" @click.stop="emit('action', 'edit')">편집</button>
      <button class="tb" title="복제" data-testid="node-duplicate" @click.stop="emit('action', 'duplicate')">복제</button>
      <button class="tb danger" title="삭제 (Delete)" data-testid="node-delete" @click.stop="emit('action', 'delete')">삭제</button>
    </div>

    <template v-if="t === 'start'">
      <ScenarioIcon class="fnode-ico" /> 시작
      <Handle type="source" :position="Position.Right" :data-testid="`handle-${id}-out`" />
    </template>

    <template v-else-if="t === 'rule'">
      <Handle type="target" :position="Position.Left" :data-testid="`handle-${id}-in`" />
      <div class="fnode-kind"><ModuleIcon class="fnode-ico" /> 이벤트 탐지모듈 <span class="nid">{{ id }}</span></div>
      <div class="fnode-title">{{ g.rule_id || '(이벤트 탐지모듈 선택)' }}</div>
      <div class="fnode-sub">{{ g.label || ruleName || '' }}</div>
      <Handle type="source" :position="Position.Right" :data-testid="`handle-${id}-out`" />
    </template>

    <template v-else-if="isDiamond">
      <svg class="diamond-shape" viewBox="0 0 160 100" preserveAspectRatio="none"><polygon points="80,2 158,50 80,98 2,50" /></svg>
      <div class="diamond-content">
        <div class="fnode-kind">{{ t === 'check' ? '탐지 확인' : '자산 태그' }} <span class="nid">{{ id }}</span></div>
        <template v-if="t === 'check'">
          <div class="fnode-title small" :title="ruleIds.join(', ')">{{ g.label || (ruleIds.length ? ruleIds.join(', ') : '(이벤트 탐지모듈 선택)') }}</div>
          <div class="fnode-sub">±{{ fmtDuration(g.lookaround) || '?' }}</div>
        </template>
        <div v-else class="fnode-title small" :title="tags.join(', ')">{{ g.label || (tags.length ? tags.join(', ') : '(태그 지정)') }}</div>
      </div>
      <Handle type="target" :position="Position.Left" :data-testid="`handle-${id}-in`" />
      <Handle id="yes" type="source" :position="Position.Right" class="handle-yes" :data-testid="`handle-${id}-yes`" />
      <Handle id="no" type="source" :position="Position.Bottom" class="handle-no" :data-testid="`handle-${id}-no`" />
      <span class="branch-tag yes">예</span>
      <span class="branch-tag no">아니오</span>
    </template>

    <template v-else-if="t === 'and' || t === 'or'">
      <Handle type="target" :position="Position.Left" :data-testid="`handle-${id}-in`" />
      <div class="join-label">{{ t === 'and' ? 'AND' : 'OR' }}</div>
      <div v-if="t === 'and'" class="join-sub">{{ fmtDuration(g.within) }}</div>
      <Handle type="source" :position="Position.Right" :data-testid="`handle-${id}-out`" />
    </template>

    <template v-else-if="t === 'alert'">
      <Handle type="target" :position="Position.Left" :data-testid="`handle-${id}-in`" />
      <div class="fnode-kind">경보 · {{ SEVERITY_LABEL[g.severity ?? 'medium'] ?? g.severity }} <span class="nid">{{ id }}</span></div>
      <div class="fnode-title small">{{ g.label || g.title || '(제목)' }}</div>
    </template>

    <div v-if="issues?.length || warnings?.length || simText" class="node-notes">
      <div v-if="issues?.length" class="node-note err" :title="issues.join('\n')">
        ⚠ {{ issues[0] }}{{ issues.length > 1 ? ` 외 ${issues.length - 1}건` : '' }}
      </div>
      <div v-else-if="warnings?.length" class="node-note warn" :title="warnings.join('\n')">{{ warnings[0] }}</div>
      <div v-if="simText" :class="['node-note', sim?.status === 'blocked' ? 'blocked' : 'reached']">{{ simText }}</div>
    </div>
  </div>
</template>
