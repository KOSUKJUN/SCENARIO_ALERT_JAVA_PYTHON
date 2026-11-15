<script setup lang="ts">
// 상태 전환 버튼 묶음. 실패 시 서버의 detail(409 등)을 그대로 보여 준다.
import { ref } from 'vue';
import { has } from '../auth';
import type { Status } from '../types';
import { STATUSES, STATUS_LABEL } from '../util';
import ErrorBox from './ErrorBox.vue';
import StatusBadge from './StatusBadge.vue';

const props = defineProps<{ current?: Status; change: (s: Status) => Promise<void>; disabled?: boolean }>();
const HELP: Record<Status, string> = {
  draft: '평가 안 함. 검증·미리보기·백테스트만 가능',
  silent: '실시간 평가, 경보는 저장만 (백테스트 1회 이상 완료 필요)',
  active: '경보를 사고처리 시스템으로 전달 (관리자, silent 에서만)',
  disabled: '평가 중지, 이력 보존',
};
const busy = ref<Status | null>(null);
const error = ref<unknown>(null);
async function run(s: Status) {
  busy.value = s;
  error.value = null;
  try {
    await props.change(s);
  } catch (e) {
    error.value = e;
  } finally {
    busy.value = null;
  }
}
</script>
<template>
  <div v-if="current" class="status-control" data-testid="status-control">
    <span>현재 상태 <StatusBadge :status="current" data-testid="status-current" /></span>
    <button
      v-for="s in STATUSES.filter((x) => x !== current)"
      :key="s"
      class="small"
      :title="HELP[s]"
      :disabled="disabled || !!busy || !has('author') || (s === 'active' && !has('admin'))"
      :data-testid="`status-${s}`"
      @click="run(s)"
    >
      {{ busy === s ? '전환 중…' : `→ ${STATUS_LABEL[s]}` }}
    </button>
    <div v-if="error" class="status-error"><ErrorBox :error="error" closable @close="error = null" /></div>
  </div>
</template>
