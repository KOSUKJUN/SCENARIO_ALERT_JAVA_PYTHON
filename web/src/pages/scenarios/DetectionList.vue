<script setup lang="ts">
// 이벤트 탐지모듈 목록 (시나리오 분석의 [이벤트 탐지모듈 관리] 새 창). 서버·DB 에서는 단일룰(single rule)이다.
import { computed, ref } from 'vue';
import { has } from '../../auth';
import type { AsyncState } from '../../composables';
import ModuleChip from '../../components/ModuleChip.vue';
import ModuleIcon from '../../components/ModuleIcon.vue';
import EmptyBox from '../../components/EmptyBox.vue';
import ErrorBox from '../../components/ErrorBox.vue';
import LoadingBox from '../../components/LoadingBox.vue';
import SeverityBadge from '../../components/SeverityBadge.vue';
import StatusBadge from '../../components/StatusBadge.vue';
import UiBadge from '../../components/UiBadge.vue';
import type { RuleSummary } from '../../types';
import { STATUSES, STATUS_LABEL, fmtDuration, fmtTime } from '../../util';

const props = defineProps<{ state: AsyncState<RuleSummary[]>; scenarioNames: Record<string, string>; highlight?: string }>();
const q = ref('');
const status = ref('');
const shown = computed(() => {
  const s = q.value.trim().toLowerCase();
  return (props.state.data.value ?? []).filter(
    (r) => (!status.value || r.status === status.value) && (!s || r.rule_id.toLowerCase().includes(s) || r.name.toLowerCase().includes(s)),
  );
});
</script>
<template>
  <div class="list-toolbar">
    <input v-model="q" class="search" placeholder="이름·ID 검색" data-testid="rule-search" />
    <select v-model="status" data-testid="rule-status-filter">
      <option value="">모든 상태</option>
      <option v-for="s in STATUSES" :key="s" :value="s">{{ STATUS_LABEL[s] }}</option>
    </select>
    <span class="spacer" />
    <RouterLink v-if="has('author')" to="/scenarios/detections/import-snort" class="button" data-testid="rule-import-snort">Snort 룰 가져오기</RouterLink>
    <RouterLink v-if="has('author')" to="/scenarios/detections/new" class="button primary" data-testid="rule-new">+ 새 이벤트 탐지모듈</RouterLink>
  </div>
  <LoadingBox v-if="state.loading.value && !state.data.value" />
  <ErrorBox :error="state.error.value" />
  <div v-if="state.data.value" class="table-wrap card">
    <table class="table hub-table" data-testid="rule-list">
      <thead>
        <tr>
          <th>이벤트 탐지모듈</th><th>상태</th><th>방식</th><th>대상</th><th class="num">히트 24시간</th><th>쓰는 시나리오</th><th>수정</th>
        </tr>
      </thead>
      <tbody>
        <tr v-for="r in shown" :key="r.rule_id" :class="{ 'row-warn': r.warning, 'row-open': r.rule_id === highlight }">
          <td>
            <RouterLink :to="`/scenarios/detections/${r.rule_id}`" class="item-name mod-name" :data-testid="`rule-link-${r.rule_id}`">
              <ModuleIcon />{{ r.name || r.rule_id }}
            </RouterLink>
            <UiBadge v-if="r.warning" kind="bad" title="연속 실패 3회 이상">실패 {{ r.consecutive_failures }}회</UiBadge>
            <div class="item-id">{{ r.rule_id }}</div>
          </td>
          <td><StatusBadge :status="r.status" /></td>
          <td class="small">
            {{ r.type === 'count' ? '횟수 집계' : '시그니처' }} · {{ fmtDuration(r.window ?? '') }}
            <div><SeverityBadge :severity="r.severity" /> <UiBadge v-if="r.alert_on_hit" kind="info">단독 경보</UiBadge></div>
          </td>
          <td class="small">{{ r.entity_type }} · {{ r.entity_field }}</td>
          <td class="num">{{ r.hits_24h ?? 0 }}</td>
          <td class="small">
            <div class="mod-list"><ModuleChip v-for="s in r.used_by ?? []" :key="s" kind="scenario" :to="`/scenarios/${s}`" :name="scenarioNames[s] ?? s" :title="s" /></div>
            <span v-if="!(r.used_by ?? []).length" class="muted">-</span>
          </td>
          <td class="small muted">v{{ r.version }} · {{ fmtTime(r.updated_at) }}</td>
        </tr>
      </tbody>
    </table>
    <EmptyBox v-if="!shown.length">이벤트 탐지모듈이 없습니다</EmptyBox>
  </div>
</template>
