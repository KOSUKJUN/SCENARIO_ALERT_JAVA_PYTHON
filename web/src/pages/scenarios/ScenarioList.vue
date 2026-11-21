<script setup lang="ts">
// 시나리오 리스트 (시나리오 분석 오른쪽): 체크박스, 그룹, 시나리오, 상태, 사용 이벤트 탐지모듈, 경보 등급. 15개씩 쪽 나눔.
import { computed, ref, watch } from 'vue';
import EmptyBox from '../../components/EmptyBox.vue';
import ModuleChip from '../../components/ModuleChip.vue';
import ScenarioIcon from '../../components/ScenarioIcon.vue';
import SeverityBadge from '../../components/SeverityBadge.vue';
import StatusBadge from '../../components/StatusBadge.vue';
import type { ScenarioSummary } from '../../types';
import { fmtTime } from '../../util';

const PAGE = 15;
const props = defineProps<{
  rows: ScenarioSummary[];
  ruleNames: Record<string, string>;
  groupNames: Record<number, string>;
  selectable: boolean;
}>();
const checked = defineModel<string[]>('checked', { default: () => [] });

const page = ref(1);
const pages = computed(() => Math.max(1, Math.ceil(props.rows.length / PAGE)));
const shown = computed(() => props.rows.slice((page.value - 1) * PAGE, page.value * PAGE));
watch(
  () => props.rows,
  () => {
    if (page.value > pages.value) page.value = 1;
  },
);
const allOnPage = computed(() => shown.value.length > 0 && shown.value.every((s) => checked.value.includes(s.scenario_id)));
function toggleAll(on: boolean) {
  const ids = shown.value.map((s) => s.scenario_id);
  checked.value = on ? [...new Set([...checked.value, ...ids])] : checked.value.filter((x) => !ids.includes(x));
}
function toggle(id: string, on: boolean) {
  checked.value = on ? [...checked.value, id] : checked.value.filter((x) => x !== id);
}
</script>
<template>
  <div class="table-wrap">
    <table class="table hub-table" data-testid="scenario-list">
      <thead>
        <tr>
          <th v-if="selectable" class="cb"><input type="checkbox" :checked="allOnPage" aria-label="이 쪽 모두 선택" data-testid="scenario-check-all" @change="toggleAll(($event.target as HTMLInputElement).checked)" /></th>
          <th>그룹</th><th>시나리오</th><th>상태</th><th>사용 이벤트 탐지모듈</th><th>경보 등급</th><th class="num">경보 24시간</th><th>수정</th>
        </tr>
      </thead>
      <tbody>
        <tr v-for="s in shown" :key="s.scenario_id" :class="{ 'row-checked': checked.includes(s.scenario_id) }">
          <td v-if="selectable" class="cb">
            <input
              type="checkbox"
              :checked="checked.includes(s.scenario_id)"
              :aria-label="`${s.scenario_id} 선택`"
              :data-testid="`scenario-check-${s.scenario_id}`"
              @change="toggle(s.scenario_id, ($event.target as HTMLInputElement).checked)"
            />
          </td>
          <td class="small" :data-testid="`scenario-group-${s.scenario_id}`">{{ s.group_id != null ? groupNames[s.group_id] ?? '-' : '미분류' }}</td>
          <td>
            <RouterLink :to="`/scenarios/${s.scenario_id}`" class="item-name mod-name" :data-testid="`scenario-link-${s.scenario_id}`"><ScenarioIcon />{{ s.name || s.scenario_id }}</RouterLink>
            <div class="item-id">{{ s.scenario_id }}</div>
          </td>
          <td><StatusBadge :status="s.status" /></td>
          <td class="small">
            <div class="mod-list"><ModuleChip v-for="r in s.rule_ids" :key="r" :to="`/scenarios/detections/${r}`" :name="ruleNames[r] ?? r" :title="r" /></div>
          </td>
          <td><SeverityBadge v-for="v in s.severities" :key="v" :severity="v" /></td>
          <td class="num">{{ s.alerts_24h ?? 0 }}</td>
          <td class="small muted">v{{ s.version }} · {{ fmtTime(s.updated_at) }}</td>
        </tr>
      </tbody>
    </table>
    <EmptyBox v-if="!rows.length">조건에 맞는 시나리오가 없습니다</EmptyBox>
  </div>
  <nav v-if="pages > 1" class="pager" data-testid="scenario-pager">
    <button class="link" :disabled="page === 1" aria-label="이전 쪽" @click="page -= 1">‹</button>
    <button v-for="n in pages" :key="n" :class="['link', { active: n === page }]" :data-testid="`scenario-page-${n}`" @click="page = n">{{ n }}</button>
    <button class="link" :disabled="page === pages" aria-label="다음 쪽" @click="page += 1">›</button>
  </nav>
</template>
