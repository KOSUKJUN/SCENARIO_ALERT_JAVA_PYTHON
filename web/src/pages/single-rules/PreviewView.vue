<script setup lang="ts">
import { computed } from 'vue';
import BarChart from '../../components/BarChart.vue';
import EmptyBox from '../../components/EmptyBox.vue';
import RowsTable from '../../components/RowsTable.vue';
import type { PreviewResponse } from '../../types';
import { fmtTime } from '../../util';

const props = defineProps<{ p: PreviewResponse }>();
const hourly = computed(() => props.p.hourly.map((h) => ({ label: `${h.hour.slice(11, 13)}시`, value: h.hits })));
</script>
<template>
  <div data-testid="preview-result">
    <div class="stats">
      <div class="stat"><div class="stat-v" data-testid="preview-total">{{ p.total_hits.toLocaleString('ko-KR') }}</div><div class="stat-l">총 히트</div></div>
      <div class="stat"><div class="stat-v">{{ p.distinct_entities.toLocaleString('ko-KR') }}</div><div class="stat-l">서로 다른 대상</div></div>
    </div>
    <div class="muted small">{{ fmtTime(p.time_from) }} ~ {{ fmtTime(p.time_to) }}</div>
    <h4>시간대별 분포</h4>
    <BarChart :data="hourly" />
    <h4>상위 대상</h4>
    <table v-if="p.top_entities.length" class="table compact">
      <thead><tr><th>기관</th><th>대상</th><th class="num">히트</th></tr></thead>
      <tbody>
        <tr v-for="(t, i) in p.top_entities" :key="i"><td>{{ t.org_id }}</td><td>{{ t.entity }}</td><td class="num">{{ t.hits }}</td></tr>
      </tbody>
    </table>
    <EmptyBox v-else>히트가 없습니다</EmptyBox>
    <h4>샘플 히트 (최근 50)</h4>
    <RowsTable :rows="p.samples" :max="50" />
  </div>
</template>
