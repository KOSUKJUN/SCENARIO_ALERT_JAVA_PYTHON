<script setup lang="ts">
import { computed } from 'vue';
import type { BacktestResult } from '../types';
import { showIncident } from '../auth';
import { fmtTime } from '../util';
import BarChart from './BarChart.vue';
import CardBox from './CardBox.vue';
import EmptyBox from './EmptyBox.vue';
import RowsTable from './RowsTable.vue';
import SeverityBadge from './SeverityBadge.vue';
import UiBadge from './UiBadge.vue';

const props = defineProps<{ r: BacktestResult }>();
const isScenario = computed(() => props.r.target_type === 'scenario');
const daily = computed(() =>
  props.r.daily.map((d) => ({ label: d.date.slice(5), value: (isScenario.value ? d.alerts : d.hits) ?? 0 })),
);
const detected = computed(() => (props.r.recall ?? []).filter((x) => x.detected).length);
const alertRows = computed(() =>
  (props.r.alerts ?? []).map((a) => ({ ...a, path: Array.isArray(a.path) ? `${a.path.length}단계` : a.path })),
);
</script>
<template>
  <div class="bt-result" data-testid="backtest-result">
    <div class="stats">
      <div class="stat"><div class="stat-v">{{ r.total_hits.toLocaleString('ko-KR') }}</div><div class="stat-l">총 히트</div></div>
      <div class="stat"><div class="stat-v">{{ r.total_alerts.toLocaleString('ko-KR') }}</div><div class="stat-l">총 경보</div></div>
      <div v-for="(v, k) in r.threshold_sensitivity ?? {}" :key="k" class="stat">
        <div class="stat-v">{{ v.toLocaleString('ko-KR') }}</div>
        <div class="stat-l">임계치 {{ String(k).replace('x', '×') }}</div>
      </div>
      <div v-for="(v, k) in r.alerts_by_severity ?? {}" :key="k" class="stat">
        <div class="stat-v">{{ v }}</div>
        <div class="stat-l"><SeverityBadge :severity="String(k)" /></div>
      </div>
    </div>
    <small v-if="r.threshold_sensitivity" class="hint">임계치 민감도: 임계치를 0.5배·1배·2배로 바꿨을 때의 히트(창) 수</small>
    <div class="grid-2">
      <CardBox title="일별 분포">
        <BarChart :data="daily" :unit="isScenario ? '건 경보' : '건 히트'" />
      </CardBox>
      <CardBox title="상위 대상 20">
        <table v-if="r.top_entities.length" class="table compact">
          <thead><tr><th>기관</th><th>대상</th><th class="num">{{ isScenario ? '경보' : '히트' }}</th></tr></thead>
          <tbody>
            <tr v-for="(t, i) in r.top_entities" :key="i">
              <td>{{ t.org_id }}</td><td>{{ t.entity }}</td><td class="num">{{ isScenario ? t.alerts : t.hits }}</td>
            </tr>
          </tbody>
        </table>
        <EmptyBox v-else />
      </CardBox>
    </div>
    <CardBox v-if="r.hits_by_rule" title="참조 룰별 히트">
      <table class="table compact">
        <tbody>
          <tr v-for="(v, k) in r.hits_by_rule" :key="k"><td>{{ k }}</td><td class="num">{{ v }}</td></tr>
        </tbody>
      </table>
    </CardBox>
    <CardBox v-if="showIncident()" title="재현율 (과거 사고 탐지 여부)">
      <template v-if="r.recall?.length">
        <p>{{ detected }} / {{ r.recall.length }} 건 탐지</p>
        <table class="table compact">
          <thead><tr><th>사고</th><th>기관</th><th>대상</th><th>발생</th><th>요약</th><th>탐지</th></tr></thead>
          <tbody>
            <tr v-for="x in r.recall" :key="x.incident_id">
              <td>{{ x.incident_id }}</td><td>{{ x.org_id }}</td><td>{{ x.entity }}</td>
              <td>{{ fmtTime(x.occurred_at) }}</td><td class="small">{{ x.summary }}</td>
              <td><UiBadge :kind="x.detected ? 'ok' : 'bad'">{{ x.detected ? '탐지' : '놓침' }}</UiBadge></td>
            </tr>
          </tbody>
        </table>
      </template>
      <EmptyBox v-else>기간 안에 등록된 과거 사고가 없습니다</EmptyBox>
    </CardBox>
    <CardBox v-if="alertRows.length" :title="`모의 경보 (${alertRows.length})`">
      <RowsTable :rows="alertRows" :max="100" />
    </CardBox>
  </div>
</template>
