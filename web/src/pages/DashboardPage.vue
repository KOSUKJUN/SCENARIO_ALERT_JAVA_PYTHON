<script setup lang="ts">
// 현황: 이벤트 탐지모듈·시나리오별 경보 수, 정탐률, 실행 시간, 실패한 실행, 전달 실패. 정탐률 20% 미만은 "조정 필요".
import { computed, ref } from 'vue';
import { api } from '../api';
import { showIncident } from '../auth';
import { useAsync } from '../composables';
import CardBox from '../components/CardBox.vue';
import EmptyBox from '../components/EmptyBox.vue';
import ErrorBox from '../components/ErrorBox.vue';
import LoadingBox from '../components/LoadingBox.vue';
import SeverityBadge from '../components/SeverityBadge.vue';
import StatusBadge from '../components/StatusBadge.vue';
import UiBadge from '../components/UiBadge.vue';
import type { RuleMetrics } from '../types';
import { fmtPct, fmtSec, fmtTime } from '../util';

const days = ref(30);
const m = useAsync(() => api.get<RuleMetrics>('/metrics/rules', { days: days.value }), [days]);
const totals = computed(() => {
  const d = m.data.value;
  if (!d) return null;
  const all = [...d.rules, ...d.scenarios];
  return {
    alerts: all.reduce((s, x) => s + x.alerts, 0),
    judged: all.reduce((s, x) => s + x.judged, 0),
    tp: all.reduce((s, x) => s + x.true_positive, 0),
    tuning: all.filter((x) => x.needs_tuning).length,
    failing: d.rules.filter((r) => r.warning).length,
  };
});
const activeRules = computed(() => (m.data.value?.rules ?? []).filter((r) => r.status === 'silent' || r.status === 'active'));
</script>
<template>
  <div class="page">
    <div class="page-head">
      <h2>현황</h2>
      <div class="actions">
        <select v-model.number="days">
          <option :value="7">최근 7일</option>
          <option :value="30">최근 30일</option>
          <option :value="90">최근 90일</option>
        </select>
        <button @click="m.reload">새로고침</button>
      </div>
    </div>
    <LoadingBox v-if="m.loading.value && !m.data.value" />
    <ErrorBox :error="m.error.value" />
    <template v-if="m.data.value && totals">
      <div class="stats" data-testid="dashboard-stats">
        <div class="stat"><div class="stat-v">{{ totals.alerts }}</div><div class="stat-l">경보 ({{ days }}일)</div></div>
        <template v-if="showIncident()">
        <div class="stat"><div class="stat-v">{{ totals.judged }}</div><div class="stat-l">판정</div></div>
        <div class="stat"><div class="stat-v">{{ totals.judged ? fmtPct(totals.tp / totals.judged) : '-' }}</div><div class="stat-l">정탐률</div></div>
        <div class="stat"><div class="stat-v" :class="{ bad: totals.tuning }">{{ totals.tuning }}</div><div class="stat-l">조정 필요</div></div>
        </template>
        <div class="stat"><div class="stat-v" :class="{ bad: totals.failing }">{{ totals.failing }}</div><div class="stat-l">연속 실패 룰</div></div>
      </div>

      <CardBox title="이벤트 탐지모듈 (실행 중)">
        <div class="table-wrap">
          <table class="table compact" data-testid="dashboard-rules">
            <thead>
              <tr>
                <th>룰</th><th>상태</th><th class="num">실행(24h)</th><th class="num">평균 ms</th><th class="num">최대 ms</th>
                <th class="num">실패(24h)</th><th class="num">히트(24h)</th><th>평가 지연</th><th class="num">경보</th><template v-if="showIncident()"><th>정탐률</th><th>오탐 상위</th></template>
              </tr>
            </thead>
            <tbody>
              <tr v-for="r in activeRules" :key="r.rule_id" :class="{ 'row-warn': r.warning || (showIncident() && r.needs_tuning) }">
                <td>
                  <RouterLink :to="`/scenarios/detections/${r.rule_id}`">{{ r.rule_id }}</RouterLink>
                  <div class="muted small">{{ r.name }}</div>
                </td>
                <td><StatusBadge :status="r.status" /></td>
                <td class="num">{{ r.runs_24h }}</td>
                <td class="num">{{ Math.round(r.avg_run_ms) }}</td>
                <td class="num">{{ r.max_run_ms }}</td>
                <td class="num">
                  {{ r.failed_runs_24h }}
                  <UiBadge v-if="r.warning" kind="bad">연속 {{ r.consecutive_failures }}회</UiBadge>
                </td>
                <td class="num">{{ r.hits_24h }}</td>
                <td>{{ fmtSec(r.eval_lag_sec) }}</td>
                <td class="num">{{ r.alerts }}</td>
                <template v-if="showIncident()">
                <td>{{ fmtPct(r.tp_rate) }} <UiBadge v-if="r.needs_tuning" kind="warn">조정 필요</UiBadge></td>
                <td class="small">{{ r.top_fp_entities.map((e) => `${e.entity}(${e.count})`).join(', ') }}</td>
                </template>
              </tr>
            </tbody>
          </table>
          <EmptyBox v-if="!activeRules.length">실행 중인 이벤트 탐지모듈이 없습니다</EmptyBox>
        </div>
      </CardBox>

      <CardBox title="시나리오">
        <div class="table-wrap">
          <table class="table compact" data-testid="dashboard-scenarios">
            <thead>
              <tr><th>시나리오</th><th>상태</th><th class="num">경보</th><template v-if="showIncident()"><th class="num">판정</th><th>정탐률</th><th class="num">전달 실패</th><th>오탐 상위</th></template></tr>
            </thead>
            <tbody>
              <tr v-for="s in m.data.value.scenarios" :key="s.scenario_id" :class="{ 'row-warn': showIncident() && s.needs_tuning }">
                <td><RouterLink :to="`/scenarios/${s.scenario_id}`">{{ s.scenario_id }}</RouterLink> <span class="muted small">{{ s.name }}</span></td>
                <td><StatusBadge :status="s.status" /></td>
                <td class="num">{{ s.alerts }}</td>
                <template v-if="showIncident()">
                <td class="num">{{ s.judged }}</td>
                <td>{{ fmtPct(s.tp_rate) }} <UiBadge v-if="s.needs_tuning" kind="warn">조정 필요</UiBadge></td>
                <td class="num">{{ s.delivery_failed }}</td>
                <td class="small">{{ s.top_fp_entities.map((e) => `${e.entity}(${e.count})`).join(', ') }}</td>
                </template>
              </tr>
            </tbody>
          </table>
        </div>
      </CardBox>

      <div class="grid-2">
        <CardBox title="실패한 실행 (최근 50)">
          <table v-if="m.data.value.failed_runs.length" class="table compact">
            <thead><tr><th>시작</th><th>룰</th><th>구간 끝</th><th>오류</th></tr></thead>
            <tbody>
              <tr v-for="(f, i) in m.data.value.failed_runs" :key="i">
                <td>{{ fmtTime(f.started_at) }}</td>
                <td><RouterLink :to="`/scenarios/detections/${f.rule_id}`">{{ f.rule_id }}</RouterLink></td>
                <td>{{ fmtTime(f.win_to) }}</td>
                <td class="small err-text">{{ f.error }}</td>
              </tr>
            </tbody>
          </table>
          <EmptyBox v-else>실패한 실행이 없습니다</EmptyBox>
        </CardBox>
        <CardBox v-if="showIncident()" title="전달 실패 경보">
          <table v-if="m.data.value.undelivered_alerts.length" class="table compact">
            <thead><tr><th>생성</th><th>등급</th><th>출처</th><th>대상</th><th>오류</th></tr></thead>
            <tbody>
              <tr v-for="a in m.data.value.undelivered_alerts" :key="a.alert_id">
                <td><RouterLink :to="`/alerts/${a.alert_id}`">{{ fmtTime(a.created_at) }}</RouterLink></td>
                <td><SeverityBadge :severity="a.severity" /></td>
                <td>{{ a.source_id }}</td>
                <td>{{ a.org_id }} {{ a.entity }}</td>
                <td class="small err-text">{{ a.delivery_error }}</td>
              </tr>
            </tbody>
          </table>
          <EmptyBox v-else>전달 실패가 없습니다</EmptyBox>
        </CardBox>
      </div>
    </template>
  </div>
</template>
