<script setup lang="ts">
import EmptyBox from '../../components/EmptyBox.vue';
import NoticeBox from '../../components/NoticeBox.vue';
import SeverityBadge from '../../components/SeverityBadge.vue';
import UiBadge from '../../components/UiBadge.vue';
import type { SimulateResponse, ValidateResponse } from '../../types';
import { fmtTime } from '../../util';
import type { LeveledIssue } from './graph';

defineProps<{ issues: LeveledIssue[]; validated: ValidateResponse | null; sim: SimulateResponse | null }>();
const emit = defineEmits<{ pick: [i: LeveledIssue] }>();
const TARGET_LABEL: Record<string, string> = { node: '노드', edge: '화살표', graph: '순서도' };
const SIM_LABEL: Record<string, string> = { reached: '성립', blocked: '막힘', not_reached: '도달 안 함' };
const REASON_LABEL: Record<string, string> = { no_hit: '히트 없음', timeout: '시간 초과', branch_missing: '가지 미성립' };
</script>
<template>
  <div class="result-panel">
    <h4>검증</h4>
    <ul v-if="issues.length" class="issue-list" data-testid="scenario-issues">
      <li v-for="(i, k) in issues" :key="k" :class="i.level">
        <button class="link" @click="emit('pick', i)">{{ TARGET_LABEL[i.target] ?? i.target }} {{ i.id }}</button>
        {{ i.message }}
      </li>
    </ul>
    <NoticeBox v-else-if="validated?.ok" kind="ok">오류가 없습니다 · 참조 룰: {{ validated.rule_refs.join(', ') || '-' }}</NoticeBox>
    <p v-else class="muted small">검증을 누르면 서버가 그래프를 점검합니다.</p>

    <div v-if="sim && sim.ok" data-testid="sim-result">
      <h4>시뮬레이션</h4>
      <NoticeBox v-if="sim.alert" kind="ok">
        선택된 경보: <SeverityBadge :severity="sim.alert.severity" /> <strong>{{ sim.alert.title }}</strong> (노드 {{ sim.alert.node }})
        <template v-if="(sim.reached_alerts?.length ?? 0) > 1"> · 도달한 경보 노드 {{ sim.reached_alerts?.join(', ') }} 중 가장 높은 등급</template>
      </NoticeBox>
      <NoticeBox v-else kind="warn">경보 노드에 도달하지 않았습니다</NoticeBox>
      <p class="small">
        대상 자산 태그:
        <template v-if="sim.asset_tags?.length"><UiBadge v-for="t in sim.asset_tags" :key="t">{{ t }}</UiBadge></template>
        <template v-else>없음</template>
      </p>
      <div class="grid-2">
        <div>
          <h5>노드별 결과</h5>
          <table class="table compact">
            <thead><tr><th>노드</th><th>결과</th><th>내용</th></tr></thead>
            <tbody>
              <tr v-for="(s, id) in sim.node_status ?? {}" :key="id" :class="{ 'row-ok': s.status === 'reached', 'row-bad': s.status === 'blocked' }">
                <td>{{ id }}</td>
                <td>{{ SIM_LABEL[s.status] ?? s.status }}</td>
                <td class="small">
                  {{ s.reason ? `${REASON_LABEL[s.reason] ?? s.reason}${s.message ? ` — ${s.message}` : ''}` : '' }}
                  {{ s.result ? (s.result === 'yes' ? '예' : '아니오') : '' }}
                  {{ s.matched_tags?.length ? `(${s.matched_tags.join(', ')})` : '' }}
                  {{ s.at ? ` · ${fmtTime(s.at)}` : '' }}
                </td>
              </tr>
            </tbody>
          </table>
        </div>
        <div>
          <h5>사용한 히트 ({{ sim.hits?.length ?? 0 }})</h5>
          <table v-if="sim.hits?.length" class="table compact">
            <thead><tr><th>룰</th><th>시각</th><th class="num">값/임계</th></tr></thead>
            <tbody>
              <tr v-for="(h, i) in sim.hits" :key="i"><td>{{ h.rule_id }}</td><td>{{ fmtTime(h.at) }}</td><td class="num">{{ h.value }} / {{ h.threshold }}</td></tr>
            </tbody>
          </table>
          <EmptyBox v-else>기간 안에 히트가 없습니다</EmptyBox>
        </div>
      </div>
      <template v-if="sim.alert">
        <h5>경로</h5>
        <ol class="path-steps">
          <li v-for="(s, i) in sim.alert.path" :key="i">
            <strong>{{ s.node }}</strong> {{ s.type ?? '' }} {{ s.rule_id ?? s.matched_rule_id ?? '' }}
            {{ s.result ? `→ ${s.result === 'yes' ? '예' : '아니오'}` : '' }} {{ s.at ? fmtTime(s.at) : '' }}
            {{ s.value !== undefined ? `값 ${s.value}${s.threshold !== undefined ? `/${s.threshold}` : ''}` : '' }}
          </li>
        </ol>
      </template>
    </div>
  </div>
</template>
