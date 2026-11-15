<script setup lang="ts">
import { computed, ref } from 'vue';
import { api } from '../../api';
import { has } from '../../auth';
import { useAsync } from '../../composables';
import EmptyBox from '../../components/EmptyBox.vue';
import ErrorBox from '../../components/ErrorBox.vue';
import LoadingBox from '../../components/LoadingBox.vue';
import SeverityBadge from '../../components/SeverityBadge.vue';
import StatusBadge from '../../components/StatusBadge.vue';
import UiBadge from '../../components/UiBadge.vue';
import type { RuleSummary } from '../../types';
import { STATUSES, STATUS_LABEL, fmtTime } from '../../util';

const rules = useAsync(() => api.get<RuleSummary[]>('/single-rules'));
const q = ref('');
const status = ref('');
const shown = computed(() => {
  const s = q.value.trim().toLowerCase();
  return (rules.data.value ?? []).filter(
    (r) => (!status.value || r.status === status.value) && (!s || r.rule_id.toLowerCase().includes(s) || r.name.toLowerCase().includes(s)),
  );
});
</script>
<template>
  <div class="page">
    <div class="page-head">
      <h2>단일룰</h2>
      <div class="actions">
        <input v-model="q" placeholder="ID·이름 검색" data-testid="rule-search" />
        <select v-model="status">
          <option value="">모든 상태</option>
          <option v-for="s in STATUSES" :key="s" :value="s">{{ STATUS_LABEL[s] }}</option>
        </select>
        <RouterLink v-if="has('author')" to="/single-rules/import-snort" class="button" data-testid="rule-import-snort">Snort 룰 가져오기</RouterLink>
        <RouterLink v-if="has('author')" to="/single-rules/new" class="button primary" data-testid="rule-new">새 룰</RouterLink>
      </div>
    </div>
    <LoadingBox v-if="rules.loading.value && !rules.data.value" />
    <ErrorBox :error="rules.error.value" />
    <div v-if="rules.data.value" class="table-wrap card">
      <table class="table" data-testid="rule-list">
        <thead>
          <tr>
            <th>ID</th><th>이름</th><th>상태</th><th>유형</th><th>대상</th><th>데이터 유형</th><th>창</th><th>등급</th>
            <th class="num">히트(24h)</th><th>사용 순서도</th><th>수정</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="r in shown" :key="r.rule_id" :class="{ 'row-warn': r.warning }">
            <td>
              <RouterLink :to="`/single-rules/${r.rule_id}`" :data-testid="`rule-link-${r.rule_id}`">{{ r.rule_id }}</RouterLink>
              <UiBadge v-if="r.warning" kind="bad" title="연속 실패 3회 이상">실패 {{ r.consecutive_failures }}회</UiBadge>
            </td>
            <td>{{ r.name }}</td>
            <td><StatusBadge :status="r.status" /></td>
            <td>{{ r.type === 'count' ? '카운트' : '시그니처' }}</td>
            <td>{{ r.entity_type }}/{{ r.entity_field }}</td>
            <td class="small">{{ (r.data_tp ?? []).join(', ') }}</td>
            <td>{{ r.window }}</td>
            <td><SeverityBadge :severity="r.severity" /> <UiBadge v-if="r.alert_on_hit" kind="info">단독 경보</UiBadge></td>
            <td class="num">{{ r.hits_24h ?? 0 }}</td>
            <td class="small">
              <RouterLink v-for="s in r.used_by ?? []" :key="s" :to="`/scenarios/${s}`" class="chip">{{ s }}</RouterLink>
            </td>
            <td class="small">v{{ r.version }} · {{ fmtTime(r.updated_at) }}</td>
          </tr>
        </tbody>
      </table>
      <EmptyBox v-if="!shown.length">룰이 없습니다</EmptyBox>
    </div>
  </div>
</template>
