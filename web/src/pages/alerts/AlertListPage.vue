<script setup lang="ts">
// 경보 목록: 필터(기관, 등급, 기간, 판정 등)는 주소(query)에 남겨 새로고침·공유해도 유지된다.
import { computed, reactive } from 'vue';
import { useRoute, useRouter, type LocationQuery } from 'vue-router';
import { api } from '../../api';
import { showIncident } from '../../auth';
import { useAsync } from '../../composables';
import AttackChips from '../../components/AttackChips.vue';
import EmptyBox from '../../components/EmptyBox.vue';
import ErrorBox from '../../components/ErrorBox.vue';
import LoadingBox from '../../components/LoadingBox.vue';
import SeverityBadge from '../../components/SeverityBadge.vue';
import UiBadge from '../../components/UiBadge.vue';
import type { AlertItem, Org } from '../../types';
import { DELIVERY_LABEL, SEVERITIES, SEVERITY_LABEL, VERDICT_LABEL, fmtTime, kstInput, localInputToIso, truthy } from '../../util';

const PAGE = 50;
interface Filters {
  org_id: string;
  severity: string[];
  verdict: string;
  source_type: string;
  source_id: string;
  entity: string;
  delivery_status: string;
  time_from: string;
  time_to: string;
  technique: string;
}
const EMPTY: Filters = { org_id: '', severity: [], verdict: '', source_type: '', source_id: '', entity: '', delivery_status: '', time_from: '', time_to: '', technique: '' };

const route = useRoute();
const router = useRouter();
const q1 = (q: LocationQuery, k: string) => (typeof q[k] === 'string' ? (q[k] as string) : '');
function fromQuery(q: LocationQuery): Filters {
  return {
    org_id: q1(q, 'org_id'),
    severity: q1(q, 'severity').split(',').filter(Boolean),
    verdict: q1(q, 'verdict'),
    source_type: q1(q, 'source_type'),
    source_id: q1(q, 'source_id'),
    entity: q1(q, 'entity'),
    delivery_status: q1(q, 'delivery_status'),
    time_from: q1(q, 'time_from'),
    time_to: q1(q, 'time_to'),
    technique: q1(q, 'technique'),
  };
}
const applied = computed(() => fromQuery(route.query));
const offset = computed(() => Number(q1(route.query, 'offset')) || 0);
const f = reactive<Filters>({ ...applied.value, severity: [...applied.value.severity] });
const orgs = useAsync(() => api.get<Org[]>('/orgs'));
const list = useAsync(() => {
  const a = applied.value;
  return api.get<{ total: number; items: AlertItem[] }>('/alerts', {
    org_id: a.org_id,
    severity: a.severity.join(','),
    verdict: a.verdict,
    source_type: a.source_type,
    source_id: a.source_id,
    entity: a.entity,
    delivery_status: a.delivery_status,
    time_from: a.time_from ? localInputToIso(a.time_from) : undefined,
    time_to: a.time_to ? localInputToIso(a.time_to) : undefined,
    technique: a.technique.trim().toUpperCase() || undefined,
    limit: PAGE,
    offset: offset.value,
  });
}, [() => route.fullPath]);
const total = computed(() => list.data.value?.total ?? 0);

function apply(nf: Filters, off = 0) {
  const q: Record<string, string> = {};
  for (const [k, v] of Object.entries(nf)) {
    const s = Array.isArray(v) ? v.join(',') : v;
    if (s) q[k] = s;
  }
  if (off) q.offset = String(off);
  void router.replace({ query: q });
}
function preset(hours: number) {
  f.time_from = kstInput(-hours);
  f.time_to = '';
  apply(f);
}
function reset() {
  Object.assign(f, { ...EMPTY, severity: [] });
  apply(f);
}
function toggleSev(s: string, on: boolean) {
  f.severity = on ? [...f.severity, s] : f.severity.filter((x) => x !== s);
}
</script>
<template>
  <div class="page">
    <div class="page-head">
      <h2>경보</h2>
      <div class="actions"><button @click="list.reload">새로고침</button></div>
    </div>
    <form class="card filters" data-testid="alert-filters" @submit.prevent="apply(f)">
      <div class="filter-grid">
        <label class="field">
          <span class="field-label">기관</span>
          <select v-model="f.org_id" data-testid="alert-filter-org">
            <option value="">전체</option>
            <option v-for="o in orgs.data.value ?? []" :key="o.org_id" :value="o.org_id">{{ o.org_id }} {{ o.name }}</option>
          </select>
        </label>
        <div class="field">
          <span class="field-label">등급</span>
          <div class="checks" data-testid="alert-filter-severity">
            <label v-for="s in [...SEVERITIES].reverse()" :key="s" class="check">
              <input type="checkbox" :checked="f.severity.includes(s)" @change="toggleSev(s, ($event.target as HTMLInputElement).checked)" />
              {{ SEVERITY_LABEL[s] }}
            </label>
          </div>
        </div>
        <label v-if="showIncident()" class="field">
          <span class="field-label">판정</span>
          <select v-model="f.verdict" data-testid="alert-filter-verdict">
            <option value="">전체</option>
            <option value="none">미판정</option>
            <option v-for="(v, k) in VERDICT_LABEL" :key="k" :value="k">{{ v }}</option>
          </select>
        </label>
        <label class="field">
          <span class="field-label">출처</span>
          <div class="inline-pair">
            <select v-model="f.source_type">
              <option value="">전체</option>
              <option value="scenario">시나리오</option>
              <option value="single_rule">이벤트 탐지모듈</option>
            </select>
            <input v-model="f.source_id" placeholder="ID" data-testid="alert-filter-source" />
          </div>
        </label>
        <label class="field">
          <span class="field-label">대상 검색</span>
          <input v-model="f.entity" placeholder="IP 일부" data-testid="alert-filter-entity" />
        </label>
        <label v-if="showIncident()" class="field">
          <span class="field-label">전달 상태</span>
          <select v-model="f.delivery_status">
            <option value="">전체</option>
            <option v-for="(v, k) in DELIVERY_LABEL" :key="k" :value="k">{{ v }}</option>
          </select>
        </label>
        <label class="field">
          <span class="field-label">ATT&amp;CK 기법</span>
          <input v-model="f.technique" placeholder="T1190 (상위 기법이면 하위 포함)" data-testid="alert-filter-technique" />
        </label>
        <label class="field"><span class="field-label">기간 시작 (KST)</span><input v-model="f.time_from" type="datetime-local" /></label>
        <label class="field"><span class="field-label">기간 끝 (KST)</span><input v-model="f.time_to" type="datetime-local" /></label>
      </div>
      <div class="form-row">
        <button type="button" class="small" @click="preset(24)">최근 24시간</button>
        <button type="button" class="small" @click="preset(24 * 7)">최근 7일</button>
        <button type="button" class="small" @click="preset(24 * 30)">최근 30일</button>
        <span class="spacer" />
        <button type="button" @click="reset">초기화</button>
        <button class="primary" type="submit" data-testid="alert-filter-apply">검색</button>
      </div>
    </form>
    <LoadingBox v-if="list.loading.value && !list.data.value" />
    <ErrorBox :error="list.error.value" />
    <div v-if="list.data.value" class="card table-wrap">
      <table class="table" data-testid="alert-list">
        <thead>
          <tr><th>생성</th><th>등급</th><th>제목</th><th>기관</th><th>대상</th><th>출처</th><th>ATT&amp;CK</th><th>최초~최종</th><th class="num">횟수</th><template v-if="showIncident()"><th>전달</th><th>판정</th></template></tr>
        </thead>
        <tbody>
          <tr v-for="a in list.data.value.items" :key="a.alert_id">
            <td class="small">{{ fmtTime(a.created_at) }}</td>
            <td><SeverityBadge :severity="a.severity" /> <UiBadge v-if="a.upgraded_at" kind="info">상향</UiBadge></td>
            <td><RouterLink :to="`/alerts/${a.alert_id}`" :data-testid="`alert-link-${a.alert_id}`">{{ a.title }}</RouterLink></td>
            <td>{{ a.org_id }}</td>
            <td>{{ a.entity }}</td>
            <td class="small">{{ a.source_type === 'scenario' ? '시나리오' : '이벤트 탐지모듈' }} {{ a.source_id }} v{{ a.source_version }}</td>
            <td class="small"><AttackChips :items="a.attack" compact /></td>
            <td class="small">{{ fmtTime(a.first_seen) }}<br />{{ fmtTime(a.last_seen) }}</td>
            <td class="num">{{ a.hit_count }}</td>
            <td v-if="showIncident()">
              <UiBadge v-if="truthy(a.silent)">silent</UiBadge>
              <UiBadge :kind="a.delivery_status === 'failed' ? 'bad' : a.delivery_status === 'sent' ? 'ok' : undefined">{{ DELIVERY_LABEL[a.delivery_status] ?? a.delivery_status }}</UiBadge>
            </td>
            <td v-if="showIncident()">
              <UiBadge v-if="a.verdict" :kind="a.verdict === 'true_positive' ? 'bad' : 'ok'">{{ VERDICT_LABEL[a.verdict] ?? a.verdict }}</UiBadge>
              <span v-else class="muted">미판정</span>
            </td>
          </tr>
        </tbody>
      </table>
      <EmptyBox v-if="!list.data.value.items.length">조건에 맞는 경보가 없습니다</EmptyBox>
      <div class="pager" data-testid="alert-pager">
        <button :disabled="offset <= 0" @click="apply(applied, Math.max(0, offset - PAGE))">이전</button>
        <span>{{ total ? `${offset + 1}–${Math.min(offset + PAGE, total)}` : 0 }} / 전체 {{ total }}건</span>
        <button :disabled="offset + PAGE >= total" @click="apply(applied, offset + PAGE)">다음</button>
      </div>
    </div>
  </div>
</template>
