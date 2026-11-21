<script setup lang="ts">
// 시나리오 분석 (탐지 설정 > 룰 관리 화면과 같은 배치):
//   왼쪽 시나리오 그룹(전체·그룹·미분류) | 오른쪽 검색 조건 → 시나리오 리스트 → 쪽 번호 → 아래 오른쪽 버튼.
//   [이벤트 탐지모듈 관리] 는 모듈 목록을 새 창(/popup/modules)으로 연다. 그룹 선택은 주소(?group=)에 남긴다.
import { computed, reactive, ref, watch } from 'vue';
import { useRoute, useRouter } from 'vue-router';
import { api } from '../../api';
import { has } from '../../auth';
import { useAsync } from '../../composables';
import ErrorBox from '../../components/ErrorBox.vue';
import LoadingBox from '../../components/LoadingBox.vue';
import ModuleIcon from '../../components/ModuleIcon.vue';
import ScenarioIcon from '../../components/ScenarioIcon.vue';
import type { GroupKey, RuleSummary, ScenarioGroupList, ScenarioSummary } from '../../types';
import { SEVERITY_LABEL, STATUSES, STATUS_LABEL } from '../../util';
import ScenarioGroupPanel from './ScenarioGroupPanel.vue';
import ScenarioList from './ScenarioList.vue';

const route = useRoute();
const router = useRouter();
const canEdit = computed(() => has('author'));
const scenarios = useAsync(() => api.get<ScenarioSummary[]>('/scenarios'));
const rules = useAsync(() => api.get<RuleSummary[]>('/single-rules'));
const groups = useAsync(() => api.get<ScenarioGroupList>('/scenario-groups'));

const selected = computed<GroupKey>(() => {
  const g = route.query.group;
  if (g === 'none') return 'none';
  const n = Number(g);
  return g && Number.isInteger(n) ? n : 'all';
});
function selectGroup(k: GroupKey) {
  checked.value = [];
  void router.replace({ path: '/scenarios', query: k === 'all' ? {} : { group: String(k) } });
}
const groupNames = computed<Record<number, string>>(() => Object.fromEntries((groups.data.value?.groups ?? []).map((g) => [g.group_id, g.name])));
const selectedName = computed(() => (selected.value === 'all' ? '전체' : selected.value === 'none' ? '미분류' : groupNames.value[selected.value] ?? ''));
const ruleNames = computed<Record<string, string>>(() => Object.fromEntries((rules.data.value ?? []).map((r) => [r.rule_id, r.name])));

// 검색 조건: 입력 후 [검색](또는 Enter) 으로 적용, [초기화] 로 비운다
const form = reactive({ q: '', status: '', severity: '', module: '' });
const applied = ref({ ...form });
function search() {
  applied.value = { ...form };
}
function reset() {
  Object.assign(form, { q: '', status: '', severity: '', module: '' });
  search();
}
const rows = computed(() => {
  const f = applied.value;
  const q = f.q.trim().toLowerCase();
  const mod = f.module.trim().toLowerCase();
  return (scenarios.data.value ?? []).filter((s) => {
    if (selected.value === 'none' && s.group_id != null) return false;
    if (typeof selected.value === 'number' && s.group_id !== selected.value) return false;
    if (f.status && s.status !== f.status) return false;
    if (f.severity && !s.severities.includes(f.severity as ScenarioSummary['severities'][number])) return false;
    if (q && !s.scenario_id.toLowerCase().includes(q) && !s.name.toLowerCase().includes(q)) return false;
    if (mod && !s.rule_ids.some((r) => r.toLowerCase().includes(mod) || (ruleNames.value[r] ?? '').toLowerCase().includes(mod))) return false;
    return true;
  });
});

// 선택한 시나리오를 다른 그룹으로
const checked = ref<string[]>([]);
const moveTo = ref('');
const moveError = ref<unknown>(null);
const moving = ref(false);
async function move() {
  if (!checked.value.length || moveTo.value === '') return;
  moving.value = true;
  moveError.value = null;
  try {
    await api.put('/scenario-groups/assign', { group_id: moveTo.value === 'none' ? null : Number(moveTo.value), scenario_ids: checked.value });
    checked.value = [];
    moveTo.value = '';
    scenarios.reload();
    groups.reload();
  } catch (e) {
    moveError.value = e;
  } finally {
    moving.value = false;
  }
}
watch(rows, (r) => {
  const ids = new Set(r.map((s) => s.scenario_id));
  checked.value = checked.value.filter((x) => ids.has(x));
});

const newLink = computed(() => (typeof selected.value === 'number' ? `/scenarios/new?group=${selected.value}` : '/scenarios/new'));
function openModules() {
  window.open('/popup/modules', 'scenario-modules', 'width=1280,height=820,resizable=yes,scrollbars=yes');
}
</script>
<template>
  <div class="page hub">
    <nav class="crumbs" aria-label="위치"><span>보안관제</span><span class="crumb-sep">/</span><strong class="crumb-now">시나리오 분석</strong></nav>
    <div class="hub-grid">
      <ScenarioGroupPanel :data="groups.data.value" :selected="selected" :can-edit="canEdit" @select="selectGroup" @changed="groups.reload(), scenarios.reload()" />

      <section class="hub-main card">
        <form class="search-grid" data-testid="scenario-search-form" @submit.prevent="search">
          <label class="sf wide">
            <span>시나리오명</span>
            <input v-model="form.q" placeholder="이름·ID" data-testid="scenario-search" />
          </label>
          <label class="sf wide">
            <span>사용 이벤트 탐지모듈</span>
            <input v-model="form.module" placeholder="모듈 이름·ID" data-testid="scenario-module-filter" />
          </label>
          <label class="sf">
            <span>상태</span>
            <select v-model="form.status" data-testid="scenario-status-filter">
              <option value="">--- 선택 ---</option>
              <option v-for="s in STATUSES" :key="s" :value="s">{{ STATUS_LABEL[s] }}</option>
            </select>
          </label>
          <label class="sf">
            <span>경보 등급</span>
            <select v-model="form.severity" data-testid="scenario-severity-filter">
              <option value="">--- 선택 ---</option>
              <option v-for="s in ['critical', 'high', 'medium', 'low']" :key="s" :value="s">{{ SEVERITY_LABEL[s] ?? s }}</option>
            </select>
          </label>
          <div class="sf-actions">
            <button type="submit" class="primary" data-testid="scenario-search-btn">검색</button>
            <button type="button" data-testid="scenario-reset" @click="reset">초기화</button>
          </div>
        </form>

        <div class="list-title">
          <ScenarioIcon />
          <strong>시나리오 리스트</strong>
          <span class="muted small">{{ selectedName }} · {{ rows.length }}개</span>
        </div>
        <LoadingBox v-if="scenarios.loading.value && !scenarios.data.value" />
        <ErrorBox :error="scenarios.error.value || groups.error.value" />
        <ScenarioList v-if="scenarios.data.value" v-model:checked="checked" :rows="rows" :rule-names="ruleNames" :group-names="groupNames" :selectable="canEdit" />

        <div class="hub-foot">
          <template v-if="canEdit">
            <span class="muted small">선택 {{ checked.length }}개</span>
            <select v-model="moveTo" :disabled="!checked.length" data-testid="group-move-select" aria-label="옮길 그룹">
              <option value="">그룹 이동…</option>
              <option v-for="g in groups.data.value?.groups ?? []" :key="g.group_id" :value="String(g.group_id)">{{ g.name }}</option>
              <option value="none">미분류</option>
            </select>
            <button :disabled="!checked.length || moveTo === '' || moving" data-testid="group-move" @click="move">이동</button>
          </template>
          <span class="spacer" />
          <button data-testid="modules-popup" title="이벤트 탐지모듈 목록을 새 창으로 엽니다" @click="openModules">
            <ModuleIcon /> 이벤트 탐지모듈 관리
            <svg viewBox="0 0 16 16" width="12" height="12" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
              <path d="M9 2.5h4.5V7M13.5 2.5 7.5 8.5M12 9.5v3.5a.5.5 0 0 1-.5.5h-8a.5.5 0 0 1-.5-.5v-8a.5.5 0 0 1 .5-.5H7" />
            </svg>
          </button>
          <RouterLink v-if="canEdit" :to="newLink" class="button primary" data-testid="scenario-new">+ 시나리오 등록</RouterLink>
        </div>
        <ErrorBox :error="moveError" closable @close="moveError = null" />
      </section>
    </div>
  </div>
</template>
