<script setup lang="ts">
// 지정 대응방책 고르기: MITRE D3FEND 방어 기법을 ID·이름으로 활성 버전에서 찾아 추가, 칩을 누르면 상세. 값은 기법 ID 목록.
// suggestFor 에 ATT&CK 기법을 주면 그 기법의 D3FEND 매핑에서 사고 대응(격리·퇴출·복구) 기법을 추천으로 보여 준다.
import { computed, onBeforeUnmount, ref, watch } from 'vue';
import { api } from '../api';
import { D3FEND_RE, lookupD3fend, TACTIC_KO } from '../d3fend';
import type { Countermeasures, D3fendLookup, D3fendSearchItem } from '../types';
import D3fendTechniqueModal from './D3fendTechniqueModal.vue';

const props = defineProps<{ modelValue?: string[]; disabled?: boolean; testId?: string; suggestFor?: string[] }>();
const emit = defineEmits<{ 'update:modelValue': [v: string[]] }>();
const ids = computed(() => props.modelValue ?? []);
const tid = computed(() => props.testId ?? 'd3fend-picker');
const info = ref<Record<string, D3fendLookup>>({});
const q = ref('');
const results = ref<D3fendSearchItem[]>([]);
const open = ref(false);
const searchErr = ref<string | null>(null);
const noData = ref(false);
const detail = ref<string | null>(null);
const suggest = ref<{ id: string; name: string; tactic: string }[]>([]);

watch(
  ids,
  async (v) => {
    const missing = v.filter((i) => !info.value[i]);
    if (!missing.length) return;
    try {
      info.value = { ...info.value, ...(await lookupD3fend(missing)) };
    } catch {
      /* 표시용: 실패해도 ID 는 보인다 */
    }
  },
  { immediate: true },
);

watch(
  () => (props.suggestFor ?? []).join(','),
  async () => {
    const atk = props.suggestFor ?? [];
    if (!atk.length || props.disabled) {
      suggest.value = [];
      return;
    }
    try {
      const r = await api.post<Countermeasures>('/d3fend/countermeasures', { attack: atk });
      suggest.value = r.tactics
        .filter((g) => g.response)
        .flatMap((g) => g.techniques.slice(0, 3).map((t) => ({ id: t.id, name: t.name, tactic: g.tactic })));
    } catch {
      suggest.value = [];
    }
  },
  { immediate: true },
);

let timer: ReturnType<typeof setTimeout> | undefined;
watch(q, (v) => {
  clearTimeout(timer);
  if (!v.trim()) {
    results.value = [];
    return;
  }
  timer = setTimeout(() => void search(v.trim()), 250);
});
onBeforeUnmount(() => clearTimeout(timer));

async function search(text: string) {
  try {
    results.value = await api.get<D3fendSearchItem[]>('/d3fend/techniques', { q: text, limit: 20 });
    searchErr.value = null;
    noData.value = false;
    open.value = true;
  } catch (e) {
    results.value = [];
    const st = (e as { status?: number }).status;
    noData.value = st === 404;
    searchErr.value = st === 404 ? 'D3FEND 데이터가 없습니다 (D3FEND > 버전 관리에서 가져오세요)' : '검색 실패';
  }
}

function add(id: string) {
  if (!ids.value.includes(id)) emit('update:modelValue', [...ids.value, id]);
  q.value = '';
  results.value = [];
  open.value = false;
}
function addTyped() {
  const v = q.value.trim().toUpperCase();
  if (D3FEND_RE.test(v)) add(v);
  else if (results.value.length) add(results.value[0].id);
}
function onBlur() {
  setTimeout(() => (open.value = false), 150);
}
function remove(id: string) {
  emit('update:modelValue', ids.value.filter((x) => x !== id));
}
const suggestions = computed(() => suggest.value.filter((s) => !ids.value.includes(s.id)));
</script>
<template>
  <div class="d3-picker" :data-testid="tid">
    <div class="chips">
      <span v-for="id in ids" :key="id" :class="['chip', 'd3-chip', { missing: !info[id] }]" :data-testid="`d3fend-chip-${id}`">
        <a href="#" @click.prevent="detail = id">{{ id }}</a>
        <span class="small">{{ info[id]?.name ?? '' }}</span>
        <span v-if="info[id]?.tactic" class="muted small">· {{ TACTIC_KO[info[id].tactic!] ?? info[id].tactic }}</span>
        <button v-if="!disabled" type="button" class="chip-x" :aria-label="`${id} 빼기`" @click="remove(id)">×</button>
      </span>
      <span v-if="!ids.length" class="muted small">없음</span>
    </div>
    <div v-if="!disabled && suggestions.length" class="d3-suggest small" :data-testid="`${tid}-suggest`">
      <span class="muted">ATT&amp;CK 기법 기준 추천:</span>
      <button v-for="s in suggestions" :key="s.id" type="button" class="small" :title="s.name" :data-testid="`d3fend-suggest-${s.id}`" @click="add(s.id)">
        + {{ s.id }} {{ s.name }} <span class="muted">({{ TACTIC_KO[s.tactic] ?? s.tactic }})</span>
      </button>
    </div>
    <div v-if="!disabled" class="d3-search">
      <input
        v-model="q"
        placeholder="대응 기법 ID 또는 이름 (예: D3-NI, isolation, termination)"
        :data-testid="`${tid}-input`"
        @keydown.enter.prevent="addTyped"
        @focus="open = results.length > 0"
        @blur="onBlur"
      />
      <ul v-if="open && results.length" class="d3-results" role="listbox">
        <li v-for="r in results" :key="r.id" role="option" :data-testid="`d3fend-result-${r.id}`" @mousedown.prevent="add(r.id)">
          <strong>{{ r.id }}</strong> {{ r.name }}
          <span class="muted small"> · {{ TACTIC_KO[r.tactic] ?? r.tactic }}<template v-if="r.parent_name"> · {{ r.parent_name }}</template></span>
        </li>
      </ul>
      <div v-if="searchErr" :class="noData ? 'warn-text small' : 'err-text small'">{{ searchErr }}</div>
    </div>
    <D3fendTechniqueModal v-if="detail" :id="detail" @close="detail = null" />
  </div>
</template>
<style scoped>
.d3-chip { display: inline-flex; gap: 4px; align-items: center; padding: 1px 6px; }
.d3-chip.missing { border-color: var(--bad); }
.chip-x { border: 0; background: none; padding: 0 2px; min-height: 0; line-height: 1; cursor: pointer; color: var(--muted); }
.d3-suggest { display: flex; flex-wrap: wrap; gap: 4px; align-items: center; margin-top: 4px; }
.d3-search { position: relative; margin-top: 4px; }
.d3-search input { width: 100%; }
.d3-results {
  position: absolute; z-index: 20; left: 0; right: 0; max-height: 260px; overflow: auto; margin: 2px 0 0; padding: 0;
  list-style: none; background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius);
}
.d3-results li { padding: 4px 8px; cursor: pointer; }
.d3-results li:hover { background: var(--surface-2); }
</style>
