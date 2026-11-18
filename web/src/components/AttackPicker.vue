<script setup lang="ts">
// MITRE ATT&CK 기법 고르기: ID·이름으로 활성 버전에서 찾아 추가, 칩을 누르면 상세. 값은 기법 ID 목록.
import { computed, onBeforeUnmount, ref, watch } from 'vue';
import { api } from '../api';
import { lookupTechniques, TECHNIQUE_RE } from '../attack';
import type { AttackLookup, AttackSearchItem } from '../types';
import AttackTechniqueModal from './AttackTechniqueModal.vue';

const props = defineProps<{ modelValue?: string[]; disabled?: boolean; testId?: string }>();
const emit = defineEmits<{ 'update:modelValue': [v: string[]] }>();
const ids = computed(() => props.modelValue ?? []);
const info = ref<Record<string, AttackLookup>>({});
const noData = ref(false);
const q = ref('');
const results = ref<AttackSearchItem[]>([]);
const open = ref(false);
const searchErr = ref<string | null>(null);
const detail = ref<string | null>(null);

watch(
  ids,
  async (v) => {
    const missing = v.filter((i) => !info.value[i]);
    if (!missing.length) return;
    try {
      info.value = { ...info.value, ...(await lookupTechniques(missing)) };
    } catch {
      /* 표시용: 실패해도 ID 는 보인다 */
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
    results.value = await api.get<AttackSearchItem[]>('/attack/techniques', { q: text, limit: 20 });
    searchErr.value = null;
    noData.value = false;
    open.value = true;
  } catch (e) {
    results.value = [];
    const st = (e as { status?: number }).status;
    noData.value = st === 404;
    searchErr.value = st === 404 ? 'ATT&CK 데이터가 없습니다 (ATT&CK > 버전 관리에서 가져오세요)' : '검색 실패';
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
  if (TECHNIQUE_RE.test(v)) add(v);
  else if (results.value.length) add(results.value[0].id);
}
/** 결과 목록은 mousedown 으로 고르므로 blur 를 조금 늦춰 닫는다. */
function onBlur() {
  setTimeout(() => (open.value = false), 150);
}
function remove(id: string) {
  emit('update:modelValue', ids.value.filter((x) => x !== id));
}
function state(id: string): 'ok' | 'missing' | 'revoked' | 'deprecated' {
  const t = info.value[id];
  if (!t) return 'missing';
  if (t.revoked) return 'revoked';
  if (t.deprecated) return 'deprecated';
  return 'ok';
}
</script>
<template>
  <div class="attack-picker" :data-testid="testId ?? 'attack-picker'">
    <div class="chips">
      <span v-for="id in ids" :key="id" :class="['chip', 'attack-chip', state(id)]" :data-testid="`attack-chip-${id}`">
        <a href="#" @click.prevent="detail = id">{{ id }}</a>
        <span class="small">{{ info[id]?.name ?? '' }}</span>
        <span v-if="info[id]?.tactics?.length" class="muted small">· {{ info[id].tactics.map((t) => t.name).join(', ') }}</span>
        <span v-if="state(id) === 'revoked'" class="err-text small">폐기 → {{ info[id].revoked_by }}</span>
        <span v-else-if="state(id) === 'deprecated'" class="warn-text small">사용 중단</span>
        <button v-if="!disabled" type="button" class="chip-x" :aria-label="`${id} 빼기`" @click="remove(id)">×</button>
      </span>
      <span v-if="!ids.length" class="muted small">없음</span>
    </div>
    <div v-if="!disabled" class="attack-search">
      <input
        v-model="q"
        placeholder="기법 ID 또는 이름 (예: T1190, brute)"
        :data-testid="`${testId ?? 'attack-picker'}-input`"
        @keydown.enter.prevent="addTyped"
        @focus="open = results.length > 0"
        @blur="onBlur"
      />
      <ul v-if="open && results.length" class="attack-results" role="listbox">
        <li v-for="r in results" :key="r.id" role="option" :data-testid="`attack-result-${r.id}`" @mousedown.prevent="add(r.id)">
          <strong>{{ r.id }}</strong> {{ r.name }}
          <span v-if="r.parent_name" class="muted small">({{ r.parent_name }})</span>
          <span class="muted small"> · {{ r.tactics.join(', ') }}</span>
        </li>
      </ul>
      <div v-if="searchErr" :class="noData ? 'warn-text small' : 'err-text small'">{{ searchErr }}</div>
    </div>
    <AttackTechniqueModal v-if="detail" :id="detail" @close="detail = null" />
  </div>
</template>
<style scoped>
.attack-chip { display: inline-flex; gap: 4px; align-items: center; padding: 1px 6px; }
.attack-chip.missing, .attack-chip.revoked { border-color: var(--bad); }
.attack-chip.deprecated { border-color: var(--warn); }
.chip-x { border: 0; background: none; padding: 0 2px; min-height: 0; line-height: 1; cursor: pointer; color: var(--muted); }
.attack-search { position: relative; margin-top: 4px; }
.attack-search input { width: 100%; }
.attack-results {
  position: absolute; z-index: 20; left: 0; right: 0; max-height: 260px; overflow: auto; margin: 2px 0 0; padding: 0;
  list-style: none; background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius);
}
.attack-results li { padding: 4px 8px; cursor: pointer; }
.attack-results li:hover { background: var(--surface-2); }
</style>
