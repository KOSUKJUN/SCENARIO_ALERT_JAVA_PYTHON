<script setup lang="ts">
// 탐지 커버리지 매트릭스: 전술(열) × 기법. 기법(또는 하위 기법)을 단 단일룰·순서도가 있으면 탐지됨으로 칠한다.
import { computed, ref } from 'vue';
import { api } from '../../api';
import { useAsync } from '../../composables';
import AttackTechniqueModal from '../../components/AttackTechniqueModal.vue';
import EmptyBox from '../../components/EmptyBox.vue';
import ErrorBox from '../../components/ErrorBox.vue';
import LoadingBox from '../../components/LoadingBox.vue';
import type { AttackMatrix, AttackMatrixCell } from '../../types';
import VersionSelect from './VersionSelect.vue';

const ver = ref('');
const onlyCovered = ref(false);
const q = ref('');
const m = useAsync(() => {
  const [domain, version] = ver.value ? ver.value.split('|') : [undefined, undefined];
  return api.get<AttackMatrix>('/attack/matrix', { domain, version });
}, [ver]);
const detail = ref<string | null>(null);
const pct = computed(() => {
  const s = m.data.value?.summary;
  return s && s.techniques ? Math.round((s.covered / s.techniques) * 100) : 0;
});
function visible(c: AttackMatrixCell): boolean {
  if (onlyCovered.value && !c.covered) return false;
  const s = q.value.trim().toLowerCase();
  return !s || c.id.toLowerCase().includes(s) || c.name.toLowerCase().includes(s);
}
const notFound = computed(() => {
  const e = m.error.value as { status?: number } | null;
  return e?.status === 404;
});
</script>
<template>
  <div>
    <div class="form-row">
      <VersionSelect v-model="ver" />
      <input v-model="q" placeholder="기법 거르기 (ID·이름)" data-testid="attack-matrix-filter" />
      <label class="check"><input v-model="onlyCovered" type="checkbox" />탐지되는 기법만</label>
      <span class="spacer" />
      <span v-if="m.data.value" class="small" data-testid="attack-coverage-summary">
        {{ m.data.value.domain }} {{ m.data.value.version }} · 기법 {{ m.data.value.summary.techniques }}개 중
        <strong>{{ m.data.value.summary.covered }}개 탐지 ({{ pct }}%)</strong>
      </span>
    </div>
    <p class="muted small">
      칸의 숫자: 단일룰 / 순서도 / 최근 30일 경보. 하위 기법의 매핑도 상위 기법 칸에 합산합니다. 칸을 누르면 상세를 봅니다.
    </p>
    <LoadingBox v-if="m.loading.value" />
    <EmptyBox v-else-if="notFound">ATT&amp;CK 데이터가 없습니다. "버전 관리" 탭에서 번들을 가져오세요.</EmptyBox>
    <ErrorBox v-else :error="m.error.value" />
    <div v-if="m.data.value" class="matrix" data-testid="attack-matrix">
      <div v-for="t in m.data.value.tactics" :key="t.id" class="matrix-col">
        <div class="matrix-head" :title="t.id">
          <strong>{{ t.name }}</strong>
          <div class="muted small">{{ t.id }} · {{ t.techniques.filter((c) => c.covered).length }}/{{ t.techniques.length }}</div>
        </div>
        <template v-for="c in t.techniques" :key="c.id">
          <button
            v-if="visible(c)"
            type="button"
            :class="['matrix-cell', { covered: c.covered, alerted: c.alerts_30d > 0 }]"
            :data-testid="`attack-cell-${t.id}-${c.id}`"
            @click="detail = c.id"
          >
            <span class="cell-id">{{ c.id }}</span>
            <span class="cell-name">{{ c.name }}</span>
            <span v-if="c.covered || c.alerts_30d" class="cell-num small">{{ c.rules }} / {{ c.scenarios }} / {{ c.alerts_30d }}</span>
            <span v-if="c.subtechniques?.length" class="muted small">하위 {{ c.subtechniques.length }}</span>
          </button>
        </template>
      </div>
    </div>
    <AttackTechniqueModal
      v-if="detail"
      :id="detail"
      :domain="ver ? ver.split('|')[0] : undefined"
      :version="ver ? ver.split('|')[1] : undefined"
      @close="detail = null"
    />
  </div>
</template>
<style scoped>
.matrix { display: flex; gap: 6px; overflow-x: auto; padding-bottom: 8px; align-items: flex-start; }
.matrix-col { min-width: 150px; max-width: 170px; display: flex; flex-direction: column; gap: 3px; }
.matrix-head { padding: 6px; border-bottom: 2px solid var(--primary); position: sticky; top: 0; background: var(--bg); }
.matrix-cell {
  display: flex; flex-direction: column; align-items: flex-start; gap: 1px; text-align: left; padding: 4px 6px;
  border: 1px solid var(--border); border-radius: var(--radius); background: var(--surface); color: var(--text);
  font-size: 12px; min-height: 0; cursor: pointer; white-space: normal;
}
.matrix-cell:hover { border-color: var(--primary); }
.matrix-cell.covered { border-color: var(--ok); background: color-mix(in srgb, var(--ok) 14%, var(--surface)); }
.matrix-cell.alerted { box-shadow: inset 3px 0 0 var(--warn); }
.cell-id { font-family: var(--mono); color: var(--muted); }
.cell-num { color: var(--ok); }
</style>
