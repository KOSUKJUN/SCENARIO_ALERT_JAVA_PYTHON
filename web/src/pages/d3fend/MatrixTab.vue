<script setup lang="ts">
// D3FEND 매트릭스: 전술(열) × 방어 기법(상위 아래 하위를 들여 씀). 이벤트 탐지모듈·시나리오가 대응방책으로 지정한 기법을 칠한다.
import { computed, ref } from 'vue';
import { api } from '../../api';
import { useAsync } from '../../composables';
import D3fendTechniqueModal from '../../components/D3fendTechniqueModal.vue';
import EmptyBox from '../../components/EmptyBox.vue';
import ErrorBox from '../../components/ErrorBox.vue';
import LoadingBox from '../../components/LoadingBox.vue';
import { RESPONSE_TACTICS } from '../../d3fend';
import type { D3fendMatrix, D3fendMatrixCell, D3fendVersion } from '../../types';

const ver = ref('');
const q = ref('');
const onlyDesignated = ref(false);
const onlyMapped = ref(false);
const vs = useAsync(() => api.get<{ versions: D3fendVersion[]; active: string | null }>('/d3fend/versions'));
const m = useAsync(() => api.get<D3fendMatrix>('/d3fend/matrix', { version: ver.value || undefined }), [ver]);
const detail = ref<string | null>(null);
function visible(c: D3fendMatrixCell): boolean {
  if (onlyDesignated.value && !c.designated) return false;
  if (onlyMapped.value && !c.attack_count) return false;
  const s = q.value.trim().toLowerCase();
  return !s || c.id.toLowerCase().includes(s) || c.name.toLowerCase().includes(s);
}
const notFound = computed(() => (m.error.value as { status?: number } | null)?.status === 404);
</script>
<template>
  <div>
    <div class="form-row">
      <select v-model="ver" data-testid="d3fend-version-select">
        <option value="">활성 버전{{ vs.data.value?.active ? ` (${vs.data.value.active})` : '' }}</option>
        <option v-for="v in vs.data.value?.versions ?? []" :key="v.version" :value="v.version">{{ v.version }}{{ v.is_active ? ' (활성)' : '' }}</option>
      </select>
      <input v-model="q" placeholder="기법 거르기 (ID·이름)" data-testid="d3fend-matrix-filter" />
      <label class="check"><input v-model="onlyDesignated" type="checkbox" />지정된 기법만</label>
      <label class="check"><input v-model="onlyMapped" type="checkbox" />ATT&amp;CK 매핑 있는 기법만</label>
      <span class="spacer" />
      <span v-if="m.data.value" class="small" data-testid="d3fend-summary">
        D3FEND {{ m.data.value.version }} · 방어 기법 {{ m.data.value.summary.techniques }}개 중
        <strong>{{ m.data.value.summary.designated }}개 지정</strong>
      </span>
    </div>
    <p class="muted small">
      칸의 숫자: 대응하는 ATT&amp;CK 기법 수 / 이 기법을 지정한 이벤트 탐지모듈·시나리오 경보 노드 수. 노란 테두리 열은 사고 대응 전술(격리·퇴출·복구)입니다.
    </p>
    <LoadingBox v-if="m.loading.value" />
    <EmptyBox v-else-if="notFound">D3FEND 데이터가 없습니다. "버전 관리" 탭에서 릴리스를 가져오세요.</EmptyBox>
    <ErrorBox v-else :error="m.error.value" />
    <div v-if="m.data.value" class="matrix" data-testid="d3fend-matrix">
      <div v-for="t in m.data.value.tactics" :key="t.name" :class="['matrix-col', { response: RESPONSE_TACTICS.includes(t.name) }]">
        <div class="matrix-head" :title="t.definition ?? ''">
          <strong>{{ t.label_ko }}</strong> <span class="muted small">{{ t.name }}</span>
          <div class="muted small">{{ t.techniques.filter((c) => c.designated).length }}/{{ t.techniques.length }}</div>
        </div>
        <template v-for="c in t.techniques" :key="c.id">
          <button
            v-if="visible(c)"
            type="button"
            :class="['matrix-cell', { designated: c.designated > 0, top: c.depth === 0 }]"
            :style="{ marginLeft: `${Math.min(c.depth, 3) * 8}px` }"
            :data-testid="`d3fend-cell-${c.id}`"
            @click="detail = c.id"
          >
            <span class="cell-id">{{ c.id }}</span>
            <span class="cell-name">{{ c.name }}</span>
            <span v-if="c.attack_count || c.designated" class="cell-num small">{{ c.attack_count }} / {{ c.designated }}</span>
          </button>
        </template>
      </div>
    </div>
    <D3fendTechniqueModal v-if="detail" :id="detail" :version="ver || undefined" @close="detail = null" />
  </div>
</template>
<style scoped>
.matrix { display: flex; gap: 6px; overflow-x: auto; padding-bottom: 8px; align-items: flex-start; }
.matrix-col { min-width: 170px; max-width: 200px; display: flex; flex-direction: column; gap: 3px; }
.matrix-head { padding: 6px; border-bottom: 2px solid var(--primary); position: sticky; top: 0; background: var(--bg); }
.matrix-col.response .matrix-head { border-bottom-color: var(--warn); }
.matrix-cell {
  display: flex; flex-direction: column; align-items: flex-start; gap: 1px; text-align: left; padding: 4px 6px;
  border: 1px solid var(--border); border-radius: var(--radius); background: var(--surface); color: var(--text);
  font-size: 12px; min-height: 0; cursor: pointer; white-space: normal;
}
.matrix-cell.top { font-weight: 600; }
.matrix-cell:hover { border-color: var(--primary); }
.matrix-cell.designated { border-color: var(--ok); background: color-mix(in srgb, var(--ok) 14%, var(--surface)); }
.cell-id { font-family: var(--mono); color: var(--muted); font-weight: 400; }
.cell-num { color: var(--muted); font-weight: 400; }
</style>
