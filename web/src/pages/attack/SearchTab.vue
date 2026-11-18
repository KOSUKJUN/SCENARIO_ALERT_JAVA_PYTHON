<script setup lang="ts">
// 기법 찾기: ID 앞부분 또는 이름 일부로 찾는다 (사용 중단·폐기 기법은 제외).
import { ref, watch } from 'vue';
import { api } from '../../api';
import AttackTechniqueModal from '../../components/AttackTechniqueModal.vue';
import ErrorBox from '../../components/ErrorBox.vue';
import type { AttackSearchItem } from '../../types';
import VersionSelect from './VersionSelect.vue';

const ver = ref('');
const q = ref('');
const items = ref<AttackSearchItem[]>([]);
const err = ref<unknown>(null);
const detail = ref<string | null>(null);
let timer: ReturnType<typeof setTimeout> | undefined;

async function run() {
  const [domain, version] = ver.value ? ver.value.split('|') : [undefined, undefined];
  try {
    items.value = await api.get<AttackSearchItem[]>('/attack/techniques', { q: q.value.trim(), domain, version, limit: 100 });
    err.value = null;
  } catch (e) {
    err.value = e;
    items.value = [];
  }
}
watch([q, ver], () => {
  clearTimeout(timer);
  timer = setTimeout(() => void run(), 250);
}, { immediate: true });
</script>
<template>
  <div>
    <div class="form-row">
      <VersionSelect v-model="ver" />
      <input v-model="q" placeholder="T1190, T1059, brute, web shell ..." data-testid="attack-search-input" style="min-width: 320px" />
    </div>
    <ErrorBox :error="err" />
    <table class="table" data-testid="attack-search-results">
      <thead><tr><th>ID</th><th>이름</th><th>상위 기법</th><th>전술</th></tr></thead>
      <tbody>
        <tr v-for="t in items" :key="t.id">
          <td><a href="#" class="mono" @click.prevent="detail = t.id">{{ t.id }}</a></td>
          <td>{{ t.name }}</td>
          <td class="small">{{ t.parent_name ?? '' }}</td>
          <td class="small">{{ t.tactics.join(', ') }}</td>
        </tr>
        <tr v-if="!items.length && !err"><td colspan="4" class="muted">결과 없음</td></tr>
      </tbody>
    </table>
    <AttackTechniqueModal
      v-if="detail"
      :id="detail"
      :domain="ver ? ver.split('|')[0] : undefined"
      :version="ver ? ver.split('|')[1] : undefined"
      @close="detail = null"
    />
  </div>
</template>
