<script setup lang="ts">
// 과거 사고 (백테스트 재현율 확인용).
import { computed, ref } from 'vue';
import { api, enc } from '../../api';
import { has } from '../../auth';
import { useAsync } from '../../composables';
import CardBox from '../../components/CardBox.vue';
import EmptyBox from '../../components/EmptyBox.vue';
import ErrorBox from '../../components/ErrorBox.vue';
import type { Incident } from '../../types';
import { fmtTime, kstInput, localInputToIso } from '../../util';

const canEdit = computed(() => has('author'));
const list = useAsync(() => api.get<Incident[]>('/known-incidents'));
const draft = ref({ incident_id: '', org_id: 'ORG001', entity: '', occurred_at: kstInput(-24), summary: '' });
const err = ref<unknown>(null);

async function add() {
  err.value = null;
  try {
    await api.post('/known-incidents', { ...draft.value, occurred_at: localInputToIso(draft.value.occurred_at), summary: draft.value.summary || null });
    draft.value = { ...draft.value, incident_id: '', entity: '', summary: '' };
    list.reload();
  } catch (e) {
    err.value = e;
  }
}
async function remove(id: string) {
  if (!window.confirm(`${id} 를 지울까요?`)) return;
  try {
    await api.del(`/known-incidents/${enc(id)}`);
    list.reload();
  } catch (e) {
    err.value = e;
  }
}
</script>
<template>
  <CardBox title="과거 사고 (재현율 확인용)">
    <ErrorBox :error="err || list.error.value" closable @close="err = null" />
    <div v-if="canEdit" class="form-row wrap">
      <input v-model="draft.incident_id" placeholder="사고 ID" />
      <input v-model="draft.org_id" placeholder="기관" />
      <input v-model="draft.entity" placeholder="대상 IP" />
      <input v-model="draft.occurred_at" type="datetime-local" />
      <input v-model="draft.summary" placeholder="요약" class="grow" />
      <button class="primary small" :disabled="!draft.incident_id || !draft.entity" @click="add">추가</button>
    </div>
    <table v-if="list.data.value?.length" class="table compact">
      <thead><tr><th>사고</th><th>기관</th><th>대상</th><th>발생</th><th>요약</th><th /></tr></thead>
      <tbody>
        <tr v-for="i in list.data.value" :key="i.incident_id">
          <td>{{ i.incident_id }}</td><td>{{ i.org_id }}</td><td>{{ i.entity }}</td><td>{{ fmtTime(i.occurred_at) }}</td><td class="small">{{ i.summary }}</td>
          <td><button v-if="canEdit" class="small danger" @click="remove(i.incident_id)">삭제</button></td>
        </tr>
      </tbody>
    </table>
    <EmptyBox v-else-if="list.data.value">등록된 과거 사고가 없습니다</EmptyBox>
  </CardBox>
</template>
