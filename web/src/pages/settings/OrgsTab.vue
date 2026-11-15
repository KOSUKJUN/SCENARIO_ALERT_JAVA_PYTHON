<script setup lang="ts">
// 기관과 내부 대역. 대역은 방향 판정(net_direction)에 쓰인다. 기관 간 대역이 겹쳐도 된다 (기관 ID 로 나눠 판정).
import { ref } from 'vue';
import { api, enc } from '../../api';
import { has } from '../../auth';
import { useAsync } from '../../composables';
import CardBox from '../../components/CardBox.vue';
import ErrorBox from '../../components/ErrorBox.vue';
import FormField from '../../components/FormField.vue';
import LoadingBox from '../../components/LoadingBox.vue';
import ModalDialog from '../../components/ModalDialog.vue';
import UiBadge from '../../components/UiBadge.vue';
import type { Org } from '../../types';
import { splitList, truthy } from '../../util';

interface Draft {
  org_id: string;
  name: string;
  enabled: boolean;
  cidrs: string;
  isNew: boolean;
}
const orgs = useAsync(() => api.get<Org[]>('/orgs'));
const draft = ref<Draft | null>(null);
const err = ref<unknown>(null);
const busy = ref(false);

function edit(o?: Org) {
  err.value = null;
  draft.value = o
    ? { org_id: o.org_id, name: o.name, enabled: truthy(o.enabled), cidrs: o.cidrs.join('\n'), isNew: false }
    : { org_id: '', name: '', enabled: true, cidrs: '', isNew: true };
}
async function save() {
  const d = draft.value;
  if (!d) return;
  busy.value = true;
  err.value = null;
  try {
    const body = { org_id: d.org_id, name: d.name, enabled: d.enabled, cidrs: splitList(d.cidrs) };
    if (d.isNew) await api.post('/orgs', body);
    else await api.put(`/orgs/${enc(d.org_id)}`, body);
    draft.value = null;
    orgs.reload();
  } catch (e) {
    err.value = e;
  } finally {
    busy.value = false;
  }
}
</script>
<template>
  <CardBox title="기관과 내부 대역">
    <template #actions><button v-if="has('admin')" class="primary small" data-testid="org-new" @click="edit()">기관 추가</button></template>
    <LoadingBox v-if="orgs.loading.value && !orgs.data.value" />
    <ErrorBox :error="orgs.error.value" />
    <table v-if="orgs.data.value" class="table compact" data-testid="org-list">
      <thead><tr><th>기관 ID</th><th>이름</th><th>사용</th><th>내부 대역</th><th /></tr></thead>
      <tbody>
        <tr v-for="o in orgs.data.value" :key="o.org_id">
          <td>{{ o.org_id }}</td>
          <td>{{ o.name }}</td>
          <td><UiBadge :kind="truthy(o.enabled) ? 'ok' : undefined">{{ truthy(o.enabled) ? '사용' : '중지' }}</UiBadge></td>
          <td class="small"><span v-for="c in o.cidrs" :key="c" class="chip">{{ c }}</span></td>
          <td><button v-if="has('admin')" class="small" @click="edit(o)">수정</button></td>
        </tr>
      </tbody>
    </table>
    <p class="muted small">기관 추가·수정은 관리자만 할 수 있습니다. 대역을 바꾸면 ClickHouse 딕셔너리를 바로 다시 읽습니다.</p>
  </CardBox>
  <ModalDialog v-if="draft" :title="draft.isNew ? '기관 추가' : `기관 ${draft.org_id}`" @close="draft = null">
    <ErrorBox :error="err" />
    <FormField label="기관 ID"><input v-model="draft.org_id" :disabled="!draft.isNew" data-testid="org-id" /></FormField>
    <FormField label="이름"><input v-model="draft.name" data-testid="org-name" /></FormField>
    <label class="check"><input v-model="draft.enabled" type="checkbox" />사용</label>
    <FormField label="내부 대역 (한 줄에 하나, CIDR)"><textarea v-model="draft.cidrs" rows="5" data-testid="org-cidrs" /></FormField>
    <template #footer>
      <button @click="draft = null">취소</button>
      <button class="primary" :disabled="busy || !draft.org_id || !draft.name" @click="save">{{ busy ? '저장 중…' : '저장' }}</button>
    </template>
  </ModalDialog>
</template>
