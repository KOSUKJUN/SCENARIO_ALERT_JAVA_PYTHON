<script setup lang="ts">
// 기관별 자산과 태그. 태그는 순서도 자산 확인 노드(asset)와 단일룰 has_tag 조건에 쓰인다.
import { computed, ref, watch } from 'vue';
import { api, enc } from '../../api';
import { has } from '../../auth';
import { loadMeta, useAsync } from '../../composables';
import CardBox from '../../components/CardBox.vue';
import EmptyBox from '../../components/EmptyBox.vue';
import ErrorBox from '../../components/ErrorBox.vue';
import FormField from '../../components/FormField.vue';
import ListInput from '../../components/ListInput.vue';
import LoadingBox from '../../components/LoadingBox.vue';
import ModalDialog from '../../components/ModalDialog.vue';
import NoticeBox from '../../components/NoticeBox.vue';
import UiBadge from '../../components/UiBadge.vue';
import type { Asset, Org } from '../../types';
import { truthy } from '../../util';

interface Draft {
  ip: string;
  purpose: string;
  os: string;
  holds_sensitive: boolean;
  tags: string[];
  isNew: boolean;
}
const canEdit = computed(() => has('author'));
const orgs = useAsync(() => api.get<Org[]>('/orgs'));
const org = ref('');
const q = ref('');
watch(
  () => orgs.data.value,
  (os) => {
    if (!org.value && os?.length) org.value = os[0].org_id;
  },
);
const assets = useAsync<Asset[]>(
  () => (org.value ? api.get<Asset[]>(`/orgs/${enc(org.value)}/assets`, { q: q.value || undefined }) : Promise.resolve([])),
  [org, q],
);
const draft = ref<Draft | null>(null);
const csv = ref('');
const err = ref<unknown>(null);
const msg = ref<string | null>(null);
const busy = ref(false);

function edit(a?: Asset) {
  err.value = null;
  draft.value = a
    ? { ip: a.ip, purpose: a.purpose ?? '', os: a.os ?? '', holds_sensitive: truthy(a.holds_sensitive), tags: [...a.tags], isNew: false }
    : { ip: '', purpose: '', os: '', holds_sensitive: false, tags: [], isNew: true };
}
async function act(fn: () => Promise<unknown>, ok: string) {
  busy.value = true;
  err.value = null;
  msg.value = null;
  try {
    await fn();
    msg.value = ok;
    assets.reload();
    void loadMeta(true);
  } catch (e) {
    err.value = e;
  } finally {
    busy.value = false;
  }
}
const save = () =>
  act(async () => {
    const d = draft.value;
    if (!d) return;
    await api.put(`/orgs/${enc(org.value)}/assets/${enc(d.ip)}`, {
      purpose: d.purpose || null,
      os: d.os || null,
      holds_sensitive: d.holds_sensitive,
      source: 'manual',
      tags: d.tags,
    });
    draft.value = null;
  }, '자산을 저장했습니다');
const remove = (a: Asset) => {
  if (window.confirm(`${a.ip} 자산을 지울까요?`)) void act(() => api.del(`/orgs/${enc(org.value)}/assets/${enc(a.ip)}`), '자산을 지웠습니다');
};
const importCsv = () =>
  act(async () => {
    const r = await api.post<{ count: number }>(`/orgs/${enc(org.value)}/assets:import`, { csv: csv.value });
    csv.value = '';
    msg.value = `${r.count}건 가져옴`;
  }, 'CSV 를 가져왔습니다');
function onCsvFile(e: Event) {
  const f = (e.target as HTMLInputElement).files?.[0];
  if (f) void f.text().then((t) => (csv.value = t));
}
</script>
<template>
  <CardBox title="자산·태그">
    <template #actions>
      <select v-model="org" data-testid="asset-org">
        <option v-for="o in orgs.data.value ?? []" :key="o.org_id" :value="o.org_id">{{ o.org_id }} {{ o.name }}</option>
      </select>
      <input v-model.lazy="q" placeholder="IP·용도 검색" />
      <button v-if="canEdit" class="primary small" data-testid="asset-new" @click="edit()">자산 추가</button>
    </template>
    <NoticeBox v-if="msg" kind="ok">{{ msg }}</NoticeBox>
    <ErrorBox :error="err || assets.error.value" closable @close="err = null" />
    <LoadingBox v-if="assets.loading.value && !assets.data.value" />
    <div v-if="assets.data.value" class="table-wrap">
      <table v-if="assets.data.value.length" class="table compact" data-testid="asset-list">
        <thead><tr><th>IP</th><th>용도</th><th>OS</th><th>민감정보</th><th>태그</th><th>출처</th><th /></tr></thead>
        <tbody>
          <tr v-for="a in assets.data.value" :key="a.ip">
            <td>{{ a.ip }}</td>
            <td>{{ a.purpose }}</td>
            <td>{{ a.os }}</td>
            <td>{{ truthy(a.holds_sensitive) ? '예' : '' }}</td>
            <td><UiBadge v-for="t in a.tags" :key="t">{{ t }}</UiBadge></td>
            <td class="small">{{ a.source }}</td>
            <td>
              <template v-if="canEdit">
                <button class="small" @click="edit(a)">수정</button>
                <button class="small danger" @click="remove(a)">삭제</button>
              </template>
            </td>
          </tr>
        </tbody>
      </table>
      <EmptyBox v-else>자산이 없습니다</EmptyBox>
    </div>
    <details v-if="canEdit" class="bulk">
      <summary>CSV 가져오기</summary>
      <p class="muted small">열: ip,purpose,os,holds_sensitive,tags (tags 는 ; 로 구분). 첫 줄이 ip 로 시작하면 머리글로 봅니다.</p>
      <input type="file" accept=".csv,text/csv,text/plain" @change="onCsvFile" />
      <textarea v-model="csv" rows="5" class="code" placeholder="ip,purpose,os,holds_sensitive,tags" />
      <button class="small" :disabled="busy || !csv.trim() || !org" @click="importCsv">가져오기</button>
    </details>
  </CardBox>
  <ModalDialog v-if="draft" :title="draft.isNew ? '자산 추가' : `자산 ${draft.ip}`" @close="draft = null">
    <ErrorBox :error="err" />
    <FormField label="IP"><input v-model="draft.ip" :disabled="!draft.isNew" data-testid="asset-ip" /></FormField>
    <FormField label="용도"><input v-model="draft.purpose" /></FormField>
    <FormField label="OS"><input v-model="draft.os" /></FormField>
    <label class="check"><input v-model="draft.holds_sensitive" type="checkbox" />민감정보 보유</label>
    <FormField label="태그 (쉼표 구분, 소문자)"><ListInput v-model="draft.tags" test-id="asset-tags" /></FormField>
    <template #footer>
      <button @click="draft = null">취소</button>
      <button class="primary" :disabled="busy || !draft.ip" @click="save">저장</button>
    </template>
  </ModalDialog>
</template>
