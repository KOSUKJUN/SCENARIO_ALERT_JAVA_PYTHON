<script setup lang="ts">
// 리스트 관리 (예외, 유해 IP/도메인, 시그니처 분류 매핑 등). 항목 추가·삭제와 CSV 일괄 등록.
import { computed, ref, watch } from 'vue';
import { api, enc } from '../../api';
import { has } from '../../auth';
import { loadMeta, useAsync } from '../../composables';
import CardBox from '../../components/CardBox.vue';
import EmptyBox from '../../components/EmptyBox.vue';
import ErrorBox from '../../components/ErrorBox.vue';
import FormField from '../../components/FormField.vue';
import LoadingBox from '../../components/LoadingBox.vue';
import ModalDialog from '../../components/ModalDialog.vue';
import NoticeBox from '../../components/NoticeBox.vue';
import type { ListDetail, ListMeta } from '../../types';
import { fmtTime } from '../../util';

const KINDS = ['ip', 'cidr', 'domain', 'string', 'signature_map'];
const canEdit = computed(() => has('author'));
const lists = useAsync(() => api.get<ListMeta[]>('/lists'));
const selected = ref<string>('');
const detail = useAsync<ListDetail | null>(
  () => (selected.value ? api.get<ListDetail>(`/lists/${enc(selected.value)}`) : Promise.resolve(null)),
  [selected],
);
watch(
  () => lists.data.value,
  (ls) => {
    if (!selected.value && ls?.length) selected.value = ls[0].list_id;
  },
);
const err = ref<unknown>(null);
const msg = ref<string | null>(null);
const busy = ref(false);
const newItem = ref({ value: '', mapped_value: '', note: '' });
const checked = ref<string[]>([]);
const csv = ref('');
const replace = ref(false);
const newList = ref<{ list_id: string; kind: string; description: string } | null>(null);
const isSigMap = computed(() => detail.data.value?.kind === 'signature_map');

async function act(fn: () => Promise<unknown>, ok: string, reloadLists = false) {
  busy.value = true;
  err.value = null;
  msg.value = null;
  try {
    await fn();
    msg.value = ok;
    detail.reload();
    if (reloadLists) lists.reload();
    void loadMeta(true); // 단일룰 양식의 리스트 목록도 새로
  } catch (e) {
    err.value = e;
  } finally {
    busy.value = false;
  }
}
const addItem = () =>
  act(async () => {
    await api.post(`/lists/${enc(selected.value)}/items`, {
      value: newItem.value.value,
      mapped_value: newItem.value.mapped_value || null,
      note: newItem.value.note || null,
    });
    newItem.value = { value: '', mapped_value: '', note: '' };
  }, '항목을 추가했습니다', true);
const deleteChecked = () =>
  act(async () => {
    await api.post(`/lists/${enc(selected.value)}/items:delete`, { values: checked.value });
    checked.value = [];
  }, '선택한 항목을 지웠습니다', true);
const bulk = () =>
  act(async () => {
    const r = await api.post<{ count: number }>(`/lists/${enc(selected.value)}/items:bulk`, { csv: csv.value, replace: replace.value });
    csv.value = '';
    msg.value = `${r.count}건 등록`;
  }, 'CSV 를 등록했습니다', true);
const createList = () =>
  act(async () => {
    const n = newList.value;
    if (!n) return;
    await api.post('/lists', { list_id: n.list_id, kind: n.kind, description: n.description || null });
    selected.value = n.list_id;
    newList.value = null;
  }, '리스트를 만들었습니다', true);
const deleteList = () => {
  if (!window.confirm(`${selected.value} 리스트를 지울까요? 룰이 참조 중이면 지워지지 않습니다.`)) return;
  void act(async () => {
    await api.del(`/lists/${enc(selected.value)}`);
    selected.value = '';
  }, '리스트를 지웠습니다', true);
};
function onCsvFile(e: Event) {
  const f = (e.target as HTMLInputElement).files?.[0];
  if (f) void f.text().then((t) => (csv.value = t));
}
</script>
<template>
  <div class="lists-layout">
    <CardBox title="리스트">
      <template #actions>
        <button v-if="canEdit" class="small" data-testid="list-new" @click="newList = { list_id: '', kind: 'ip', description: '' }">새 리스트</button>
      </template>
      <LoadingBox v-if="lists.loading.value && !lists.data.value" />
      <ErrorBox :error="lists.error.value" />
      <ul class="list-menu" data-testid="list-menu">
        <li v-for="l in lists.data.value ?? []" :key="l.list_id">
          <button :class="['link', { active: l.list_id === selected }]" :data-testid="`list-${l.list_id}`" @click="selected = l.list_id">
            {{ l.list_id }} <span class="muted small">[{{ l.kind }}] {{ l.item_count ?? 0 }}건</span>
          </button>
        </li>
      </ul>
    </CardBox>

    <CardBox :title="selected ? `리스트 ${selected}` : '리스트를 고르세요'">
      <template v-if="selected && canEdit" #actions><button class="small danger" @click="deleteList">리스트 삭제</button></template>
      <NoticeBox v-if="msg" kind="ok">{{ msg }}</NoticeBox>
      <ErrorBox :error="err || detail.error.value" closable @close="err = null" />
      <LoadingBox v-if="detail.loading.value && !detail.data.value" />
      <template v-if="detail.data.value">
        <p class="muted small">
          종류 {{ detail.data.value.kind }}{{ detail.data.value.description ? ` · ${detail.data.value.description}` : '' }}
          <template v-if="isSigMap"> · 값 형식 "데이터유형|시그니처명" (모든 유형은 "*|이름"), 매핑값 = 분류</template>
        </p>
        <div v-if="canEdit" class="form-row wrap">
          <input v-model="newItem.value" :placeholder="isSigMap ? '*|시그니처명' : '값'" data-testid="list-item-value" />
          <input v-if="isSigMap" v-model="newItem.mapped_value" placeholder="분류 (예: bruteforce)" data-testid="list-item-mapped" />
          <input v-model="newItem.note" placeholder="메모 (선택)" />
          <button class="primary small" :disabled="busy || !newItem.value" data-testid="list-item-add" @click="addItem">추가</button>
          <button class="small danger" :disabled="busy || !checked.length" @click="deleteChecked">선택 삭제 ({{ checked.length }})</button>
        </div>
        <div class="table-wrap">
          <table v-if="detail.data.value.items.length" class="table compact" data-testid="list-items">
            <thead><tr><th v-if="canEdit" /><th>값</th><th v-if="isSigMap">분류</th><th>만료</th><th>메모</th></tr></thead>
            <tbody>
              <tr v-for="it in detail.data.value.items" :key="it.value">
                <td v-if="canEdit"><input v-model="checked" type="checkbox" :value="it.value" /></td>
                <td>{{ it.value }}</td>
                <td v-if="isSigMap">{{ it.mapped_value }}</td>
                <td>{{ fmtTime(it.expires_at) }}</td>
                <td class="small">{{ it.note }}</td>
              </tr>
            </tbody>
          </table>
          <EmptyBox v-else>항목이 없습니다</EmptyBox>
        </div>
        <details v-if="canEdit" class="bulk">
          <summary>CSV 일괄 등록</summary>
          <p class="muted small">열: value[,mapped_value[,expires_at[,note]]]. 첫 줄이 value 로 시작하면 머리글로 봅니다.</p>
          <input type="file" accept=".csv,text/csv,text/plain" @change="onCsvFile" />
          <textarea v-model="csv" rows="5" class="code" placeholder="value,mapped_value,expires_at,note" data-testid="list-csv" />
          <label class="check"><input v-model="replace" type="checkbox" />기존 항목을 모두 바꾸기</label>
          <button class="small" :disabled="busy || !csv.trim()" data-testid="list-csv-submit" @click="bulk">등록</button>
        </details>
      </template>
    </CardBox>
  </div>

  <ModalDialog v-if="newList" title="새 리스트" @close="newList = null">
    <ErrorBox :error="err" />
    <FormField label="리스트 ID" hint="소문자, 숫자, _, - (1~64자)"><input v-model="newList.list_id" data-testid="new-list-id" /></FormField>
    <FormField label="종류">
      <select v-model="newList.kind"><option v-for="k in KINDS" :key="k" :value="k">{{ k }}</option></select>
    </FormField>
    <FormField label="설명"><input v-model="newList.description" /></FormField>
    <template #footer>
      <button @click="newList = null">취소</button>
      <button class="primary" :disabled="busy || !newList.list_id" @click="createList">만들기</button>
    </template>
  </ModalDialog>
</template>
