<script setup lang="ts">
import { ref } from 'vue';
import { api, enc } from '../../api';
import { useAsync } from '../../composables';
import CardBox from '../../components/CardBox.vue';
import ErrorBox from '../../components/ErrorBox.vue';
import FormField from '../../components/FormField.vue';
import ModalDialog from '../../components/ModalDialog.vue';
import UiBadge from '../../components/UiBadge.vue';
import type { Role, UserRow } from '../../types';
import { ROLE_LABEL, fmtTime, truthy } from '../../util';

const ROLES: Role[] = ['viewer', 'analyst', 'author', 'admin'];
const users = useAsync(() => api.get<UserRow[]>('/users'));
const draft = ref<{ username: string; password: string; role: Role; enabled: boolean; isNew: boolean } | null>(null);
const err = ref<unknown>(null);

function edit(u?: UserRow) {
  err.value = null;
  draft.value = u
    ? { username: u.username, password: '', role: u.role, enabled: truthy(u.enabled), isNew: false }
    : { username: '', password: '', role: 'viewer', enabled: true, isNew: true };
}
async function save() {
  const d = draft.value;
  if (!d) return;
  err.value = null;
  try {
    await api.put(`/users/${enc(d.username)}`, { username: d.username, password: d.password || null, role: d.role, enabled: d.enabled });
    draft.value = null;
    users.reload();
  } catch (e) {
    err.value = e;
  }
}
</script>
<template>
  <CardBox title="사용자">
    <template #actions><button class="primary small" @click="edit()">사용자 추가</button></template>
    <ErrorBox :error="users.error.value" />
    <table v-if="users.data.value" class="table compact">
      <thead><tr><th>아이디</th><th>역할</th><th>사용</th><th>만든 시각</th><th /></tr></thead>
      <tbody>
        <tr v-for="u in users.data.value" :key="u.username">
          <td>{{ u.username }}</td>
          <td>{{ ROLE_LABEL[u.role] ?? u.role }}</td>
          <td><UiBadge :kind="truthy(u.enabled) ? 'ok' : undefined">{{ truthy(u.enabled) ? '사용' : '중지' }}</UiBadge></td>
          <td>{{ fmtTime(u.created_at) }}</td>
          <td><button class="small" @click="edit(u)">수정</button></td>
        </tr>
      </tbody>
    </table>
  </CardBox>
  <ModalDialog v-if="draft" :title="draft.isNew ? '사용자 추가' : `사용자 ${draft.username}`" @close="draft = null">
    <ErrorBox :error="err" />
    <FormField label="아이디"><input v-model="draft.username" :disabled="!draft.isNew" /></FormField>
    <FormField label="비밀번호" :hint="draft.isNew ? undefined : '비우면 그대로 둡니다'"><input v-model="draft.password" type="password" autocomplete="new-password" /></FormField>
    <FormField label="역할">
      <select v-model="draft.role"><option v-for="r in ROLES" :key="r" :value="r">{{ ROLE_LABEL[r] }} ({{ r }})</option></select>
    </FormField>
    <label class="check"><input v-model="draft.enabled" type="checkbox" />사용</label>
    <template #footer>
      <button @click="draft = null">취소</button>
      <button class="primary" :disabled="!draft.username || (draft.isNew && !draft.password)" @click="save">저장</button>
    </template>
  </ModalDialog>
</template>
