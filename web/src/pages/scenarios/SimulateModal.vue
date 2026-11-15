<script setup lang="ts">
import { ref, watch } from 'vue';
import { api } from '../../api';
import { useAsync } from '../../composables';
import ErrorBox from '../../components/ErrorBox.vue';
import FormField from '../../components/FormField.vue';
import ModalDialog from '../../components/ModalDialog.vue';
import type { Org } from '../../types';
import { kstInput, localInputToIso } from '../../util';

interface SimParams {
  org_id: string;
  entity: string;
  time_from: string;
  time_to: string;
}
defineProps<{ busy: boolean }>();
const emit = defineEmits<{ close: []; run: [p: SimParams] }>();
const orgs = useAsync(() => api.get<Org[]>('/orgs'));
const org = ref('');
const entity = ref('');
const from = ref(kstInput(-24));
const to = ref(kstInput(0));
watch(
  () => orgs.data.value,
  (os) => {
    if (!org.value && os?.length) org.value = os[0].org_id;
  },
);
function run() {
  emit('run', { org_id: org.value, entity: entity.value.trim(), time_from: localInputToIso(from.value), time_to: localInputToIso(to.value) });
}
</script>
<template>
  <ModalDialog title="시뮬레이션" @close="emit('close')">
    <p class="muted small">편집 중인 순서도를 지정한 대상·기간의 실제 히트(rule_hits)에 대입합니다. 저장하지 않습니다.</p>
    <ErrorBox :error="orgs.error.value" />
    <FormField label="기관">
      <select v-model="org" data-testid="sim-org">
        <option v-for="o in orgs.data.value ?? []" :key="o.org_id" :value="o.org_id">{{ o.org_id }} {{ o.name }}</option>
      </select>
    </FormField>
    <FormField label="대상 (IP)">
      <input v-model="entity" placeholder="10.1.2.3" data-testid="sim-entity" />
    </FormField>
    <div class="form-grid">
      <FormField label="시작 (KST)"><input v-model="from" type="datetime-local" data-testid="sim-from" /></FormField>
      <FormField label="끝 (KST)"><input v-model="to" type="datetime-local" data-testid="sim-to" /></FormField>
    </div>
    <template #footer>
      <button @click="emit('close')">취소</button>
      <button class="primary" :disabled="busy || !org || !entity.trim()" data-testid="sim-run" @click="run">{{ busy ? '실행 중…' : '실행' }}</button>
    </template>
  </ModalDialog>
</template>
