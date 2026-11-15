<script setup lang="ts">
import { ref } from 'vue';
import { api, enc } from '../../api';
import { useAsync } from '../../composables';
import ErrorBox from '../../components/ErrorBox.vue';
import LoadingBox from '../../components/LoadingBox.vue';
import RowsTable from '../../components/RowsTable.vue';
import type { Row } from '../../types';

const props = defineProps<{ ruleId: string }>();
const hours = ref(24);
const org = ref('');
const hs = useAsync(
  () => api.get<Row[]>(`/single-rules/${enc(props.ruleId)}/hits`, { hours: hours.value, org_id: org.value || undefined }),
  [() => props.ruleId, hours, org],
);
</script>
<template>
  <div>
    <div class="form-row">
      <label class="inline">
        기간
        <select v-model.number="hours">
          <option :value="1">1시간</option>
          <option :value="24">24시간</option>
          <option :value="72">3일</option>
          <option :value="168">7일</option>
          <option :value="720">30일</option>
        </select>
      </label>
      <label class="inline">기관 <input v-model.lazy="org" placeholder="ORG001" /></label>
      <button @click="hs.reload">새로고침</button>
    </div>
    <LoadingBox v-if="hs.loading.value" />
    <ErrorBox :error="hs.error.value" />
    <RowsTable v-if="hs.data.value" :rows="hs.data.value" />
  </div>
</template>
