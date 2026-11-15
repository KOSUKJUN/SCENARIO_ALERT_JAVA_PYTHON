<script setup lang="ts">
import { api, enc } from '../../api';
import { useAsync } from '../../composables';
import EmptyBox from '../../components/EmptyBox.vue';
import ErrorBox from '../../components/ErrorBox.vue';
import LoadingBox from '../../components/LoadingBox.vue';
import type { RuleDefinition, RuleVersion } from '../../types';
import { fmtTime } from '../../util';

const props = defineProps<{ ruleId: string }>();
const emit = defineEmits<{ load: [d: RuleDefinition] }>();
const vs = useAsync(() => api.get<RuleVersion[]>(`/single-rules/${enc(props.ruleId)}/versions`), [() => props.ruleId]);
</script>
<template>
  <LoadingBox v-if="vs.loading.value" />
  <ErrorBox v-else-if="vs.error.value" :error="vs.error.value" />
  <EmptyBox v-else-if="!vs.data.value?.length">버전이 없습니다</EmptyBox>
  <table v-else class="table compact" data-testid="rule-versions">
    <thead><tr><th>버전</th><th>작성</th><th>시각</th><th>변경 메모</th><th>정의</th><th /></tr></thead>
    <tbody>
      <tr v-for="v in vs.data.value" :key="v.version">
        <td>v{{ v.version }}</td>
        <td>{{ v.created_by }}</td>
        <td>{{ fmtTime(v.created_at) }}</td>
        <td>{{ v.change_note ?? '-' }}</td>
        <td>
          <details>
            <summary>JSON</summary>
            <pre class="code small">{{ JSON.stringify(v.definition, null, 2) }}</pre>
          </details>
        </td>
        <td><button class="small" @click="emit('load', v.definition)">편집기로 불러오기</button></td>
      </tr>
    </tbody>
  </table>
</template>
