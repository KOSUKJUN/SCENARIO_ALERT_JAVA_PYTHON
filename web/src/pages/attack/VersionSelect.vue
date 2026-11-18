<script setup lang="ts">
// ATT&CK 버전 고르기 ("" = 활성 버전). 값은 "domain|version".
import { api } from '../../api';
import { useAsync } from '../../composables';
import type { AttackVersion } from '../../types';

defineProps<{ modelValue: string }>();
const emit = defineEmits<{ 'update:modelValue': [v: string] }>();
const vs = useAsync(() => api.get<{ versions: AttackVersion[] }>('/attack/versions'));
</script>
<template>
  <select :value="modelValue" data-testid="attack-version-select" @change="emit('update:modelValue', ($event.target as HTMLSelectElement).value)">
    <option value="">활성 버전</option>
    <option v-for="v in vs.data.value?.versions ?? []" :key="`${v.domain}|${v.version}`" :value="`${v.domain}|${v.version}`">
      {{ v.name }} {{ v.version }}{{ v.is_active ? ' (활성)' : '' }}
    </option>
  </select>
</template>
