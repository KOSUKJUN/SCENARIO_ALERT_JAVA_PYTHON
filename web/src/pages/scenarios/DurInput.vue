<script setup lang="ts">
import { fmtDuration, isDuration } from '../../util';
defineProps<{ modelValue: string; testId?: string; disabled?: boolean }>();
const emit = defineEmits<{ 'update:modelValue': [v: string] }>();
</script>
<template>
  <input
    list="scn-dur"
    :value="modelValue"
    :disabled="disabled"
    :data-testid="testId"
    placeholder="예: 30m, 1h, 1d"
    @input="emit('update:modelValue', ($event.target as HTMLInputElement).value.trim())"
  />
  <small v-if="modelValue && !isDuration(modelValue)" class="field-error">시간 형식이 아닙니다 (예: 30s, 10m, 1h, 1d)</small>
  <small v-else-if="modelValue" class="hint">{{ fmtDuration(modelValue) }}</small>
</template>
