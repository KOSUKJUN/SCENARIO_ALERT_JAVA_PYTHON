<script setup lang="ts">
// 문자열 목록 입력 (쉼표 구분). 입력 중인 글자는 그대로 두고 바뀐 목록만 올린다.
import { ref, watch } from 'vue';
import { splitList } from '../util';
const props = defineProps<{ modelValue: string[]; placeholder?: string; list?: string; testId?: string; disabled?: boolean }>();
const emit = defineEmits<{ 'update:modelValue': [v: string[]] }>();
const text = ref(props.modelValue.join(', '));
watch(
  () => props.modelValue.join('\u0000'),
  () => {
    if (splitList(text.value).join('\u0000') !== props.modelValue.join('\u0000')) text.value = props.modelValue.join(', ');
  },
);
function onInput(e: Event) {
  text.value = (e.target as HTMLInputElement).value;
  emit('update:modelValue', splitList(text.value));
}
</script>
<template>
  <input :value="text" :list="list" :placeholder="placeholder" :data-testid="testId" :disabled="disabled" @input="onInput" />
</template>
