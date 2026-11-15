<script setup lang="ts">
import { onMounted, ref } from 'vue';
import ModalDialog from './ModalDialog.vue';
withDefaults(defineProps<{ title?: string; busy?: boolean }>(), { title: '저장' });
const emit = defineEmits<{ submit: [note: string]; close: [] }>();
const note = ref('');
const input = ref<HTMLInputElement | null>(null);
onMounted(() => input.value?.focus());
</script>
<template>
  <ModalDialog :title="title" @close="emit('close')">
    <label class="field">
      <span class="field-label">변경 메모 (선택)</span>
      <input
        ref="input"
        v-model="note"
        data-testid="change-note"
        placeholder="무엇을 바꿨는지 적어 두면 버전 이력에서 보입니다"
        @keydown.enter="emit('submit', note)"
      />
    </label>
    <template #footer>
      <button @click="emit('close')">취소</button>
      <button class="primary" :disabled="busy" data-testid="confirm-save" @click="emit('submit', note)">
        {{ busy ? '저장 중…' : '저장' }}
      </button>
    </template>
  </ModalDialog>
</template>
