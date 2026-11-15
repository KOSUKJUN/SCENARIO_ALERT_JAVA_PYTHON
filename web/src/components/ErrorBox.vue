<script setup lang="ts">
import { computed } from 'vue';
import { ApiError, errorText } from '../api';
const props = defineProps<{ error: unknown; closable?: boolean }>();
defineEmits<{ close: [] }>();
const text = computed(() => (props.error ? errorText(props.error) : ''));
const warnings = computed(() => (props.error instanceof ApiError ? props.error.warnings : []));
</script>
<template>
  <div v-if="error" class="alert-box error" role="alert" data-testid="error-box">
    <button v-if="closable" class="close" aria-label="닫기" @click="$emit('close')">×</button>
    <pre>{{ text }}</pre>
    <ul v-if="warnings.length" class="warn-list">
      <li v-for="(w, i) in warnings" :key="i">경고 {{ w.path ?? w.id ?? '' }}: {{ w.message }}</li>
    </ul>
  </div>
</template>
