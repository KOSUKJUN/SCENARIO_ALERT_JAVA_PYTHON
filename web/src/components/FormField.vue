<script setup lang="ts">
import { computed } from 'vue';
const props = defineProps<{ label: string; hint?: string; error?: string | string[] | null }>();
const errors = computed(() => (props.error ? (Array.isArray(props.error) ? props.error : [props.error]) : []));
</script>
<template>
  <label :class="['field', { 'has-error': errors.length }]">
    <span class="field-label">{{ label }}</span>
    <slot />
    <small v-if="hint" class="hint">{{ hint }}</small>
    <small v-for="(e, i) in errors" :key="i" class="field-error">{{ e }}</small>
  </label>
</template>
