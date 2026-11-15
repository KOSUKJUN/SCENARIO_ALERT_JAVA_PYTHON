<script setup lang="ts">
withDefaults(defineProps<{ kind?: 'info' | 'ok' | 'warn' | 'error' }>(), { kind: 'info' });
</script>
<template>
  <div :class="['alert-box', kind]" data-testid="notice"><slot /></div>
</template>
