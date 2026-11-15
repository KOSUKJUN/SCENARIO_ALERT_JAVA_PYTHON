<script setup lang="ts">
defineProps<{ kind?: string; title?: string }>();
</script>
<template>
  <span :class="['badge', kind ? `badge-${kind}` : '']" :title="title"><slot /></span>
</template>
