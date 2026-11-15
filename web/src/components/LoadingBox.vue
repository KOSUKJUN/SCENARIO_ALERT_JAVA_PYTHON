<script setup lang="ts">
withDefaults(defineProps<{ text?: string }>(), { text: '불러오는 중…' });
</script>
<template>
  <div class="loading">{{ text }}</div>
</template>
