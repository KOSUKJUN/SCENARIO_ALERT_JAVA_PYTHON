<script setup lang="ts">
import type { FormIssue } from './filter';
defineProps<{ items: FormIssue[] }>();
</script>
<template>
  <ul v-if="items.length" class="issue-lines">
    <li v-for="(i, k) in items" :key="k" :class="{ warn: i.level === 'warn' }">{{ i.message }}</li>
  </ul>
</template>
