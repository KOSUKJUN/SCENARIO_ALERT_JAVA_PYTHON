<script setup lang="ts">
import { SEVERITY_LABEL } from '../util';
import UiBadge from './UiBadge.vue';
defineProps<{ severity?: string | null }>();
</script>
<template>
  <UiBadge v-if="severity" :kind="`sev-${severity}`">{{ SEVERITY_LABEL[severity] ?? severity }}</UiBadge>
</template>
