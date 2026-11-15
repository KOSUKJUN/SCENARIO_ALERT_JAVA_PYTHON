<script setup lang="ts">
import { STATUS_LABEL } from '../util';
import UiBadge from './UiBadge.vue';
defineProps<{ status?: string | null }>();
</script>
<template>
  <UiBadge v-if="status" :kind="`st-${status}`">{{ STATUS_LABEL[status] ?? status }}</UiBadge>
</template>
