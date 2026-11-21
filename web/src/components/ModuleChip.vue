<script setup lang="ts">
// 이벤트 탐지모듈 칩: 블록 아이콘이 붙은 부품 모양. kind='scenario' 이면 시나리오 아이콘 칩.
import ModuleIcon from './ModuleIcon.vue';
import ScenarioIcon from './ScenarioIcon.vue';

defineProps<{ to?: string; name: string; title?: string; testId?: string; kind?: 'module' | 'scenario' }>();
</script>
<template>
  <component :is="to ? 'RouterLink' : 'span'" :to="to" :class="['mod-chip', { scn: kind === 'scenario' }]" :title="title" :data-testid="testId">
    <ScenarioIcon v-if="kind === 'scenario'" />
    <ModuleIcon v-else />
    <span>{{ name }}</span>
  </component>
</template>
