<script setup lang="ts">
// 경보에 저장된 ATT&CK 기법(스냅샷) 표시. 칩을 누르면 현재 활성 버전의 상세를 연다.
import { ref } from 'vue';
import type { AttackRef } from '../types';
import AttackTechniqueModal from './AttackTechniqueModal.vue';

defineProps<{ items?: AttackRef[] | null; compact?: boolean }>();
const detail = ref<string | null>(null);
</script>
<template>
  <span class="chips attack-chips">
    <a
      v-for="t in items ?? []"
      :key="t.id"
      href="#"
      class="chip"
      :title="t.tactics.map((x) => `${x.id} ${x.name}`).join(', ')"
      :data-testid="`alert-attack-${t.id}`"
      @click.prevent="detail = t.id"
    >
      {{ t.id }}<template v-if="!compact && t.name">{{ ' ' + t.name }}</template>
      <span v-if="!compact && t.tactics.length" class="muted small"> · {{ t.tactics.map((x) => x.name).join(', ') }}</span>
    </a>
    <span v-if="!items?.length" class="muted small">-</span>
    <AttackTechniqueModal v-if="detail" :id="detail" @close="detail = null" />
  </span>
</template>
<style scoped>
.attack-chips { display: inline-flex; margin-top: 0; }
</style>
