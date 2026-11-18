<script setup lang="ts">
// MITRE ATT&CK (내부 사본): 탐지 커버리지 매트릭스, 기법 찾기, 버전 관리.
import { computed } from 'vue';
import { useRouter } from 'vue-router';
import TabBar from '../../components/TabBar.vue';
import MatrixTab from './MatrixTab.vue';
import SearchTab from './SearchTab.vue';
import VersionsTab from './VersionsTab.vue';

const props = defineProps<{ tab?: string }>();
const router = useRouter();
const active = computed(() => props.tab || 'matrix');
const tabs = [
  { key: 'matrix', label: '탐지 커버리지' },
  { key: 'search', label: '기법 찾기' },
  { key: 'versions', label: '버전 관리' },
];
</script>
<template>
  <div class="page">
    <div class="page-head">
      <h2>MITRE ATT&amp;CK</h2>
      <span class="muted small">폐쇄망 내부 사본 · 룰·순서도의 기법 매핑과 경보의 기법 정보에 쓴다</span>
    </div>
    <TabBar :model-value="active" :tabs="tabs" @update:model-value="(k) => router.push(`/attack/${k}`)" />
    <div class="tab-body">
      <MatrixTab v-if="active === 'matrix'" />
      <SearchTab v-else-if="active === 'search'" />
      <VersionsTab v-else-if="active === 'versions'" />
    </div>
  </div>
</template>
