<script setup lang="ts">
// MITRE D3FEND (내부 사본): 대응 기법 매트릭스, 이벤트 탐지모듈·시나리오의 대응방책 연계 현황, 버전 관리.
import { computed } from 'vue';
import { useRouter } from 'vue-router';
import TabBar from '../../components/TabBar.vue';
import LinksTab from './LinksTab.vue';
import MatrixTab from './MatrixTab.vue';
import VersionsTab from './VersionsTab.vue';

const props = defineProps<{ tab?: string }>();
const router = useRouter();
const active = computed(() => props.tab || 'matrix');
const tabs = [
  { key: 'matrix', label: '대응 기법' },
  { key: 'links', label: '대응방책 연계' },
  { key: 'versions', label: '버전 관리' },
];
</script>
<template>
  <div class="page">
    <div class="page-head">
      <h2>MITRE D3FEND</h2>
      <span class="muted small">폐쇄망 내부 사본 · 이벤트 탐지모듈·시나리오의 지정 대응방책과 경보의 권고 대응방책(ATT&amp;CK 기법 → 방어 기법)에 쓴다</span>
    </div>
    <TabBar :model-value="active" :tabs="tabs" @update:model-value="(k) => router.push(`/d3fend/${k}`)" />
    <div class="tab-body">
      <MatrixTab v-if="active === 'matrix'" />
      <LinksTab v-else-if="active === 'links'" />
      <VersionsTab v-else-if="active === 'versions'" />
    </div>
  </div>
</template>
