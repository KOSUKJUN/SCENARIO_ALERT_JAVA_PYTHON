<script setup lang="ts">
// 단순 세로 막대 그래프 (시간대·일별 분포).
import { computed } from 'vue';
const props = withDefaults(defineProps<{ data: { label: string; value: number }[]; height?: number; unit?: string }>(), {
  height: 120,
  unit: '건',
});
const max = computed(() => Math.max(1, ...props.data.map((d) => d.value)));
const every = computed(() => Math.max(1, Math.ceil(props.data.length / 12)));
</script>
<template>
  <div v-if="!data.length" class="empty">분포 데이터가 없습니다</div>
  <div v-else class="barchart" :style="{ height: `${height + 34}px` }">
    <div class="barchart-bars" :style="{ height: `${height}px` }">
      <div v-for="(d, i) in data" :key="i" class="bar-col" :title="`${d.label}: ${d.value.toLocaleString('ko-KR')}${unit}`">
        <div class="bar" :style="{ height: `${(d.value / max) * 100}%` }" />
      </div>
    </div>
    <div class="barchart-axis">
      <div v-for="(d, i) in data" :key="i" class="bar-label">{{ i % every === 0 ? d.label : '' }}</div>
    </div>
    <div class="barchart-max">최대 {{ max.toLocaleString('ko-KR') }}{{ unit }}</div>
  </div>
</template>
