<script setup lang="ts">
// 시나리오 아이콘: 갈라지는 순서도 (블록 하나에서 두 갈래).
defineProps<{ size?: number }>();
</script>
<template>
  <svg class="scn-ico" :style="size ? { width: `${size}px`, height: `${size}px` } : undefined" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.3" stroke-linejoin="round" stroke-linecap="round" aria-hidden="true">
    <rect x="1.2" y="6" width="4.3" height="4" rx="1" /><rect x="10.5" y="1.8" width="4.3" height="4" rx="1" /><rect x="10.5" y="10.2" width="4.3" height="4" rx="1" />
    <path d="M5.5 8H8M8 3.8V12.2M8 3.8h2.5M8 12.2h2.5" />
  </svg>
</template>
