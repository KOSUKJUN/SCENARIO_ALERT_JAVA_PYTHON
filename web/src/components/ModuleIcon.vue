<script setup lang="ts">
// 이벤트 탐지모듈 아이콘: 블록(정육면체). 시나리오에 끼워 쓰는 부품.
defineProps<{ size?: number }>();
</script>
<template>
  <svg class="mod-ico" :style="size ? { width: `${size}px`, height: `${size}px` } : undefined" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.3" stroke-linejoin="round" aria-hidden="true">
    <path d="M8 1.8 13.5 4.8v6.4L8 14.2 2.5 11.2V4.8z" /><path d="M2.5 4.8 8 7.8l5.5-3M8 7.8v6.4" />
  </svg>
</template>
