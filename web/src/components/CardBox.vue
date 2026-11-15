<script setup lang="ts">
defineProps<{ title?: string }>();
</script>
<template>
  <section class="card">
    <div v-if="title || $slots.actions" class="card-head">
      <h3 v-if="title">{{ title }}</h3>
      <div v-if="$slots.actions" class="card-actions"><slot name="actions" /></div>
    </div>
    <div class="card-body"><slot /></div>
  </section>
</template>
