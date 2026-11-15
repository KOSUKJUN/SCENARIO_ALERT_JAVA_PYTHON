<script setup lang="ts">
defineProps<{ tabs: { key: string; label: string; hidden?: boolean }[]; modelValue: string }>();
defineEmits<{ 'update:modelValue': [key: string] }>();
</script>
<template>
  <div class="tabs" role="tablist">
    <template v-for="t in tabs" :key="t.key">
      <button
        v-if="!t.hidden"
        role="tab"
        :data-testid="`tab-${t.key}`"
        :class="['tab', { active: t.key === modelValue }]"
        @click="$emit('update:modelValue', t.key)"
      >
        {{ t.label }}
      </button>
    </template>
  </div>
</template>
