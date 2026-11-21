<script setup lang="ts">
import { computed, ref } from 'vue';
import type { RuleSummary } from '../../types';

const props = defineProps<{ rules: RuleSummary[]; selected: string[]; multi: boolean; disabled?: boolean }>();
const emit = defineEmits<{ change: [v: string[]] }>();
const q = ref('');
const shown = computed(() => {
  const s = q.value.trim().toLowerCase();
  return props.rules.filter((r) => !s || r.rule_id.toLowerCase().includes(s) || r.name.toLowerCase().includes(s));
});
const unknown = computed(() => props.selected.filter((s) => !props.rules.some((r) => r.rule_id === s)));
function pick(id: string, checked: boolean) {
  if (!props.multi) emit('change', [id]);
  else emit('change', checked ? [...props.selected, id] : props.selected.filter((x) => x !== id));
}
</script>
<template>
  <div class="rule-picker">
    <input v-model="q" placeholder="이벤트 탐지모듈 검색" />
    <div class="rule-picker-list" data-testid="prop-rule-picker">
      <label v-for="u in unknown" :key="u" class="check warn-text">
        <input :type="multi ? 'checkbox' : 'radio'" checked :disabled="disabled" @change="emit('change', selected.filter((x) => x !== u))" />
        {{ u }} (목록에 없음)
      </label>
      <label v-for="r in shown" :key="r.rule_id" class="check" :title="r.name">
        <input
          :type="multi ? 'checkbox' : 'radio'"
          name="rule-picker"
          :disabled="disabled"
          :checked="selected.includes(r.rule_id)"
          :data-testid="`prop-rule-${r.rule_id}`"
          @change="pick(r.rule_id, ($event.target as HTMLInputElement).checked)"
        />
        <span>{{ r.rule_id }} <span class="muted small">{{ r.name }}</span></span>
      </label>
      <span v-if="!shown.length" class="muted small">해당 이벤트 탐지모듈이 없습니다</span>
    </div>
  </div>
</template>
