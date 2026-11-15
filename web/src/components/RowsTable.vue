<script setup lang="ts">
// 열 이름을 자동으로 잡는 단순 표 (샘플 행, 이벤트 등).
import { computed } from 'vue';
import type { Row } from '../types';
import { cellText } from '../util';
import EmptyBox from './EmptyBox.vue';
const props = withDefaults(defineProps<{ rows: Row[]; columns?: string[]; max?: number }>(), { max: 200 });
const cols = computed(() => props.columns ?? Array.from(new Set(props.rows.slice(0, 50).flatMap((r) => Object.keys(r)))));
const shown = computed(() => props.rows.slice(0, props.max).map((r) => cols.value.map((c) => cellText(r[c]))));
</script>
<template>
  <EmptyBox v-if="!rows.length" />
  <div v-else class="table-wrap">
    <table class="table compact">
      <thead>
        <tr><th v-for="c in cols" :key="c">{{ c }}</th></tr>
      </thead>
      <tbody>
        <tr v-for="(r, i) in shown" :key="i">
          <td v-for="(t, j) in r" :key="j" :title="t.length > 60 ? t : undefined">{{ t.length > 120 ? `${t.slice(0, 120)}…` : t }}</td>
        </tr>
      </tbody>
    </table>
    <small v-if="rows.length > max" class="hint">앞 {{ max }}건만 표시 (전체 {{ rows.length }}건)</small>
  </div>
</template>
