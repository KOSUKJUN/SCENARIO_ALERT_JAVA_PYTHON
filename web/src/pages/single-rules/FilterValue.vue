<script setup lang="ts">
// 조건 한 줄의 값 입력. 필드 유형과 연산자에 따라 모양이 달라진다.
import { computed } from 'vue';
import ListInput from '../../components/ListInput.vue';
import type { FieldMeta, Json, MetaFields } from '../../types';
import { LIST_ID_OPS, SCALAR_LIST_OPS } from './filter';

const props = defineProps<{ f: FieldMeta; op: string; value: Json | undefined; meta: MetaFields; path: string; readOnly?: boolean }>();
const emit = defineEmits<{ change: [v: Json] }>();
const tid = computed(() => `filter-value-${props.path}`);
const str = computed(() => (typeof props.value === 'string' ? props.value : props.value === undefined || props.value === null ? '' : String(props.value)));
const arr = computed(() => (Array.isArray(props.value) ? props.value.map((x) => String(x)) : []));
const kind = computed(() => {
  const { f, op } = props;
  if (op === 'exists') return 'none';
  if (SCALAR_LIST_OPS.has(op)) return 'list';
  if (LIST_ID_OPS.has(op)) return 'listid';
  if (op === 'has_tag') return 'tag';
  if (f.type === 'bool' || f.type === 'peer') return 'bool';
  if (f.type === 'int' && op !== 'regex') return 'int';
  if (f.enum.length && (op === 'eq' || op === 'ne')) return 'enum';
  return 'text';
});
function onList(vs: string[]) {
  emit('change', props.f.type === 'int' ? vs.map((x) => (/^\d+$/.test(x) ? Number(x) : x)) : vs);
}
function onInt(e: Event) {
  const t = (e.target as HTMLInputElement).value.trim();
  emit('change', /^\d+$/.test(t) ? Number(t) : t);
}
const val = (e: Event) => (e.target as HTMLInputElement | HTMLSelectElement).value;
</script>
<template>
  <span v-if="kind === 'none'" class="muted small">값 없음</span>
  <ListInput v-else-if="kind === 'list'" :model-value="arr" :test-id="tid" :disabled="readOnly" placeholder="값1, 값2, … (쉼표 구분)" @update:model-value="onList" />
  <select v-else-if="kind === 'listid'" :value="str" :disabled="readOnly" :data-testid="tid" @change="emit('change', val($event))">
    <option v-if="!meta.lists.some((l) => l.list_id === str)" :value="str">{{ str || '(리스트 선택)' }}</option>
    <option v-for="l in meta.lists" :key="l.list_id" :value="l.list_id">{{ l.list_id }} [{{ l.kind }}]{{ l.description ? ` ${l.description}` : '' }}</option>
  </select>
  <template v-else-if="kind === 'tag'">
    <input :value="str" :list="`tags-${path}`" :disabled="readOnly" placeholder="태그" :data-testid="tid" @input="emit('change', val($event))" />
    <datalist :id="`tags-${path}`"><option v-for="t in meta.asset_tags" :key="t" :value="t" /></datalist>
  </template>
  <select v-else-if="kind === 'bool'" :value="value === false ? 'false' : 'true'" :disabled="readOnly" :data-testid="tid" @change="emit('change', val($event) === 'true')">
    <option value="true">예 (true)</option>
    <option v-if="f.type === 'bool'" value="false">아니오 (false)</option>
  </select>
  <input v-else-if="kind === 'int'" class="num-input" inputmode="numeric" :value="str" :disabled="readOnly" :data-testid="tid" @input="onInt" />
  <select v-else-if="kind === 'enum'" :value="str" :disabled="readOnly" :data-testid="tid" @change="emit('change', val($event))">
    <option v-if="!f.enum.includes(str)" :value="str">{{ str || '(선택)' }}</option>
    <option v-for="x in f.enum" :key="x" :value="x">{{ x }}</option>
  </select>
  <input
    v-else
    :value="str"
    :disabled="readOnly"
    :placeholder="op === 'cidr' ? '10.0.0.0/8' : op === 'regex' ? '정규식 (RE2)' : '값'"
    :data-testid="tid"
    @input="emit('change', val($event))"
  />
</template>
