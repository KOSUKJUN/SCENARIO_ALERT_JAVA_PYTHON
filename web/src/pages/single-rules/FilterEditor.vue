<script setup lang="ts">
// 조건 트리 편집기 (재귀). 묶음(all/any), 조건 한 줄, NOT 을 다룬다. 값은 바꾸지 않고 새 노드를 올려 보낸다.
import { computed } from 'vue';
import type { FilterLeaf, FilterNode, Json } from '../../types';
import FilterValue from './FilterValue.vue';
import IssueLines from './IssueLines.vue';
import {
  MAX_DEPTH,
  defaultValue,
  fieldAvailability,
  isGroup,
  isNot,
  issuesFor,
  leaf,
  makeLeaf,
  type FilterCtx,
} from './filter';

const props = defineProps<{ node: FilterNode; path: string; depth: number; ctx: FilterCtx; negated?: boolean; removable?: boolean }>();
const emit = defineEmits<{ change: [n: FilterNode]; remove: []; toggleNot: [] }>();

const ro = computed(() => !!props.ctx.readOnly);
const meta = computed(() => props.ctx.meta);
const asNot = computed(() => (isNot(props.node) ? props.node : null));
const asGroup = computed(() => (!isNot(props.node) && isGroup(props.node) ? props.node : null));
const asLeaf = computed(() => (!isNot(props.node) && !isGroup(props.node) ? (props.node as FilterLeaf) : null));

// NOT 토글: 감싸진 상태면 벗기고, 아니면 감싼다
function toggleNot() {
  if (props.negated) emit('toggleNot');
  else emit('change', { not: props.node });
}

// ---- 묶음
const kind = computed<'all' | 'any'>(() => (asGroup.value && 'all' in asGroup.value ? 'all' : 'any'));
const items = computed<FilterNode[]>(() => {
  const g = asGroup.value;
  if (!g) return [];
  return 'all' in g ? g.all : g.any;
});
const setGroup = (k: 'all' | 'any', its: FilterNode[]) => emit('change', k === 'all' ? { all: its } : { any: its });
const groupIssues = computed(() => [
  ...issuesFor(props.ctx.issues, props.path, false),
  ...issuesFor(props.ctx.issues, `${props.path}.${kind.value}`, false),
]);

// ---- 조건 한 줄
const f = computed(() => meta.value.fields.find((x) => x.name === asLeaf.value?.field));
const avail = computed(() => fieldAvailability(f.value, props.ctx.dataTp));
const leafIssues = computed(() => issuesFor(props.ctx.issues, props.path));
function optMark(name: string): string {
  const a = fieldAvailability(meta.value.fields.find((x) => x.name === name), props.ctx.dataTp);
  return a.none ? ' — 선택 유형에 없음' : a.missing.length ? ' ⚠ 일부 유형 비어 있음' : '';
}
function setField(e: Event) {
  const n = asLeaf.value;
  const nf = meta.value.fields.find((x) => x.name === (e.target as HTMLSelectElement).value);
  if (!n || !nf) return;
  const op = nf.ops.includes(n.op) ? n.op : nf.ops[0];
  const same = f.value && f.value.type === nf.type && op === n.op;
  emit('change', leaf(nf.name, op, same ? n.value : defaultValue(meta.value, nf, op)));
}
function setOp(e: Event) {
  const n = asLeaf.value;
  if (!n || !f.value) return;
  const op = (e.target as HTMLSelectElement).value;
  emit('change', leaf(n.field, op, defaultValue(meta.value, f.value, op)));
}
function setValue(v: Json) {
  const n = asLeaf.value;
  if (n) emit('change', { field: n.field, op: n.op, value: v });
}
</script>

<template>
  <!-- NOT: 안쪽 노드를 negated 로 그린다 -->
  <FilterEditor
    v-if="asNot"
    :node="asNot.not"
    :path="`${path}.not`"
    :depth="depth + 1"
    :ctx="ctx"
    negated
    :removable="removable"
    @change="(n) => emit('change', { not: n })"
    @toggle-not="emit('change', asNot.not)"
    @remove="emit('remove')"
  />

  <div v-else-if="asGroup" :class="['fgroup', `depth-${depth % 2}`, { negated }]" :data-testid="`filter-group-${path}`">
    <div class="fgroup-head">
      <span v-if="negated" class="not-tag">NOT</span>
      <select :value="kind" :disabled="ro" :data-testid="`filter-kind-${path}`" @change="setGroup(($event.target as HTMLSelectElement).value as 'all' | 'any', items)">
        <option value="all">모두 만족 (AND)</option>
        <option value="any">하나 이상 만족 (OR)</option>
      </select>
      <template v-if="!ro">
        <button type="button" class="small" :data-testid="`filter-add-cond-${path}`" @click="setGroup(kind, [...items, makeLeaf(meta)])">+ 조건</button>
        <button type="button" class="small" :disabled="depth >= MAX_DEPTH - 1" :data-testid="`filter-add-group-${path}`" @click="setGroup(kind, [...items, { all: [makeLeaf(meta)] }])">+ 묶음</button>
        <label class="check small"><input type="checkbox" :checked="!!negated" @change="toggleNot" />NOT</label>
        <button v-if="removable" type="button" class="small danger" @click="emit('remove')">묶음 삭제</button>
      </template>
    </div>
    <IssueLines :items="groupIssues" />
    <div class="fgroup-items">
      <div v-if="!items.length" class="muted small">조건이 없습니다. "+ 조건"으로 추가하세요.</div>
      <FilterEditor
        v-for="(it, i) in items"
        :key="i"
        :node="it"
        :path="`${path}.${kind}[${i}]`"
        :depth="depth + 1"
        :ctx="ctx"
        removable
        @change="(n) => setGroup(kind, items.map((x, j) => (j === i ? n : x)))"
        @remove="setGroup(kind, items.filter((_, j) => j !== i))"
      />
    </div>
  </div>

  <div v-else-if="asLeaf" :class="['fleaf', { negated, 'has-error': leafIssues.some((i) => i.level !== 'warn') }]" :data-testid="`filter-leaf-${path}`">
    <div class="fleaf-row">
      <span v-if="negated" class="not-tag">NOT</span>
      <select
        :value="asLeaf.field"
        :disabled="ro"
        :data-testid="`filter-field-${path}`"
        :class="avail.none ? 'unavailable' : avail.missing.length ? 'partial' : ''"
        @change="setField"
      >
        <option v-if="!f" :value="asLeaf.field">{{ asLeaf.field }} (알 수 없는 필드)</option>
        <option v-for="x in meta.fields" :key="x.name" :value="x.name">{{ x.label }} ({{ x.name }}){{ optMark(x.name) }}</option>
      </select>
      <select :value="asLeaf.op" :disabled="ro" :data-testid="`filter-op-${path}`" @change="setOp">
        <option v-if="!(f?.ops ?? []).includes(asLeaf.op)" :value="asLeaf.op">{{ asLeaf.op }}</option>
        <option v-for="o in f?.ops ?? []" :key="o" :value="o">{{ meta.op_labels[o] ?? o }}</option>
      </select>
      <FilterValue v-if="f" :f="f" :op="asLeaf.op" :value="asLeaf.value" :meta="meta" :path="path" :read-only="ro" @change="setValue" />
      <span v-if="!ro" class="fleaf-actions">
        <label class="check small" title="조건 뒤집기"><input type="checkbox" :checked="!!negated" :data-testid="`filter-not-${path}`" @change="toggleNot" />NOT</label>
        <button type="button" class="small" title="이 조건을 묶음으로 감싸기" :disabled="depth >= MAX_DEPTH - 1" @click="emit('change', { all: [asLeaf] })">묶기</button>
        <button v-if="removable" type="button" class="small danger" :data-testid="`filter-remove-${path}`" @click="emit('remove')">삭제</button>
      </span>
    </div>
    <small v-if="f?.note" class="hint">{{ f.note }}</small>
    <small v-if="avail.missing.length" class="warn-text">
      {{ avail.none ? `${f?.name} 은(는) 고른 데이터 유형 모두에서 비어 있습니다` : `${f?.name} 은(는) ${avail.missing.join(', ')} 에서 비어 있습니다` }}
    </small>
    <IssueLines :items="leafIssues" />
  </div>
</template>
