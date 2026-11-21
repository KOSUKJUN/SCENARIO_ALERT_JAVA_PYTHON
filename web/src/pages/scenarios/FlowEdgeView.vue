<script setup lang="ts">
// 순서도 화살표: 기존과 같은 꺾은선(smoothstep)과 가운데 라벨("예 · 30분 내", 오류).
// 편집기에서 선택하면 라벨 옆에 삭제 버튼이 나온다.
import { computed, type CSSProperties } from 'vue';
import { BaseEdge, EdgeLabelRenderer, Position, getSmoothStepPath } from '@vue-flow/core';
import type { FlowEdgeData } from './graph';

defineOptions({ inheritAttrs: false });
const props = defineProps<{
  id: string;
  sourceX: number;
  sourceY: number;
  targetX: number;
  targetY: number;
  sourcePosition: Position;
  targetPosition: Position;
  markerEnd?: string;
  style?: CSSProperties;
  label?: unknown;
  data?: FlowEdgeData;
  selected?: boolean;
  editable?: boolean;
}>();
const emit = defineEmits<{ remove: [id: string] }>();

const geo = computed(() =>
  getSmoothStepPath({
    sourceX: props.sourceX,
    sourceY: props.sourceY,
    targetX: props.targetX,
    targetY: props.targetY,
    sourcePosition: props.sourcePosition,
    targetPosition: props.targetPosition,
  }),
);
const text = computed(() => (typeof props.label === 'string' ? props.label : ''));
const hasIssue = computed(() => !!props.data?.issues?.length);
const showDelete = computed(() => !!props.editable && !!props.selected);
</script>
<template>
  <BaseEdge :id="id" :path="geo[0]" :marker-end="markerEnd" :style="style" :interaction-width="20" />
  <EdgeLabelRenderer>
    <div
      v-if="text || showDelete"
      :class="['edge-label', 'nodrag', 'nopan', { err: hasIssue }]"
      :style="{ transform: `translate(-50%, -50%) translate(${geo[1]}px, ${geo[2]}px)` }"
      :data-testid="`edge-label-${id}`"
    >
      <span v-if="text">{{ text }}</span>
      <button v-if="showDelete" class="edge-del" title="화살표 삭제" :data-testid="`edge-delete-${id}`" @click.stop="emit('remove', id)">✕</button>
    </div>
  </EdgeLabelRenderer>
</template>
