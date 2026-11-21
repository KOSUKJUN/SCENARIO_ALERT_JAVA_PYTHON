<script setup lang="ts">
// 오른쪽 속성 패널: 선택한 노드·화살표, 아무것도 고르지 않았으면 순서도 전체 설정.
// 노드·화살표 객체는 Vue Flow 저장소의 반응형 객체라 여기서 바로 고치고 changed 를 알린다.
import { computed, ref, watch } from 'vue';
import AttackPicker from '../../components/AttackPicker.vue';
import D3fendPicker from '../../components/D3fendPicker.vue';
import FormField from '../../components/FormField.vue';
import ListInput from '../../components/ListInput.vue';
import type { MetaFields, NodeSim, RuleSummary, Severity } from '../../types';
import { NODE_TYPE_LABEL, SEVERITY_LABEL } from '../../util';
import DurInput from './DurInput.vue';
import RulePicker from './RulePicker.vue';
import { DIAMONDS, gtype, type FlowEdge, type FlowNode, type GraphMeta } from './graph';

const props = defineProps<{
  meta: GraphMeta;
  isNew: boolean;
  metaFields?: MetaFields;
  rules: RuleSummary[];
  node: FlowNode | null;
  edge: FlowEdge | null;
  nodes: FlowNode[];
  edges: FlowEdge[];
  graphIssues: { id: string; message: string; level: 'error' | 'warn' }[];
  nodeIssues: string[];
  nodeWarnings: string[];
  edgeIssues: string[];
  sim?: NodeSim;
  readOnly: boolean;
  rename: (id: string, newId: string) => string | null;
}>();
const emit = defineEmits<{ changed: []; delete: []; 'edit-rule': [ruleId: string]; 'new-rule': [] }>();

const NODE_ID_RE = /^[A-Za-z0-9_-]{1,32}$/;
const g = computed(() => props.node?.data?.g);
const touch = () => emit('changed');

// ---- 노드 ID
const idText = ref('');
const idErr = ref<string | null>(null);
watch(
  () => props.node?.id,
  (v) => {
    idText.value = v ?? '';
    idErr.value = null;
  },
  { immediate: true },
);
function commitId() {
  const n = props.node;
  if (!n || idText.value === n.id) return;
  if (!NODE_ID_RE.test(idText.value)) {
    idErr.value = '영문, 숫자, _, - 1~32자';
    return;
  }
  idErr.value = props.rename(n.id, idText.value);
  if (idErr.value) idText.value = n.id;
}

function setG<K extends keyof NonNullable<typeof g.value>>(k: K, v: NonNullable<typeof g.value>[K]) {
  if (!g.value) return;
  g.value[k] = v;
  touch();
}

// ---- 화살표
const src = computed(() => props.nodes.find((n) => n.id === props.edge?.source));
const dst = computed(() => props.nodes.find((n) => n.id === props.edge?.target));
const needsWithin = computed(() => !!dst.value && gtype(dst.value) === 'rule' && !!src.value && gtype(src.value) !== 'start');
const fromDiamond = computed(() => !!src.value && DIAMONDS.has(gtype(src.value)));
const usedBranches = computed(() =>
  props.edges.filter((e) => e.source === props.edge?.source && e.id !== props.edge?.id).map((e) => e.sourceHandle),
);
// 화살표·설정 객체는 편집기가 넘긴 Vue Flow 저장소의 반응형 객체라 직접 고친다 (편집기가 changed 로 저장 안 됨 표시)
/* eslint-disable vue/no-mutating-props */
function setBranch(b: string) {
  if (!props.edge) return;
  props.edge.sourceHandle = b;
  touch();
}
function setWithin(v: string | null) {
  const e = props.edge;
  if (!e) return;
  const d = { ...(e.data ?? {}) };
  if (v) d.within = v;
  else delete d.within;
  e.data = d;
  touch();
}

// ---- 순서도 전체
const gErr = (k: string) => props.graphIssues.filter((i) => i.id === k).map((i) => i.message);
const setMeta = <K extends keyof GraphMeta>(k: K, v: GraphMeta[K]) => {
  props.meta[k] = v;
  touch();
};
/* eslint-enable vue/no-mutating-props */
</script>

<template>
  <!-- 노드 -->
  <div v-if="node && g" class="props" data-testid="props-node">
    <h4>{{ NODE_TYPE_LABEL[g.type] ?? g.type }}</h4>
    <template v-if="g.type === 'rule'">
      <FormField label="이벤트 탐지모듈">
        <RulePicker :rules="rules" :selected="g.rule_id ? [g.rule_id] : []" :multi="false" :disabled="readOnly" @change="(v) => setG('rule_id', v[0] ?? '')" />
      </FormField>
      <div v-if="!readOnly" class="prop-actions">
        <button class="small" :disabled="!g.rule_id" data-testid="prop-rule-edit" @click="emit('edit-rule', g.rule_id ?? '')">선택한 탐지 편집</button>
        <button class="small" data-testid="prop-rule-new" @click="emit('new-rule')">+ 새로 만들기</button>
      </div>
    </template>
    <FormField v-if="g.type !== 'start'" label="표시 이름 (선택)" hint="비우면 이벤트 탐지모듈 이름·제목을 보여 줍니다">
      <input :value="g.label ?? ''" :disabled="readOnly" data-testid="prop-label" @input="setG('label', ($event.target as HTMLInputElement).value || undefined)" />
    </FormField>
    <template v-if="g.type === 'check'">
      <FormField label="확인할 이벤트 탐지모듈 — 하나라도 히트가 있으면 예">
        <RulePicker :rules="rules" :selected="g.rule_ids ?? []" multi :disabled="readOnly" @change="(v) => setG('rule_ids', v)" />
      </FormField>
      <FormField label="앞뒤 확인 시간 (lookaround)">
        <DurInput :model-value="g.lookaround ?? ''" :disabled="readOnly" test-id="prop-lookaround" @update:model-value="(v) => setG('lookaround', v)" />
      </FormField>
    </template>
    <FormField v-if="g.type === 'asset'" label="자산 태그 (tags) — 대상 자산이 하나라도 가지면 예" hint="쉼표로 구분, 소문자">
      <ListInput :model-value="g.tags ?? []" list="scn-tags" test-id="prop-tags" :disabled="readOnly" @update:model-value="(v) => setG('tags', v)" />
      <datalist id="scn-tags"><option v-for="t in metaFields?.asset_tags ?? []" :key="t" :value="t" /></datalist>
      <div class="chips">
        <button
          v-for="t in (metaFields?.asset_tags ?? []).filter((x) => !(g?.tags ?? []).includes(x)).slice(0, 30)"
          :key="t"
          type="button"
          class="chip"
          :disabled="readOnly"
          @click="setG('tags', [...(g?.tags ?? []), t])"
        >
          + {{ t }}
        </button>
      </div>
    </FormField>
    <FormField v-if="g.type === 'and'" label="모든 가지 성립 허용 시간 (within)">
      <DurInput :model-value="g.within ?? ''" :disabled="readOnly" test-id="prop-within" @update:model-value="(v) => setG('within', v)" />
    </FormField>
    <p v-if="g.type === 'or'" class="muted small">들어오는 가지 중 하나라도 성립하면 통과합니다.</p>
    <template v-if="g.type === 'alert'">
      <FormField label="등급 (severity)">
        <select :value="g.severity ?? 'medium'" :disabled="readOnly" data-testid="prop-severity" @change="setG('severity', ($event.target as HTMLSelectElement).value as Severity)">
          <option v-for="s in metaFields?.severities ?? ['low', 'medium', 'high', 'critical']" :key="s" :value="s">{{ SEVERITY_LABEL[s] ?? s }} ({{ s }})</option>
        </select>
      </FormField>
      <FormField label="제목 (title)" hint="{{entity}}, {{org_id}} 를 쓸 수 있습니다">
        <input :value="g.title ?? ''" :disabled="readOnly" data-testid="prop-title" @input="setG('title', ($event.target as HTMLInputElement).value)" />
      </FormField>
      <FormField label="대응 절차 (playbook)">
        <textarea :value="g.playbook ?? ''" rows="4" :disabled="readOnly" data-testid="prop-playbook" @input="setG('playbook', ($event.target as HTMLTextAreaElement).value)" />
      </FormField>
      <FormField label="MITRE ATT&amp;CK 기법" hint="이 결론이 뜻하는 기법. 경로에서 성립한 룰의 기법은 경보에 자동으로 더해집니다">
        <AttackPicker :model-value="g.attack ?? []" :disabled="readOnly" test-id="prop-attack" @update:model-value="(v) => setG('attack', v.length ? v : undefined)" />
      </FormField>
      <FormField label="지정 대응방책 (MITRE D3FEND)" hint="이 결론에서 할 대응 기법. 경로의 룰에 지정한 대응방책도 경보에 더해집니다">
        <D3fendPicker :model-value="g.d3fend ?? []" :disabled="readOnly" :suggest-for="g.attack ?? []" test-id="prop-d3fend" @update:model-value="(v) => setG('d3fend', v.length ? v : undefined)" />
      </FormField>
    </template>
    <FormField label="노드 ID" :error="idErr" hint="경보 경로·검증 메시지에 쓰입니다">
      <input v-model="idText" :disabled="readOnly || g.type === 'start'" data-testid="prop-node-id" @blur="commitId" @keydown.enter="commitId" />
    </FormField>
    <div v-if="sim" class="sim-box">
      <strong>시뮬레이션</strong>
      <pre class="small">{{ JSON.stringify(sim, null, 2) }}</pre>
    </div>
    <div v-for="(m, i) in nodeIssues" :key="`e${i}`" class="field-error">{{ m }}</div>
    <div v-for="(m, i) in nodeWarnings" :key="`w${i}`" class="warn-text small">{{ m }}</div>
    <button v-if="!readOnly && g.type !== 'start'" class="danger" data-testid="prop-delete" @click="emit('delete')">노드 삭제</button>
  </div>

  <!-- 화살표 -->
  <div v-else-if="edge" class="props" data-testid="props-edge">
    <h4>연결</h4>
    <div class="muted">{{ edge.source }} → {{ edge.target }}</div>
    <FormField v-if="fromDiamond" label="분기">
      <select :value="edge.sourceHandle ?? ''" :disabled="readOnly" data-testid="prop-edge-branch" @change="setBranch(($event.target as HTMLSelectElement).value)">
        <option value="yes" :disabled="usedBranches.includes('yes')">예 (yes)</option>
        <option value="no" :disabled="usedBranches.includes('no')">아니오 (no)</option>
      </select>
    </FormField>
    <FormField v-if="needsWithin" label="허용 시간" hint="앞 단계가 성립한 뒤 이 시간 안에 다음 이벤트 탐지모듈 히트가 있어야 이어집니다">
      <DurInput :model-value="edge.data?.within ?? ''" :disabled="readOnly" test-id="prop-edge-within" @update:model-value="(v) => setWithin(v || null)" />
    </FormField>
    <p v-else class="muted small">
      {{ dst && gtype(dst) === 'rule' ? '시작 노드에서 나가는 화살표에는 허용 시간이 없습니다.' : '허용 시간(within)은 이벤트 탐지모듈 노드로 들어가는 화살표에만 씁니다.' }}
      <button v-if="edge.data?.within" class="small link" @click="setWithin(null)">within 지우기</button>
    </p>
    <div v-for="(m, i) in edgeIssues" :key="i" class="field-error">{{ m }}</div>
    <button v-if="!readOnly" class="danger" data-testid="prop-delete" @click="emit('delete')">연결 삭제</button>
  </div>

  <!-- 순서도 전체 -->
  <div v-else class="props" data-testid="props-graph">
    <h4>시나리오 설정</h4>
    <FormField label="ID" :error="gErr('id')" hint="대문자로 시작, 대문자·숫자·_ (예: SC_SMB_WORM)">
      <input :value="meta.id" :disabled="!isNew || readOnly" data-testid="scenario-id" @input="setMeta('id', ($event.target as HTMLInputElement).value.toUpperCase())" />
    </FormField>
    <FormField label="이름" :error="gErr('name')">
      <input :value="meta.name" :disabled="readOnly" data-testid="scenario-name" @input="setMeta('name', ($event.target as HTMLInputElement).value)" />
    </FormField>
    <FormField label="설명">
      <textarea :value="meta.description ?? ''" rows="2" :disabled="readOnly" @input="setMeta('description', ($event.target as HTMLTextAreaElement).value)" />
    </FormField>
    <FormField label="대상 유형" :error="gErr('entity_type')" hint="같은 유형의 이벤트 탐지모듈만 왼쪽 목록에 보입니다">
      <select :value="meta.entity_type" :disabled="readOnly" data-testid="scenario-entity-type" @change="setMeta('entity_type', ($event.target as HTMLSelectElement).value)">
        <option v-for="t in metaFields?.entity_types ?? [{ type: meta.entity_type, fields: [] }]" :key="t.type" :value="t.type">{{ t.type }}</option>
      </select>
    </FormField>
    <FormField label="억제 시간 (suppress_for)" :error="gErr('suppress_for')" hint="같은 대상에 경보를 다시 만들지 않는 시간 (최대 7일)">
      <DurInput :model-value="meta.suppress_for" :disabled="readOnly" test-id="scenario-suppress-for" @update:model-value="(v) => setMeta('suppress_for', v)" />
    </FormField>
    <ol class="howto small">
      <li>왼쪽에서 이벤트 탐지모듈·블록을 끌어다 놓습니다.</li>
      <li>노드 오른쪽 점을 끌어 다음 노드에 잇습니다. 확인 노드는 위가 "예", 아래가 "아니오"입니다.</li>
      <li>노드를 누르면 여기서 설정하고, 이벤트 탐지모듈 노드는 두 번 눌러 바로 편집합니다.</li>
    </ol>
    <p class="muted small">노드 {{ nodes.length }}개 · 연결 {{ edges.length }}개 · Delete 키로 선택 항목 삭제</p>
  </div>
</template>
