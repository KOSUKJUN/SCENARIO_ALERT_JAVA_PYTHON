<script setup lang="ts">
// D3FEND 방어 기법 상세 (내부 사본): 전술·상위 기법, 정의, 설명(KB), 이 기법이 막는 ATT&CK 기법(디지털 아티팩트 근거),
// 연결된 ATT&CK 완화(M), 이 기법을 대응방책으로 지정한 이벤트 탐지모듈·시나리오.
import { ref, watch } from 'vue';
import { api, enc } from '../api';
import { d3fendText, tacticLabel } from '../d3fend';
import { useAsync } from '../composables';
import type { D3fendTechniqueDetail } from '../types';
import ErrorBox from './ErrorBox.vue';
import LoadingBox from './LoadingBox.vue';
import ModalDialog from './ModalDialog.vue';
import StatusBadge from './StatusBadge.vue';

const props = defineProps<{ id: string; version?: string }>();
const emit = defineEmits<{ close: [] }>();
const current = ref(props.id);
watch(
  () => props.id,
  (v) => (current.value = v),
);
const t = useAsync(() => api.get<D3fendTechniqueDetail>(`/d3fend/techniques/${enc(current.value)}`, { version: props.version }), [current]);
const MAX = 20;
const showAll = ref(false);
const viaText = (v: { def_rel: string | null; def_artifact: string | null; off_rel: string | null; off_artifact: string | null }) =>
  `${v.def_rel ?? ''} ${v.def_artifact ?? ''} ← 공격이 ${v.off_rel ?? ''} ${v.off_artifact ?? ''}`.trim();
</script>
<template>
  <ModalDialog :title="`MITRE D3FEND ${current}`" wide @close="emit('close')">
    <LoadingBox v-if="t.loading.value" />
    <ErrorBox :error="t.error.value" />
    <div v-if="t.data.value" class="d3-detail" data-testid="d3fend-detail">
      <h3 class="d3-title">{{ t.data.value.id }} {{ t.data.value.name }}</h3>
      <p class="muted small">
        D3FEND {{ t.data.value.version }} · 전술 <strong>{{ tacticLabel(t.data.value.tactic) }}</strong>
        <template v-for="a in t.data.value.ancestors" :key="a.id">
          › <a href="#" @click.prevent="current = a.id">{{ a.id }} {{ a.name }}</a>
        </template>
        <template v-if="t.data.value.synonyms.length"> · 다른 이름 {{ t.data.value.synonyms.join(', ') }}</template>
      </p>

      <section class="d3-sec">
        <h4>이 시스템의 지정</h4>
        <p v-if="!t.data.value.designated_by.length" class="muted small" data-testid="d3fend-undesignated">이 기법을 대응방책으로 지정한 이벤트 탐지모듈·시나리오가 없습니다.</p>
        <ul class="plain">
          <li v-for="r in t.data.value.designated_by" :key="`${r.kind}${r.id}${r.detail}`">
            {{ r.kind === 'rule' ? '이벤트 탐지모듈' : '시나리오' }}
            <RouterLink :to="r.kind === 'rule' ? `/scenarios/detections/${r.id}` : `/scenarios/${r.id}`" @click="emit('close')">{{ r.id }}</RouterLink>
            {{ r.name }} <StatusBadge :status="r.status" /> <span class="muted small">{{ r.detail ?? '' }}</span>
          </li>
        </ul>
      </section>

      <section class="d3-sec">
        <h4>정의</h4>
        <p class="pre-wrap">{{ t.data.value.definition ?? '' }}</p>
        <details v-if="t.data.value.kb_article">
          <summary>설명 (D3FEND KB)</summary>
          <p class="pre-wrap small">{{ d3fendText(t.data.value.kb_article) }}</p>
        </details>
      </section>

      <section v-if="t.data.value.children.length" class="d3-sec">
        <h4>하위 기법 ({{ t.data.value.children.length }})</h4>
        <div class="chips">
          <a v-for="c in t.data.value.children" :key="c.id" href="#" class="chip" @click.prevent="current = c.id">{{ c.id }} {{ c.name }}</a>
        </div>
      </section>

      <section class="d3-sec">
        <h4>이 기법이 대응하는 ATT&amp;CK 기법 ({{ t.data.value.attack.length }})</h4>
        <p v-if="!t.data.value.attack.length" class="muted small">D3FEND 매핑 없음</p>
        <table v-else class="table small" data-testid="d3fend-detail-attack">
          <thead><tr><th>ATT&amp;CK</th><th>근거 (디지털 아티팩트)</th></tr></thead>
          <tbody>
            <tr v-for="a in showAll ? t.data.value.attack : t.data.value.attack.slice(0, MAX)" :key="a.id">
              <td class="nowrap"><span class="mono">{{ a.id }}</span> {{ a.name ?? '' }}<span v-if="a.domain !== 'enterprise'" class="muted"> ({{ a.domain }})</span></td>
              <td class="muted">{{ a.via.map(viaText).join(' / ') }}</td>
            </tr>
          </tbody>
        </table>
        <button v-if="t.data.value.attack.length > MAX && !showAll" class="small" @click="showAll = true">모두 보기</button>
      </section>

      <section v-if="t.data.value.mitigations.length" class="d3-sec">
        <h4>연결된 ATT&amp;CK 완화 (Mitigation)</h4>
        <div class="chips">
          <span v-for="m in t.data.value.mitigations" :key="m.id" class="chip">{{ m.id }} {{ m.name }}</span>
        </div>
      </section>
      <p class="muted small">원문 (인터넷): https://d3fend.mitre.org/technique/d3f:{{ t.data.value.iri }}/</p>
    </div>
  </ModalDialog>
</template>
<style scoped>
.d3-title { margin: 0 0 4px; }
.d3-sec { margin-top: 14px; }
.d3-sec h4 { margin: 0 0 6px; }
.pre-wrap { white-space: pre-wrap; }
.plain { list-style: none; padding: 0; margin: 0; }
.plain li { padding: 2px 0; }
.nowrap { white-space: nowrap; }
</style>
