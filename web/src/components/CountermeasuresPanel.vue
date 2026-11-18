<script setup lang="ts">
// 대응방책 (MITRE D3FEND): ATT&CK 기법들에 대한 방어 기법을 전술별로 묶어 보여 준다.
// 순서: 사고 대응(격리 → 퇴출 → 복구) → 재발 방지(탐지 → 강화) → 기만 → 모델링.
// 각 전술 안에서는 지정(룰·경보 노드에 사람이 정한 것) → ATT&CK 완화(M)와 연결된 권고 → 더 많은 기법에 대응하는 것 순.
import { computed, ref } from 'vue';
import { api } from '../api';
import { useAsync } from '../composables';
import type { Countermeasures, D3fendRef } from '../types';
import D3fendTechniqueModal from './D3fendTechniqueModal.vue';
import EmptyBox from './EmptyBox.vue';
import ErrorBox from './ErrorBox.vue';
import LoadingBox from './LoadingBox.vue';

const props = defineProps<{
  attack: string[];
  /** 지정 대응방책: 경보 스냅샷(이름·전술 포함) 또는 ID 목록 */
  designated?: (D3fendRef | string)[];
  designatedVersion?: string | null;
  /** 전술마다 처음에 보여 줄 수 */
  perTactic?: number;
  testId?: string;
}>();
const designatedIds = computed(() => (props.designated ?? []).map((d) => (typeof d === 'string' ? d : d.id)));
const key = computed(() => `${props.attack.join(',')}|${designatedIds.value.join(',')}`);
const cm = useAsync(
  () => (props.attack.length || designatedIds.value.length
    ? api.post<Countermeasures>('/d3fend/countermeasures', { attack: props.attack, d3fend: designatedIds.value })
    : Promise.resolve(null)),
  [key],
);
const PER = computed(() => props.perTactic ?? 5);
const expanded = ref<Record<string, boolean>>({});
const detail = ref<string | null>(null);
const notFound = computed(() => (cm.error.value as { status?: number } | null)?.status === 404);
const snapshot = computed(() => (props.designated ?? []).filter((d): d is D3fendRef => typeof d !== 'string'));
</script>
<template>
  <div class="cm" :data-testid="testId ?? 'countermeasures'">
    <div v-if="snapshot.length" class="cm-designated" data-testid="cm-designated">
      <strong class="small">지정 대응방책</strong>
      <span class="chips">
        <a v-for="d in snapshot" :key="d.id" href="#" class="chip designated" :data-testid="`alert-d3fend-${d.id}`" @click.prevent="detail = d.id">
          {{ d.id }}<template v-if="d.name">{{ ' ' + d.name }}</template>
        </a>
      </span>
      <span v-if="designatedVersion" class="muted small">{{ designatedVersion }} 기준 (경보 생성·상향 때)</span>
    </div>
    <LoadingBox v-if="cm.loading.value" />
    <EmptyBox v-else-if="notFound">D3FEND 데이터가 없습니다. D3FEND 메뉴의 "버전 관리"에서 가져오세요.</EmptyBox>
    <ErrorBox v-else-if="cm.error.value" :error="cm.error.value" />
    <EmptyBox v-else-if="!attack.length && !designatedIds.length">ATT&amp;CK 기법이 없어 권고할 대응방책이 없습니다</EmptyBox>
    <template v-if="cm.data.value">
      <p class="muted small">
        D3FEND {{ cm.data.value.version }} · 대응 기법 {{ cm.data.value.summary.techniques }}개
        (지정 {{ cm.data.value.summary.designated }}, ATT&amp;CK 완화 연계 {{ cm.data.value.summary.recommended }}, D3FEND 매핑 {{ cm.data.value.summary.mapped }})
        <template v-if="cm.data.value.parent_fallback.length">
          · 상위 기법으로 찾음: {{ cm.data.value.parent_fallback.map((p) => `${p.attack}→${p.used}`).join(', ') }}
        </template>
        <template v-if="cm.data.value.unmapped_attack.length"> · 매핑 없음: {{ cm.data.value.unmapped_attack.join(', ') }}</template>
      </p>
      <div class="cm-groups">
        <section v-for="g in cm.data.value.tactics" :key="g.tactic" :class="['cm-group', { response: g.response }]" :data-testid="`cm-tactic-${g.tactic}`">
          <h5>
            {{ g.label_ko }} <span class="muted small">{{ g.tactic }} · {{ g.techniques.length }}</span>
            <span v-if="g.response" class="tag small">사고 대응</span>
          </h5>
          <ul class="cm-list">
            <li v-for="t in expanded[g.tactic] ? g.techniques : g.techniques.slice(0, PER)" :key="t.id" :data-testid="`cm-item-${t.id}`">
              <a href="#" class="mono" @click.prevent="detail = t.id">{{ t.id }}</a> {{ t.name }}
              <span v-if="t.designated" class="badge designated">지정</span>
              <span v-else-if="t.recommended" class="badge rec" :title="t.mitigations.map((m) => `${m.id} ${m.name}`).join(', ')">
                권고 ({{ t.mitigations.map((m) => m.id).join(', ') }})
              </span>
              <div v-if="t.attack.length" class="muted small">
                대응 ATT&amp;CK: {{ t.attack.join(', ') }}
                <template v-if="t.via.length"> · {{ t.via[0].def_rel }} {{ t.via[0].def_artifact }}</template>
              </div>
            </li>
          </ul>
          <button v-if="g.techniques.length > PER && !expanded[g.tactic]" class="small" @click="expanded[g.tactic] = true">
            {{ g.techniques.length - PER }}개 더 보기
          </button>
        </section>
      </div>
      <details v-if="cm.data.value.attack_mitigations.length" class="cm-mit">
        <summary>ATT&amp;CK 완화 (Mitigation) {{ cm.data.value.attack_mitigations.length }}개와 D3FEND 연결</summary>
        <ul class="small">
          <li v-for="m in cm.data.value.attack_mitigations" :key="m.id">
            <strong>{{ m.id }}</strong> {{ m.name }} <span class="muted">({{ m.attack.join(', ') }})</span>
            <template v-if="m.d3fend.length"> → {{ m.d3fend.join(', ') }}</template>
          </li>
        </ul>
      </details>
    </template>
    <D3fendTechniqueModal v-if="detail" :id="detail" @close="detail = null" />
  </div>
</template>
<style scoped>
.cm-designated { display: flex; flex-wrap: wrap; gap: 6px; align-items: center; margin-bottom: 6px; }
.chip.designated { border-color: var(--primary); }
.cm-groups { display: grid; grid-template-columns: repeat(auto-fill, minmax(240px, 1fr)); gap: 8px; }
.cm-group { border: 1px solid var(--border); border-radius: var(--radius); padding: 6px 8px; }
.cm-group.response { border-left: 3px solid var(--warn); }
.cm-group h5 { margin: 0 0 4px; font-size: 13px; }
.cm-list { list-style: none; padding: 0; margin: 0; }
.cm-list li { padding: 2px 0; font-size: 13px; }
.badge { margin-left: 4px; padding: 0 5px; border-radius: 9px; font-size: 11px; border: 1px solid; }
.badge.designated { color: var(--primary); }
.badge.rec { color: var(--ok); }
.tag { margin-left: 4px; color: var(--warn); }
.cm-mit { margin-top: 8px; }
</style>
