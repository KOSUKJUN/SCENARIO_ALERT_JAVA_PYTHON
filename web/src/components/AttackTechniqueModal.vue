<script setup lang="ts">
// ATT&CK 기법 상세 (내부 사본): 전술, 설명, 하위 기법, 완화, 탐지 전략, 그룹·소프트웨어, 이 시스템의 커버리지.
import { ref, watch } from 'vue';
import { api, enc } from '../api';
import { attackText } from '../attack';
import { useAsync } from '../composables';
import type { AttackTechniqueDetail } from '../types';
import CountermeasuresPanel from './CountermeasuresPanel.vue';
import ErrorBox from './ErrorBox.vue';
import LoadingBox from './LoadingBox.vue';
import ModalDialog from './ModalDialog.vue';
import StatusBadge from './StatusBadge.vue';

const props = defineProps<{ id: string; domain?: string; version?: string }>();
const emit = defineEmits<{ close: [] }>();
const current = ref(props.id);
watch(
  () => props.id,
  (v) => (current.value = v),
);
const t = useAsync(
  () => api.get<AttackTechniqueDetail>(`/attack/techniques/${enc(current.value)}`, { domain: props.domain, version: props.version }),
  [current],
);
const MAX = 12;
const showAll = ref<Record<string, boolean>>({});
const list = <T,>(k: string, xs: T[]) => (showAll.value[k] ? xs : xs.slice(0, MAX));
</script>
<template>
  <ModalDialog :title="`MITRE ATT&CK ${current}`" wide @close="emit('close')">
    <LoadingBox v-if="t.loading.value" />
    <ErrorBox :error="t.error.value" />
    <div v-if="t.data.value" class="attack-detail" data-testid="attack-detail">
      <h3 class="attack-title">
        {{ t.data.value.id }} {{ t.data.value.name }}
        <span v-if="t.data.value.revoked" class="badge bad">폐기 → {{ t.data.value.revoked_by }}</span>
        <span v-else-if="t.data.value.deprecated" class="badge warn">사용 중단</span>
      </h3>
      <p class="muted small">
        {{ t.data.value.domain }} {{ t.data.value.version }}
        <template v-if="t.data.value.parent_id">
          · 상위 기법 <a href="#" @click.prevent="current = t.data.value.parent_id!">{{ t.data.value.parent_id }} {{ t.data.value.parent_name }}</a>
        </template>
        <template v-if="t.data.value.extra.platforms?.length"> · 플랫폼 {{ t.data.value.extra.platforms.join(', ') }}</template>
      </p>
      <div class="chips">
        <span v-for="ta in t.data.value.tactics" :key="ta.id" class="chip tactic">{{ ta.id }} {{ ta.name }}</span>
      </div>

      <section class="attack-sec">
        <h4>이 시스템의 탐지</h4>
        <p v-if="!t.data.value.coverage.rules.length && !t.data.value.coverage.scenarios.length" class="warn-text small" data-testid="attack-uncovered">
          이 기법을 탐지하는 이벤트 탐지모듈·시나리오가 없습니다.
        </p>
        <ul class="plain">
          <li v-for="r in t.data.value.coverage.rules" :key="r.id">
            이벤트 탐지모듈 <RouterLink :to="`/scenarios/detections/${r.id}`">{{ r.id }}</RouterLink> {{ r.name }} <StatusBadge :status="r.status" />
          </li>
          <li v-for="s in t.data.value.coverage.scenarios" :key="s.id">
            시나리오 <RouterLink :to="`/scenarios/${s.id}`">{{ s.id }}</RouterLink> {{ s.name }} <StatusBadge :status="s.status" />
            <span class="muted small">({{ s.via }})</span>
          </li>
        </ul>
        <p class="small">
          최근 30일 경보 {{ t.data.value.coverage.alerts_30d }}건
          <RouterLink v-if="t.data.value.coverage.alerts_30d" :to="{ path: '/alerts', query: { technique: t.data.value.id } }" @click="emit('close')">경보 보기</RouterLink>
        </p>
      </section>

      <section class="attack-sec">
        <h4>설명</h4>
        <p class="pre-wrap">{{ attackText(t.data.value.description) }}</p>
      </section>

      <section v-if="t.data.value.subtechniques.length" class="attack-sec">
        <h4>하위 기법 ({{ t.data.value.subtechniques.length }})</h4>
        <div class="chips">
          <a v-for="s in t.data.value.subtechniques" :key="s.id" href="#" class="chip" @click.prevent="current = s.id">{{ s.id }} {{ s.name }}</a>
        </div>
      </section>

      <section v-for="sec in ([['mitigations', '완화 (Mitigation)'], ['detections', '탐지 전략 (Detection Strategy)']] as const)" :key="sec[0]" class="attack-sec">
        <h4>{{ sec[1] }} ({{ t.data.value[sec[0]].length }})</h4>
        <p v-if="!t.data.value[sec[0]].length" class="muted small">없음</p>
        <dl class="kv">
          <div v-for="m in list(sec[0], t.data.value[sec[0]])" :key="m.id" class="kv-row">
            <dt>{{ m.id }} {{ m.name }}</dt>
            <dd class="small">{{ attackText(m.description) }}</dd>
          </div>
        </dl>
        <button v-if="t.data.value[sec[0]].length > MAX && !showAll[sec[0]]" class="small" @click="showAll[sec[0]] = true">모두 보기</button>
      </section>

      <section class="attack-sec" data-testid="attack-d3fend">
        <h4>D3FEND 대응 기법</h4>
        <CountermeasuresPanel :attack="[t.data.value.id]" :per-tactic="3" test-id="attack-countermeasures" />
      </section>

      <section v-for="sec in ([['groups', '이 기법을 쓴 그룹'], ['software', '이 기법을 쓰는 소프트웨어']] as const)" :key="sec[0]" class="attack-sec">
        <h4>{{ sec[1] }} ({{ t.data.value[sec[0]].length }})</h4>
        <div class="chips">
          <span v-for="g in list(sec[0], t.data.value[sec[0]])" :key="g.id" class="chip" :title="attackText(g.description)">{{ g.id }} {{ g.name }}</span>
        </div>
        <button v-if="t.data.value[sec[0]].length > MAX && !showAll[sec[0]]" class="small" @click="showAll[sec[0]] = true">모두 보기</button>
      </section>
      <p v-if="t.data.value.url" class="muted small">원문 (인터넷): {{ t.data.value.url }}</p>
    </div>
  </ModalDialog>
</template>
<style scoped>
.attack-title { margin: 0 0 4px; }
.attack-sec { margin-top: 14px; }
.attack-sec h4 { margin: 0 0 6px; }
.pre-wrap { white-space: pre-wrap; }
.plain { list-style: none; padding: 0; margin: 0; }
.plain li { padding: 2px 0; }
.chip.tactic { border-color: var(--primary); }
.badge { margin-left: 6px; padding: 0 6px; border-radius: 10px; font-size: 12px; border: 1px solid; }
.badge.bad { color: var(--bad); }
.badge.warn { color: var(--warn); }
</style>
