<script setup lang="ts">
// 경보 상세: 순서도와 지나온 경로 강조, 노드별 근거 이벤트, 판정 등록, 오탐 대상을 예외 리스트에 추가.
import { computed, ref } from 'vue';
import { api, enc } from '../../api';
import { has, showIncident } from '../../auth';
import { useAsync } from '../../composables';
import CardBox from '../../components/CardBox.vue';
import EmptyBox from '../../components/EmptyBox.vue';
import ErrorBox from '../../components/ErrorBox.vue';
import FormField from '../../components/FormField.vue';
import LoadingBox from '../../components/LoadingBox.vue';
import NoticeBox from '../../components/NoticeBox.vue';
import RowsTable from '../../components/RowsTable.vue';
import SeverityBadge from '../../components/SeverityBadge.vue';
import UiBadge from '../../components/UiBadge.vue';
import type { AlertDetail, AlertEvents, PathStep, Row } from '../../types';
import { DELIVERY_LABEL, VERDICT_LABEL, cellText, fmtTime, truthy } from '../../util';
import GraphView from '../scenarios/GraphView.vue';

const props = defineProps<{ alertId: string }>();
const EVENT_COLS = ['mgr_time', 'data_tp', 'product', 'src_ip', 'src_port', 'dst_ip', 'dst_port', 'protocol', 'action', 'net_direction', 'signature_name', 'attack', 'event_count', 'uri'];

const a = useAsync(() => api.get<AlertDetail>(`/alerts/${enc(props.alertId)}`), [() => props.alertId]);
const ev = useAsync(() => api.get<AlertEvents>(`/alerts/${enc(props.alertId)}/events`), [() => props.alertId]);
const verdict = ref('');
const note = ref('');
const excList = ref('');
const excOnly = ref('');
const excNote = ref('');
const busy = ref<string | null>(null);
const err = ref<unknown>(null);
const msg = ref<string | null>(null);

const d = computed(() => a.data.value);
const path = computed<PathStep[]>(() => (Array.isArray(d.value?.path) ? d.value.path : []));
const silent = computed(() => truthy(d.value?.silent));
const groups = computed(() => {
  const events = ev.data.value?.events ?? [];
  const byId = new Map(events.map((e) => [String(e.event_id), e]));
  return Object.entries(ev.data.value?.by_node ?? {}).map(([node, ids]) => {
    const rows = ids.map((id) => byId.get(id)).filter((x): x is Row => !!x);
    return {
      node,
      rows,
      step: path.value.find((s) => s.node === node),
      cols: EVENT_COLS.filter((c) => rows.some((r) => r[c] !== null && r[c] !== undefined && r[c] !== '')),
    };
  });
});

function stepText(s: PathStep): string {
  const parts: string[] = [];
  if (s.type === 'rule') parts.push(`단일룰 ${s.rule_id ?? ''} 히트`);
  else if (s.type === 'check') parts.push(`룰 확인 → ${s.result === 'yes' ? `예 (${s.matched_rule_id ?? ''})` : '아니오'}`);
  else if (s.type === 'asset') parts.push(`자산 태그 → ${s.result === 'yes' ? `예 (${(s.matched_tags ?? []).join(', ')})` : '아니오'}`);
  else if (s.type === 'alert') parts.push(`경보 (${s.severity ?? ''})`);
  else if (s.rule_id) parts.push(`룰 ${s.rule_id}`);
  else if (s.result) parts.push(`결과 ${s.result}`);
  if (s.value !== undefined) parts.push(`값 ${s.value}${s.threshold !== undefined ? ` / 임계 ${s.threshold}` : ''}`);
  return parts.join(' · ');
}

async function run(key: string, fn: () => Promise<unknown>, ok: string) {
  busy.value = key;
  err.value = null;
  msg.value = null;
  try {
    await fn();
    msg.value = ok;
    a.reload();
  } catch (e) {
    err.value = e;
  } finally {
    busy.value = null;
  }
}
const submitVerdict = () =>
  run('verdict', () => api.post(`/alerts/${enc(props.alertId)}/verdict`, { verdict: verdict.value, note: note.value || null, exception_list: excList.value || null }), '판정을 등록했습니다');
const submitException = () =>
  run('exc', () => api.post(`/alerts/${enc(props.alertId)}/exception`, { list_id: excOnly.value, note: excNote.value || null }), `${excOnly.value} 에 추가했습니다`);
const redeliver = () => run('redeliver', () => api.post(`/alerts/${enc(props.alertId)}/redeliver`), '다시 전달하도록 대기열에 넣었습니다');
const assetVal = (v: unknown) => (Array.isArray(v) ? v.map(String) : cellText(v));
</script>

<template>
  <LoadingBox v-if="a.loading.value && !d" />
  <ErrorBox v-else-if="a.error.value" :error="a.error.value" />
  <div v-else-if="d" class="page">
    <div class="page-head">
      <h2 data-testid="alert-title"><SeverityBadge :severity="d.severity" /> {{ d.title }}</h2>
      <div class="actions"><RouterLink to="/alerts" class="button">목록</RouterLink></div>
    </div>
    <NoticeBox v-if="msg" kind="ok">{{ msg }}</NoticeBox>
    <ErrorBox :error="err" closable @close="err = null" />
    <div class="grid-2">
      <CardBox title="경보 정보">
        <dl class="kv">
          <div class="kv-row">
            <dt>출처</dt>
            <dd>
              <RouterLink :to="d.source_type === 'scenario' ? `/scenarios/${d.source_id}` : `/single-rules/${d.source_id}`">
                {{ d.source_type === 'scenario' ? '순서도' : '단일룰' }} {{ d.source_id }}
              </RouterLink>
              v{{ d.source_version }}
            </dd>
          </div>
          <div class="kv-row"><dt>기관</dt><dd>{{ d.org_id }}</dd></div>
          <div class="kv-row"><dt>대상</dt><dd>{{ d.entity_type }} {{ d.entity }}</dd></div>
          <div class="kv-row"><dt>최초 / 최종</dt><dd>{{ fmtTime(d.first_seen) }} ~ {{ fmtTime(d.last_seen) }}</dd></div>
          <div class="kv-row"><dt>횟수</dt><dd>{{ d.hit_count }}</dd></div>
          <div class="kv-row"><dt>생성 / 상향</dt><dd>{{ fmtTime(d.created_at) }}{{ d.upgraded_at ? ` / 상향 ${fmtTime(d.upgraded_at)}` : '' }}</dd></div>
          <div class="kv-row"><dt>silent</dt><dd><UiBadge v-if="silent">silent (전달 안 함)</UiBadge><template v-else>아니오</template></dd></div>
          <div v-if="showIncident()" class="kv-row">
            <dt>전달</dt>
            <dd>
              <UiBadge :kind="d.delivery_status === 'failed' ? 'bad' : d.delivery_status === 'sent' ? 'ok' : undefined">{{ DELIVERY_LABEL[d.delivery_status] ?? d.delivery_status }}</UiBadge>
              시도 {{ d.delivery_attempts }}회
              <button v-if="has('analyst') && !silent" class="small" :disabled="!!busy" data-testid="alert-redeliver" @click="redeliver">다시 전달</button>
              <div v-if="d.delivery_error" class="err-text small">{{ d.delivery_error }}</div>
            </dd>
          </div>
          <div v-if="showIncident()" class="kv-row"><dt>사고 번호</dt><dd>{{ d.case_ref ?? '-' }}</dd></div>
          <div v-if="showIncident()" class="kv-row">
            <dt>판정</dt>
            <dd data-testid="alert-verdict">
              {{ d.verdict ? `${VERDICT_LABEL[d.verdict] ?? d.verdict}${d.verdict_note ? ` — ${d.verdict_note}` : ''} (${fmtTime(d.verdict_at)})` : '미판정' }}
            </dd>
          </div>
        </dl>
      </CardBox>
      <CardBox title="자산 정보">
        <dl v-if="d.asset" class="kv">
          <div v-for="(v, k) in d.asset" :key="k" class="kv-row">
            <dt>{{ k }}</dt>
            <dd>
              <template v-if="Array.isArray(v)"><UiBadge v-for="t in assetVal(v)" :key="t">{{ t }}</UiBadge></template>
              <template v-else>{{ assetVal(v) }}</template>
            </dd>
          </div>
        </dl>
        <EmptyBox v-else>등록된 자산 정보가 없습니다</EmptyBox>
        <template v-if="d.playbook">
          <h4>대응 절차</h4>
          <p class="playbook">{{ d.playbook }}</p>
        </template>
      </CardBox>
    </div>

    <CardBox title="지나온 경로">
      <ol class="path-steps" data-testid="alert-path">
        <li v-for="(s, i) in path" :key="i">
          <strong>{{ s.node }}</strong> {{ stepText(s) }} <span v-if="s.at" class="muted small">{{ fmtTime(s.at) }}</span>
          <span v-if="s.first_seen" class="muted small"> (이벤트 {{ fmtTime(s.first_seen) }} ~ {{ fmtTime(s.last_seen) }})</span>
        </li>
      </ol>
      <GraphView v-if="d.source_type === 'scenario' && d.graph" :graph="d.graph" :path="path" />
      <EmptyBox v-else-if="d.source_type === 'scenario'">해당 버전의 순서도를 찾을 수 없습니다</EmptyBox>
    </CardBox>

    <CardBox title="근거 이벤트">
      <LoadingBox v-if="ev.loading.value" />
      <ErrorBox :error="ev.error.value" />
      <EmptyBox v-if="!ev.loading.value && !(ev.data.value?.events.length)">근거 이벤트가 없습니다</EmptyBox>
      <div v-for="g in groups" :key="g.node" class="evidence-group" :data-testid="`evidence-${g.node}`">
        <h4>노드 {{ g.node }} <span v-if="g.step" class="muted small">{{ stepText(g.step) }}</span> · {{ g.rows.length }}건</h4>
        <RowsTable :rows="g.rows" :columns="g.cols" />
        <details v-if="g.rows.length">
          <summary>전체 열 보기</summary>
          <RowsTable :rows="g.rows" />
        </details>
      </div>
    </CardBox>

    <div v-if="has('analyst')" class="grid-2">
      <CardBox v-if="showIncident()" title="판정 등록">
        <div class="radio-row" data-testid="verdict-options">
          <label v-for="(v, k) in VERDICT_LABEL" :key="k" class="check">
            <input v-model="verdict" type="radio" name="verdict" :value="k" :data-testid="`verdict-${k}`" />{{ v }}
          </label>
        </div>
        <FormField label="메모"><textarea v-model="note" rows="2" data-testid="verdict-note" /></FormField>
        <FormField label="오탐 대상을 예외 리스트에 함께 추가 (선택)">
          <select v-model="excList" data-testid="verdict-exception">
            <option value="">추가 안 함</option>
            <option v-for="l in d.exception_lists" :key="l.list_id" :value="l.list_id">{{ l.list_id }} [{{ l.kind }}] {{ l.description ?? '' }}</option>
          </select>
        </FormField>
        <button class="primary" :disabled="!verdict || !!busy" data-testid="verdict-submit" @click="submitVerdict">판정 등록</button>
      </CardBox>
      <CardBox title="이 대상을 예외 리스트에 추가">
        <p class="muted small">대상 {{ d.entity }} 를 예외 리스트에 넣으면 그 리스트를 exclude_lists 로 쓰는 룰에서 이 대상이 빠집니다.</p>
        <FormField label="리스트">
          <select v-model="excOnly" data-testid="exception-list">
            <option value="">선택</option>
            <option v-for="l in d.exception_lists" :key="l.list_id" :value="l.list_id">{{ l.list_id }} [{{ l.kind }}] {{ l.description ?? '' }}</option>
          </select>
        </FormField>
        <FormField label="메모"><input v-model="excNote" /></FormField>
        <button :disabled="!excOnly || !!busy" data-testid="exception-submit" @click="submitException">예외 리스트에 추가</button>
      </CardBox>
    </div>
  </div>
</template>
