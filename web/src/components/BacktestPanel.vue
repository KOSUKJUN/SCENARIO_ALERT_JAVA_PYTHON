<script setup lang="ts">
import { onBeforeUnmount, ref } from 'vue';
import { api, enc } from '../api';
import { useAsync } from '../composables';
import type { BacktestJob, Org } from '../types';
import { fmtTime, kstInput, localInputToIso } from '../util';
import BacktestResult from './BacktestResult.vue';
import ErrorBox from './ErrorBox.vue';
import UiBadge from './UiBadge.vue';

const props = defineProps<{
  targetType: 'single_rule' | 'scenario';
  targetId: string;
  /** 편집 중인 정의(저장 안 된 내용 포함). 없으면 서버가 저장된 현재 버전을 쓴다. */
  getDefinition?: () => unknown;
  disabled?: boolean;
}>();
const emit = defineEmits<{ done: [job: BacktestJob] }>();

const STATUS_TEXT: Record<string, string> = { queued: '대기 중', running: '실행 중', done: '완료', failed: '실패' };
const from = ref(kstInput(-24));
const to = ref(kstInput(0));
const orgIds = ref<string[]>([]);
const useDraft = ref(true);
const job = ref<BacktestJob | null>(null);
const error = ref<unknown>(null);
const busy = ref(false);
let timer: ReturnType<typeof setTimeout> | undefined;
const orgs = useAsync(() => api.get<Org[]>('/orgs'));
const history = useAsync(
  () => (props.targetId ? api.get<BacktestJob[]>('/backtests', { target_id: props.targetId }) : Promise.resolve([])),
  [() => props.targetId, () => job.value?.status],
);
onBeforeUnmount(() => timer && clearTimeout(timer));

function poll(jobId: string) {
  api
    .get<BacktestJob>(`/backtests/${enc(jobId)}`)
    .then((j) => {
      job.value = j;
      if (j.status === 'queued' || j.status === 'running') {
        timer = setTimeout(() => poll(jobId), 2000);
      } else {
        busy.value = false;
        emit('done', j);
      }
    })
    .catch((e: unknown) => {
      error.value = e;
      busy.value = false;
    });
}

async function start() {
  error.value = null;
  busy.value = true;
  job.value = null;
  try {
    const r = await api.post<{ job_id: string; status: string }>('/backtests', {
      target_type: props.targetType,
      target_id: props.targetId,
      definition: useDraft.value && props.getDefinition ? props.getDefinition() : null,
      org_ids: orgIds.value.length ? orgIds.value : null,
      time_from: localInputToIso(from.value),
      time_to: localInputToIso(to.value),
    });
    poll(r.job_id);
  } catch (e) {
    error.value = e;
    busy.value = false;
  }
}

function open(jobId: string) {
  if (timer) clearTimeout(timer);
  busy.value = true;
  poll(jobId);
}
</script>
<template>
  <div class="backtest" data-testid="backtest-panel">
    <div class="form-row wrap">
      <label class="field inline-field">
        <span class="field-label">시작 (KST)</span>
        <input v-model="from" type="datetime-local" data-testid="backtest-from" />
      </label>
      <label class="field inline-field">
        <span class="field-label">끝 (KST)</span>
        <input v-model="to" type="datetime-local" data-testid="backtest-to" />
      </label>
      <label class="field inline-field">
        <span class="field-label">기관 (비우면 전체)</span>
        <select v-model="orgIds" multiple :size="Math.min(4, Math.max(2, orgs.data.value?.length ?? 2))">
          <option v-for="o in orgs.data.value ?? []" :key="o.org_id" :value="o.org_id">{{ o.org_id }} {{ o.name }}</option>
        </select>
      </label>
      <label v-if="getDefinition" class="check">
        <input v-model="useDraft" type="checkbox" />
        편집 중인 내용으로 실행
      </label>
      <button class="primary" :disabled="busy || disabled || !targetId" data-testid="backtest-start" @click="start">
        {{ busy ? '실행 중…' : '백테스트 실행' }}
      </button>
    </div>
    <small class="hint">기간은 최대 30일입니다. 결과는 백테스트 전용 테이블에 쓰이며 운영 히트에는 영향이 없습니다.</small>
    <ErrorBox :error="error" />
    <div v-if="job" class="bt-status" data-testid="backtest-status">
      작업 {{ job.job_id.slice(0, 8) }} · 상태
      <UiBadge :kind="job.status === 'done' ? 'ok' : job.status === 'failed' ? 'bad' : 'info'" :data-testid="`backtest-${job.status}`">
        {{ STATUS_TEXT[job.status] ?? job.status }}
      </UiBadge>
      <pre v-if="job.error" class="err-text">{{ job.error }}</pre>
    </div>
    <BacktestResult v-if="job?.status === 'done' && job.result" :r="job.result" />
    <details v-if="(history.data.value?.length ?? 0) > 0" class="bt-history">
      <summary>지난 백테스트 ({{ history.data.value?.length }})</summary>
      <table class="table compact">
        <thead>
          <tr><th>요청</th><th>기간</th><th>상태</th><th>요청자</th><th /></tr>
        </thead>
        <tbody>
          <tr v-for="h in history.data.value ?? []" :key="h.job_id">
            <td>{{ fmtTime(h.created_at) }}</td>
            <td>{{ fmtTime(h.time_from) }} ~ {{ fmtTime(h.time_to) }}</td>
            <td>{{ STATUS_TEXT[h.status] ?? h.status }}</td>
            <td>{{ h.created_by }}</td>
            <td><button class="small" @click="open(h.job_id)">결과 보기</button></td>
          </tr>
        </tbody>
      </table>
    </details>
  </div>
</template>
