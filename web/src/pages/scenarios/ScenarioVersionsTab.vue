<script setup lang="ts">
import { ref } from 'vue';
import { api, enc, errorText } from '../../api';
import { useAsync } from '../../composables';
import EmptyBox from '../../components/EmptyBox.vue';
import ErrorBox from '../../components/ErrorBox.vue';
import LoadingBox from '../../components/LoadingBox.vue';
import ModalDialog from '../../components/ModalDialog.vue';
import type { Graph, GraphDiff, ScenarioCode, ScenarioVersion } from '../../types';
import { fmtSec, fmtTime } from '../../util';

const props = defineProps<{ sid: string }>();
const emit = defineEmits<{ load: [g: Graph] }>();
const vs = useAsync(() => api.get<ScenarioVersion[]>(`/scenarios/${enc(props.sid)}/versions`), [() => props.sid]);
const DIFF_LABEL: [keyof GraphDiff, string, string][] = [
  ['nodes_added', '노드 추가', 'add'],
  ['nodes_removed', '노드 삭제', 'del'],
  ['nodes_changed', '노드 변경', 'chg'],
  ['edges_added', '화살표 추가', 'add'],
  ['edges_removed', '화살표 삭제', 'del'],
  ['edges_changed', '화살표 변경', 'chg'],
  ['settings_changed', '설정 변경', 'chg'],
];
const parts = (d: GraphDiff) => DIFF_LABEL.filter(([k]) => d[k]?.length);

// 버전마다 생성된 Python 평가 코드 보기
const code = ref<ScenarioCode | null>(null);
const codeError = ref('');
async function showCode(version: number): Promise<void> {
  codeError.value = '';
  try {
    code.value = await api.get<ScenarioCode>(`/scenarios/${enc(props.sid)}/code`, { version });
  } catch (e) {
    codeError.value = errorText(e);
  }
}
</script>
<template>
  <LoadingBox v-if="vs.loading.value" />
  <ErrorBox v-else-if="vs.error.value" :error="vs.error.value" />
  <EmptyBox v-else-if="!vs.data.value?.length">버전이 없습니다</EmptyBox>
  <template v-else>
    <div v-if="codeError" class="alert-box error small">{{ codeError }}</div>
    <table class="table compact" data-testid="scenario-version-list">
      <thead><tr><th>버전</th><th>작성</th><th>시각</th><th>변경 메모</th><th>최대 기간</th><th>이전 버전과 차이</th><th /></tr></thead>
      <tbody>
        <tr v-for="v in vs.data.value" :key="v.version">
          <td>v{{ v.version }}</td>
          <td>{{ v.created_by }}</td>
          <td>{{ fmtTime(v.created_at) }}</td>
          <td>{{ v.change_note ?? '-' }}</td>
          <td>{{ fmtSec(v.max_span_sec) }}</td>
          <td>
            <span v-if="!v.diff" class="muted small">첫 버전</span>
            <span v-else-if="!parts(v.diff).length" class="muted small">구조 변경 없음 (좌표만 바뀜)</span>
            <div v-else class="diff">
              <div v-for="[k, label, cls] in parts(v.diff)" :key="k" :class="`diff-${cls}`"><strong>{{ label }}</strong>: {{ v.diff[k].join(', ') }}</div>
            </div>
          </td>
          <td>
            <button class="small" @click="emit('load', v.graph)">편집기로 불러오기</button>
            <button class="small" data-testid="show-python-code" @click="showCode(v.version)">Python 코드</button>
          </td>
        </tr>
      </tbody>
    </table>
  </template>
  <ModalDialog v-if="code" :title="`${code.scenario_id} v${code.version} 생성 코드`" wide @close="code = null">
    <p class="muted small">
      순서도를 저장할 때 서버(Java)가 버전마다 생성한 Python 평가 코드입니다. 실시간 평가·백테스트·시뮬레이션이 이 코드를 실행합니다.
      생성기 {{ code.generator_version }} · sha256 <code>{{ code.code_sha256.slice(0, 16) }}…</code>
    </p>
    <pre class="sql" style="max-height: 60vh; white-space: pre">{{ code.python_code }}</pre>
  </ModalDialog>
</template>
