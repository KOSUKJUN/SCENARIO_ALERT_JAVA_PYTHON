<script setup lang="ts">
import { api, enc } from '../../api';
import { useAsync } from '../../composables';
import EmptyBox from '../../components/EmptyBox.vue';
import ErrorBox from '../../components/ErrorBox.vue';
import LoadingBox from '../../components/LoadingBox.vue';
import UiBadge from '../../components/UiBadge.vue';
import type { Row } from '../../types';
import { fmtTime } from '../../util';

const props = defineProps<{ ruleId: string }>();
const rs = useAsync(() => api.get<Row[]>(`/single-rules/${enc(props.ruleId)}/runs`, { limit: 200 }), [() => props.ruleId]);
const s = (v: unknown) => (v === null || v === undefined ? '' : String(v));
</script>
<template>
  <LoadingBox v-if="rs.loading.value" />
  <ErrorBox v-else-if="rs.error.value" :error="rs.error.value" />
  <EmptyBox v-else-if="!rs.data.value?.length">실행 이력이 없습니다 (draft 룰은 실시간 평가하지 않습니다)</EmptyBox>
  <div v-else class="table-wrap">
    <table class="table compact" data-testid="rule-runs">
      <thead>
        <tr><th>시작</th><th>버전</th><th>창</th><th>상태</th><th class="num">히트</th><th class="num">새 히트</th><th class="num">ms</th><th>인스턴스</th><th>오류</th></tr>
      </thead>
      <tbody>
        <tr v-for="(r, i) in rs.data.value" :key="i" :class="{ 'row-bad': r.status !== 'ok' }">
          <td>{{ fmtTime(r.started_at) }}</td>
          <td>v{{ s(r.version) }}</td>
          <td class="small">{{ fmtTime(r.win_from) }} ~ {{ fmtTime(r.win_to) }}</td>
          <td><UiBadge :kind="r.status === 'ok' ? 'ok' : 'bad'">{{ s(r.status) }}</UiBadge></td>
          <td class="num">{{ s(r.hit_count) }}</td>
          <td class="num">{{ s(r.new_hit_count) }}</td>
          <td class="num">{{ s(r.duration_ms) }}</td>
          <td class="small">{{ s(r.instance_id) }}</td>
          <td class="small err-text">{{ s(r.error) }}</td>
        </tr>
      </tbody>
    </table>
  </div>
</template>
