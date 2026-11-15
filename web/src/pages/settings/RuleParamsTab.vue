<script setup lang="ts">
// 기관별 임계치와 사용 여부. 비워 두면 룰 정의의 임계치를 쓴다.
import { computed, ref, watch } from 'vue';
import { api, enc } from '../../api';
import { has } from '../../auth';
import { useAsync } from '../../composables';
import CardBox from '../../components/CardBox.vue';
import ErrorBox from '../../components/ErrorBox.vue';
import LoadingBox from '../../components/LoadingBox.vue';
import NoticeBox from '../../components/NoticeBox.vue';
import type { Org, RuleParam, RuleSummary } from '../../types';
import { truthy } from '../../util';

const canEdit = computed(() => has('author'));
const orgs = useAsync(() => api.get<Org[]>('/orgs'));
const rules = useAsync(() => api.get<RuleSummary[]>('/single-rules'));
const org = ref('');
watch(
  () => orgs.data.value,
  (os) => {
    if (!org.value && os?.length) org.value = os[0].org_id;
  },
);
const params = useAsync<RuleParam[]>(() => (org.value ? api.get<RuleParam[]>(`/orgs/${enc(org.value)}/rule-params`) : Promise.resolve([])), [org]);
const edits = ref<Record<string, { enabled: boolean; threshold: string }>>({});
watch(
  [() => params.data.value, () => rules.data.value],
  () => {
    const by = Object.fromEntries((params.data.value ?? []).map((p) => [p.rule_id, p]));
    edits.value = Object.fromEntries(
      (rules.data.value ?? []).map((r) => {
        const p = by[r.rule_id];
        return [r.rule_id, { enabled: p ? truthy(p.enabled) : true, threshold: p?.threshold === null || p?.threshold === undefined ? '' : String(p.threshold) }];
      }),
    );
  },
);
const overridden = computed(() => new Set((params.data.value ?? []).map((p) => p.rule_id)));
const err = ref<unknown>(null);
const msg = ref<string | null>(null);

async function save(ruleId: string) {
  err.value = null;
  msg.value = null;
  const e = edits.value[ruleId];
  try {
    await api.put(`/orgs/${enc(org.value)}/rule-params/${enc(ruleId)}`, { enabled: e.enabled, threshold: e.threshold === '' ? null : Number(e.threshold) });
    msg.value = `${org.value} / ${ruleId} 저장`;
    params.reload();
  } catch (x) {
    err.value = x;
  }
}
async function reset(ruleId: string) {
  err.value = null;
  try {
    await api.del(`/orgs/${enc(org.value)}/rule-params/${enc(ruleId)}`);
    msg.value = `${org.value} / ${ruleId} 기본값으로`;
    params.reload();
  } catch (x) {
    err.value = x;
  }
}
</script>
<template>
  <CardBox title="기관별 임계치">
    <template #actions>
      <select v-model="org">
        <option v-for="o in orgs.data.value ?? []" :key="o.org_id" :value="o.org_id">{{ o.org_id }} {{ o.name }}</option>
      </select>
    </template>
    <NoticeBox v-if="msg" kind="ok">{{ msg }}</NoticeBox>
    <ErrorBox :error="err || params.error.value || rules.error.value" closable @close="err = null" />
    <LoadingBox v-if="rules.loading.value && !rules.data.value" />
    <table v-if="rules.data.value" class="table compact" data-testid="rule-params">
      <thead><tr><th>룰</th><th>유형</th><th>기본 임계</th><th>사용</th><th>기관 임계치</th><th /></tr></thead>
      <tbody>
        <tr v-for="r in rules.data.value" :key="r.rule_id" :class="{ 'row-ok': overridden.has(r.rule_id) }">
          <td>{{ r.rule_id }} <span class="muted small">{{ r.name }}</span></td>
          <td>{{ r.type === 'count' ? '카운트' : '시그니처' }}</td>
          <td class="small muted">룰 정의 값</td>
          <td><input v-if="edits[r.rule_id]" v-model="edits[r.rule_id].enabled" type="checkbox" :disabled="!canEdit" /></td>
          <td><input v-if="edits[r.rule_id]" v-model="edits[r.rule_id].threshold" class="num-input" placeholder="(기본)" :disabled="!canEdit || r.type !== 'count'" /></td>
          <td>
            <template v-if="canEdit">
              <button class="small" @click="save(r.rule_id)">저장</button>
              <button v-if="overridden.has(r.rule_id)" class="small" @click="reset(r.rule_id)">기본값</button>
            </template>
          </td>
        </tr>
      </tbody>
    </table>
  </CardBox>
</template>
