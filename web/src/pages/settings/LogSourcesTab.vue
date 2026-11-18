<script setup lang="ts">
// 로그 수집원 → 기관 매핑. 운영 원본에는 기관 컬럼이 없고 로그 수집원 ID(_asset_id)만 있어서, 수집원마다 기관을 정한다.
// 매핑이 없는 수집원의 이벤트는 기관 UNASSIGNED(미지정)로 탐지된다. 최근 24시간에 들어온 미매핑 수집원을 바로 지정할 수 있다.
import { computed, ref } from 'vue';
import { api, enc } from '../../api';
import { has } from '../../auth';
import { useAsync } from '../../composables';
import CardBox from '../../components/CardBox.vue';
import ErrorBox from '../../components/ErrorBox.vue';
import LoadingBox from '../../components/LoadingBox.vue';
import NoticeBox from '../../components/NoticeBox.vue';
import type { Org } from '../../types';
import { fmtTime } from '../../util';

interface LogSource { asset_id: string; org_id: string; org_name: string; description: string | null; updated_by: string; updated_at: string; events_24h: number }
interface Unmapped { asset_id: string; data_types: string[]; events_24h: number; last_seen: string }

const admin = computed(() => has('admin'));
const data = useAsync(() => api.get<{ items: LogSource[]; unmapped: Unmapped[] }>('/log-sources'));
const orgs = useAsync(() => api.get<Org[]>('/orgs'));
const err = ref<unknown>(null);
const msg = ref<string | null>(null);
const busy = ref(false);
const pick = ref<Record<string, string>>({});
const form = ref({ asset_id: '', org_id: '', description: '' });

async function save(assetId: string, orgId: string, description: string | null) {
  busy.value = true;
  err.value = null;
  msg.value = null;
  try {
    await api.put(`/log-sources/${enc(assetId)}`, { org_id: orgId, description: description || null });
    msg.value = `${assetId} → ${orgId} 로 지정했습니다 (1분 안에 탐지에 반영)`;
    form.value = { asset_id: '', org_id: '', description: '' };
    data.reload();
  } catch (e) {
    err.value = e;
  } finally {
    busy.value = false;
  }
}
async function remove(assetId: string) {
  if (!window.confirm(`${assetId} 매핑을 지울까요? 이 수집원의 이벤트는 미지정 기관으로 탐지됩니다.`)) return;
  busy.value = true;
  err.value = null;
  try {
    await api.del(`/log-sources/${enc(assetId)}`);
    msg.value = `${assetId} 매핑을 지웠습니다`;
    data.reload();
  } catch (e) {
    err.value = e;
  } finally {
    busy.value = false;
  }
}
</script>
<template>
  <div>
    <p class="muted small">
      원본 이벤트에는 기관 컬럼이 없어 로그 수집원(_asset_id)으로 기관을 정합니다. 매핑이 없는 수집원의 이벤트는
      <strong>UNASSIGNED (미지정)</strong> 기관으로 탐지되므로 먼저 지정하세요. 변경은 1분 안에 탐지에 반영되고, 이미 만든 히트·경보는 그대로입니다.
    </p>
    <NoticeBox v-if="msg" kind="ok">{{ msg }}</NoticeBox>
    <ErrorBox :error="err" closable @close="err = null" />
    <LoadingBox v-if="data.loading.value" />
    <ErrorBox :error="data.error.value" />
    <CardBox v-if="data.data.value?.unmapped.length" title="매핑 없는 수집원 (최근 24시간)">
      <table class="table" data-testid="log-sources-unmapped">
        <thead><tr><th>수집원</th><th>데이터 유형</th><th class="num">24시간 이벤트</th><th>마지막 수집</th><th v-if="admin">기관 지정</th></tr></thead>
        <tbody>
          <tr v-for="u in data.data.value.unmapped" :key="u.asset_id">
            <td class="mono">{{ u.asset_id }}</td>
            <td>{{ u.data_types.join(', ') }}</td>
            <td class="num">{{ u.events_24h }}</td>
            <td class="small">{{ fmtTime(u.last_seen) }}</td>
            <td v-if="admin" class="form-row">
              <select v-model="pick[u.asset_id]" :data-testid="`log-source-pick-${u.asset_id}`">
                <option value="">기관 선택</option>
                <option v-for="o in orgs.data.value ?? []" :key="o.org_id" :value="o.org_id">{{ o.org_id }} {{ o.name }}</option>
              </select>
              <button class="small primary" :disabled="busy || !pick[u.asset_id]" :data-testid="`log-source-assign-${u.asset_id}`"
                      @click="save(u.asset_id, pick[u.asset_id], null)">지정</button>
            </td>
          </tr>
        </tbody>
      </table>
    </CardBox>
    <CardBox title="수집원 → 기관 매핑">
      <div v-if="admin" class="form-row">
        <input v-model="form.asset_id" placeholder="수집원 ID (_asset_id)" data-testid="log-source-new-id" />
        <select v-model="form.org_id" data-testid="log-source-new-org">
          <option value="">기관 선택</option>
          <option v-for="o in orgs.data.value ?? []" :key="o.org_id" :value="o.org_id">{{ o.org_id }} {{ o.name }}</option>
        </select>
        <input v-model="form.description" placeholder="설명 (선택)" />
        <button class="primary" :disabled="busy || !form.asset_id || !form.org_id" data-testid="log-source-new-save"
                @click="save(form.asset_id.trim(), form.org_id, form.description)">추가·변경</button>
      </div>
      <table v-if="data.data.value" class="table" data-testid="log-sources">
        <thead><tr><th>수집원</th><th>기관</th><th>설명</th><th class="num">24시간 이벤트</th><th>변경</th><th v-if="admin" /></tr></thead>
        <tbody>
          <tr v-for="s in data.data.value.items" :key="s.asset_id">
            <td class="mono">{{ s.asset_id }}</td>
            <td>{{ s.org_id }} <span class="muted small">{{ s.org_name }}</span></td>
            <td class="small">{{ s.description ?? '' }}</td>
            <td class="num">{{ s.events_24h }}</td>
            <td class="small">{{ s.updated_by }} {{ fmtTime(s.updated_at) }}</td>
            <td v-if="admin"><button class="small danger" :disabled="busy" @click="remove(s.asset_id)">삭제</button></td>
          </tr>
          <tr v-if="!data.data.value.items.length"><td colspan="6" class="muted">매핑이 없습니다</td></tr>
        </tbody>
      </table>
    </CardBox>
  </div>
</template>
